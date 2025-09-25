// Copyright 2025 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The REDECRYPTOR is a layer that handles redecryption of events in case we
//! couldn't decrypt them imediatelly

use std::sync::{Arc, Weak};

use as_variant::as_variant;
use futures_core::Stream;
use futures_util::{StreamExt, pin_mut};
use matrix_sdk_base::{
    crypto::{store::types::RoomKeyInfo, types::events::room::encrypted::EncryptedEvent},
    deserialized_responses::{DecryptedRoomEvent, TimelineEvent, TimelineEventKind},
};
use matrix_sdk_common::executor::JoinHandle;
use ruma::{RoomId, serde::Raw};
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tracing::warn;

use crate::{
    Client,
    event_cache::{EventCache, EventCacheError, EventCacheInner},
};

pub(crate) struct Redecryptor {
    redecryption_task: JoinHandle<()>,
    inner: Arc<InnerRedecryptor>,
}

impl Drop for Redecryptor {
    fn drop(&mut self) {
        self.redecryption_task.abort();
    }
}

pub(crate) struct InnerRedecryptor {
    cache: Weak<EventCacheInner>,
}

impl InnerRedecryptor {
    /// Attempt to redecrypt events after a room key with the given session ID
    /// has been received.
    pub async fn retry_decryption(
        &self,
        room_key_info: RoomKeyInfo,
    ) -> Result<(), EventCacheError> {
        let event_cache = EventCache { inner: self.cache.upgrade().unwrap() };
        let client: Client = event_cache.inner.client.get().unwrap();

        // Load the relevant events from the event cache store and attempt to redecrypt
        // things.
        let events = {
            let store = event_cache.inner.store.lock().await.unwrap();
            let events = store.get_room_events(&room_key_info.room_id).await?;

            events
        };

        // TODO: We can't load **all** events all the time.
        let only_utd_events = |event: TimelineEvent| {
            // We need the event ID and we only care about events that are still encrypted.
            event.event_id().zip(
                as_variant!(event.kind, TimelineEventKind::UnableToDecrypt { event, .. } => event),
            )
        };

        let (room_cache, _) = event_cache.for_room(&room_key_info.room_id).await.unwrap();
        let mut state = room_cache.inner.state.write().await;

        for (event_id, event) in events.into_iter().filter_map(only_utd_events) {
            let Some((location, mut target_event)) = state.find_event(&event_id).await? else {
                continue;
            };

            if let Some(decrypted) = self
                .decrypt_event(&client, &room_key_info.room_id, event.cast_ref_unchecked())
                .await
            {
                target_event.kind = TimelineEventKind::Decrypted(decrypted);

                state.replace_event_at(location, target_event).await?
            }
        }

        Ok(())
    }

    pub async fn decrypt_event(
        &self,
        client: &Client,
        room_id: &RoomId,
        event: &Raw<EncryptedEvent>,
    ) -> Option<DecryptedRoomEvent> {
        let machine = client.olm_machine().await;
        let Some(machine) = &*machine else {
            return None;
        };

        match machine.decrypt_room_event(event, room_id, client.decryption_settings()).await {
            Ok(decrypted) => Some(decrypted),
            // TODO: Inspect the error.
            Err(e) => None,
        }
    }

    pub async fn listen_for_room_keys_task(
        weak_redecryptor: Weak<InnerRedecryptor>,
        received_stream: impl Stream<Item = Result<Vec<RoomKeyInfo>, BroadcastStreamRecvError>>,
    ) {
        pin_mut!(received_stream);

        // TODO: We need to relisten to this stream if it dies.
        while let Some(update) = received_stream.next().await {
            let Some(decryptor) = weak_redecryptor.upgrade() else {
                break;
            };

            if let Ok(room_keys) = update {
                for key in room_keys {
                    let _ = decryptor
                        .retry_decryption(key)
                        .await
                        .inspect_err(|e| warn!("Error redecrypting {e:?}"));
                }
            } else {
                todo!("Redecrypt all visible events?")
            }
        }
    }
}
