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

use futures_core::Stream;
use futures_util::{StreamExt, pin_mut};
use matrix_sdk_base::{
    crypto::{OlmMachine, store::types::RoomKeyInfo},
    deserialized_responses::{DecryptedRoomEvent, TimelineEvent, TimelineEventKind},
    event_cache::store::{EventCacheStoreError, EventCacheStoreLock},
};
use matrix_sdk_common::executor::JoinHandle;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tracing::warn;

use crate::event_cache::{EventCacheError, RoomEventCacheState};

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
    store: EventCacheStoreLock,
    olm_machine: OlmMachine,
}

impl InnerRedecryptor {
    /// Attempt to redecrypt events after a room key with the given session ID
    /// has been received.
    pub async fn retry_decryption(
        &self,
        room_key_info: RoomKeyInfo,
    ) -> Result<(), EventCacheError> {
        let event_cache: RoomEventCacheState = unimplemented!();

        // Load the relevant events from the event cache store and attempt to redecrypt
        // things.
        // TODO: Do we want to have this method on the [`RoomEventCacheState`]?
        let store = self.store.lock().await.unwrap();

        // TODO: We can't load **all** events all the time.
        let events = store.get_room_events(&room_key_info.room_id).await?;

        for event in events.into_iter().filter(|e| !e.kind.is_utd()) {
            let Some(event_id) = event.event_id() else {
                continue;
            };

            let Some((location, mut target_event)) = event_cache.find_event(&event_id).await?
            else {
                continue;
            };

            let decrypted = self.decrypt_event(event).await?;
            target_event.kind = TimelineEventKind::Decrypted(decrypted);

            event_cache.replace_event_at(location, target_event).await?
        }

        Ok(())
    }

    pub async fn decrypt_event(
        &self,
        event: TimelineEvent,
    ) -> Result<DecryptedRoomEvent, EventCacheStoreError> {
        todo!();
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
