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

use std::sync::Weak;

use as_variant::as_variant;
use futures_core::Stream;
use futures_util::{StreamExt, pin_mut};
use matrix_sdk_base::{
    crypto::{store::types::RoomKeyInfo, types::events::room::encrypted::EncryptedEvent},
    deserialized_responses::{DecryptedRoomEvent, TimelineEvent, TimelineEventKind},
};
use matrix_sdk_common::executor::spawn;
use ruma::{RoomId, serde::Raw};
use tokio::task::JoinHandle;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tracing::{instrument, trace, warn};

use crate::{
    Client,
    event_cache::{EventCache, EventCacheError, EventCacheInner},
};

pub(crate) struct Redecryptor {
    cache: Weak<EventCacheInner>,
}

impl Redecryptor {
    pub fn new(client: Client, cache: Weak<EventCacheInner>) -> JoinHandle<()> {
        let redecryptor = Self { cache };

        let task = spawn(async {
            let stream = {
                let machine = client.olm_machine().await;
                machine.as_ref().unwrap().store().room_keys_received_stream()
            };

            drop(client);

            redecryptor.listen_for_room_keys_task(stream).await;
        });

        task
    }
    /// Attempt to redecrypt events after a room key with the given session ID
    /// has been received.
    #[instrument(skip_all, fields(room_key_info))]
    async fn retry_decryption(
        &self,
        cache: &EventCache,
        room_key_info: RoomKeyInfo,
    ) -> Result<(), EventCacheError> {
        trace!("Retrying to decrypt");

        // Load the relevant events from the event cache store and attempt to redecrypt
        // things.
        let events = {
            // TODO: We can't load **all** events all the time.
            let store = cache.inner.store.lock().await?;
            let events = store.get_room_events(&room_key_info.room_id).await?;

            events
        };

        let only_utd_events = |event: TimelineEvent| {
            // We need the event ID to be able to replace the event.
            let event_id = event.event_id();
            // We only care about events fort his particular room key, identified by the
            // session ID.
            let session_id = event.kind.session_id();

            if session_id == Some(&room_key_info.session_id) {
                // Only pick out events that are UTDs.
                let event = as_variant!(event.kind, TimelineEventKind::UnableToDecrypt { event, .. } => event);
                event.zip(event_id)
            } else {
                None
            }
        };

        // Get the cache for this particular room and lock the state for the duration of
        // the decryption.
        // TODO: Do we want to first decrypt and then do the locking and replacement,
        // would be an additional loop but the lock would be free for the
        // duration of the "slow" decryption attempts.
        let (room_cache, _) = cache.for_room(&room_key_info.room_id).await?;
        let mut state = room_cache.inner.state.write().await;

        for (event, event_id) in events.into_iter().filter_map(only_utd_events) {
            // The event isn't in the cache, nothing to replace. Realistically this can't
            // happen since we retrieved the list of events from the cache itself.
            let Some((location, mut target_event)) = state.find_event(&event_id).await? else {
                continue;
            };

            // If we managed to decrypt the event, and we should have to since we received
            // the room key for this specific event, then replace the event.
            if let Some(decrypted) =
                self.decrypt_event(&cache, &room_key_info.room_id, event.cast_ref_unchecked()).await
            {
                target_event.kind = TimelineEventKind::Decrypted(decrypted);

                state.replace_event_at(location, target_event).await?
            }
        }

        Ok(())
    }

    async fn decrypt_event(
        &self,
        cache: &EventCache,
        room_id: &RoomId,
        event: &Raw<EncryptedEvent>,
    ) -> Option<DecryptedRoomEvent> {
        let client = cache.inner.client().ok()?;
        let machine = client.olm_machine().await;
        let machine = machine.as_ref()?;

        match machine.decrypt_room_event(event, room_id, client.decryption_settings()).await {
            Ok(decrypted) => Some(decrypted),
            Err(e) => {
                warn!("Failed to redecrypt an event {e:?}");
                None
            }
        }
    }

    async fn listen_for_room_keys_task(
        self,
        received_stream: impl Stream<Item = Result<Vec<RoomKeyInfo>, BroadcastStreamRecvError>>,
    ) {
        pin_mut!(received_stream);

        // TODO: We need to relisten to this stream if it dies due to the cross-process
        // lock reloading the Olm machine.
        while let Some(update) = received_stream.next().await {
            if let Ok(room_keys) = update {
                let Some(event_cache) = self.cache.upgrade() else {
                    break;
                };

                let cache = EventCache { inner: event_cache };

                for key in room_keys {
                    let _ = self
                        .retry_decryption(&cache, key)
                        .await
                        .inspect_err(|e| warn!("Error redecrypting {e:?}"));
                }
            } else {
                todo!("Redecrypt all visible events?")
            }
        }
    }
}
