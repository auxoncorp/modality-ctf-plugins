use crate::attrs::{EventAttrKey, EventAttrKeyExt, TimelineAttrKey, TimelineAttrKeyExt};
use crate::error::Error;
use async_trait::async_trait;
use modality_ingest_client::dynamic::DynamicIngestClient;
use modality_ingest_client::{IngestClient, ReadyState};
use modality_ingest_protocol::InternedAttrKey;
use std::collections::BTreeMap;

pub struct Client {
    pub c: DynamicIngestClient,
    pub timeline_keys: BTreeMap<TimelineAttrKey, InternedAttrKey>,
    pub event_keys: BTreeMap<EventAttrKey, InternedAttrKey>,
}

impl Client {
    pub fn new(c: IngestClient<ReadyState>) -> Self {
        Self {
            c: c.into(),
            timeline_keys: Default::default(),
            event_keys: Default::default(),
        }
    }
}

#[async_trait]
impl TimelineAttrKeyExt for Client {
    async fn interned_key(&mut self, key: TimelineAttrKey) -> Result<InternedAttrKey, Error> {
        let int_key = if let Some(k) = self.timeline_keys.get(&key) {
            *k
        } else {
            let k = self.c.declare_attr_key(key.to_string()).await?;
            self.timeline_keys.insert(key, k);
            k
        };
        Ok(int_key)
    }
}

#[async_trait]
impl EventAttrKeyExt for Client {
    async fn interned_key(&mut self, key: EventAttrKey) -> Result<InternedAttrKey, Error> {
        let int_key = if let Some(k) = self.event_keys.get(&key) {
            *k
        } else {
            let k = self.c.declare_attr_key(key.to_string()).await?;
            self.event_keys.insert(key, k);
            k
        };
        Ok(int_key)
    }
}
