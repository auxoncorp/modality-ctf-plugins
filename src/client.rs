use crate::attrs::{EventAttrKey, TimelineAttrKey};
use crate::config::AttrKeyRename;
use crate::error::Error;
use modality_ingest_client::dynamic::DynamicIngestClient;
use modality_ingest_client::{IngestClient, ReadyState};
use modality_ingest_protocol::InternedAttrKey;
use std::collections::{BTreeMap, HashMap};

pub struct Client {
    pub c: DynamicIngestClient,
    timeline_keys: BTreeMap<String, InternedAttrKey>,
    event_keys: BTreeMap<String, InternedAttrKey>,
    rename_timeline_attrs: HashMap<String, String>,
    rename_event_attrs: HashMap<String, String>,
}

fn normalize_timeline_key(s: String) -> String {
    if s.starts_with("timeline.") {
        s
    } else {
        format!("timeline.{s}")
    }
}

fn normalize_event_key(s: String) -> String {
    if s.starts_with("event.") {
        s
    } else {
        format!("event.{s}")
    }
}

impl Client {
    pub fn new(
        c: IngestClient<ReadyState>,
        rename_timeline_attrs: Vec<AttrKeyRename>,
        rename_event_attrs: Vec<AttrKeyRename>,
    ) -> Self {
        Self {
            c: c.into(),
            timeline_keys: Default::default(),
            event_keys: Default::default(),
            rename_timeline_attrs: rename_timeline_attrs
                .into_iter()
                .map(|r| {
                    (
                        normalize_timeline_key(r.original),
                        normalize_timeline_key(r.new),
                    )
                })
                .collect(),
            rename_event_attrs: rename_event_attrs
                .into_iter()
                .map(|r| (normalize_event_key(r.original), normalize_event_key(r.new)))
                .collect(),
        }
    }

    pub async fn interned_timeline_key(
        &mut self,
        key: TimelineAttrKey,
    ) -> Result<InternedAttrKey, Error> {
        let mut key = &key.to_string();
        if let Some(new) = self.rename_timeline_attrs.get(key) {
            key = new;
        }

        let int_key = if let Some(k) = self.timeline_keys.get(key) {
            *k
        } else {
            let k = self.c.declare_attr_key(key.to_string()).await?;
            self.timeline_keys.insert(key.to_string(), k);
            k
        };
        Ok(int_key)
    }

    pub async fn interned_event_key(
        &mut self,
        key: EventAttrKey,
    ) -> Result<InternedAttrKey, Error> {
        let mut key = &key.to_string();
        if let Some(new) = self.rename_event_attrs.get(key) {
            key = new;
        }

        let int_key = if let Some(k) = self.event_keys.get(&key.to_string()) {
            *k
        } else {
            let k = self.c.declare_attr_key(key.to_string()).await?;
            self.event_keys.insert(key.to_string(), k);
            k
        };
        Ok(int_key)
    }
}
