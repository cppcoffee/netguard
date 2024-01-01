use std::sync::RwLock;
use std::time::Instant;

use anyhow::{anyhow, Result};
use hashbrown::HashMap;

use crate::ConntrackEntry;

pub struct ConntrackMap {
    entries: RwLock<HashMap<ConntrackEntry, Instant>>,
}

impl ConntrackMap {
    pub fn new() -> ConntrackMap {
        ConntrackMap {
            entries: RwLock::new(HashMap::new()),
        }
    }

    pub fn add_entry(&self, entry: ConntrackEntry) -> Result<()> {
        let _ = self
            .entries
            .write()
            .map_err(|e| anyhow!("ConntrackMap add_entry fetch write lock failed: {e}"))?
            .insert(entry, Instant::now());

        Ok(())
    }

    pub fn get_timestamp(&self, entry: &ConntrackEntry) -> Result<Option<Instant>> {
        let entries = self
            .entries
            .read()
            .map_err(|e| anyhow!("ConntrackMap get_timestamp fetch read lock failed: {e}"))?;

        match entries.get(entry) {
            Some(inst) => Ok(Some(inst.clone())),
            None => Ok(None),
        }
    }

    pub fn update_timestamp(&self, entry: ConntrackEntry) -> Result<()> {
        self.entries
            .write()
            .map_err(|e| anyhow!("ConntrackMap update_timestamp fetch write lock failed: {e}"))?
            .entry(entry)
            .and_modify(|inst| *inst = Instant::now());

        Ok(())
    }

    pub fn reclaim_expired_entries(&self, timeout: u64) -> Result<(usize, usize)> {
        let now = Instant::now();

        let mut entries = self.entries.write().map_err(|e| {
            anyhow!("ConntrackMap reclaim_expired_entries fetch write lock failed: {e}")
        })?;

        let prev = entries.len();

        entries.retain(|_, inst| now.duration_since(*inst).as_secs() < timeout);

        Ok((prev, entries.len()))
    }

    pub fn remove_entry(&self, entry: &ConntrackEntry) -> Result<()> {
        self.entries
            .write()
            .map_err(|e| anyhow!("ConntrackMap remove_entry fetch write lock failed: {e}"))?
            .remove(entry);

        Ok(())
    }
}
