//! Long commands run as jobs on their own thread. The page polls for the
//! result; leaving the Working screen doesn't stop a job (an update is never
//! cut off halfway), its result just isn't shown.

use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Clone, Default)]
pub struct Jobs {
    next: Arc<AtomicU64>,
    done: Arc<Mutex<HashMap<u64, Option<Value>>>>, // None while running
}

impl Jobs {
    /// Start `work` on a thread; returns the job id to poll.
    pub fn start(&self, work: impl FnOnce() -> Value + Send + 'static) -> u64 {
        let id = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        let mut done = self.done.lock().unwrap();
        if done.len() > 50 {
            done.retain(|_, v| v.is_none()); // forget old results nobody fetched
        }
        done.insert(id, None);
        drop(done);
        let store = self.done.clone();
        thread::spawn(move || {
            let result = work();
            store.lock().unwrap().insert(id, Some(result));
        });
        id
    }

    /// Some(Some(result)) when finished (and forgets it), Some(None) while
    /// running, None for an unknown id.
    pub fn poll(&self, id: u64) -> Option<Option<Value>> {
        let mut done = self.done.lock().unwrap();
        match done.get(&id)? {
            None => Some(None),
            Some(_) => done.remove(&id).map(|v| v),
        }
    }
}
