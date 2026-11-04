//! Long commands run as jobs on their own thread. The page polls for the
//! result; leaving the Working screen doesn't stop a job (an update is never
//! cut off halfway), its result just isn't shown. While it runs, the page
//! shows its live lines (output so far).

use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

/// A running job's output so far, shown on the Working screen.
pub type Live = Arc<Mutex<Vec<String>>>;

#[derive(Clone, Default)]
pub struct Jobs {
    next: Arc<AtomicU64>,
    done: Arc<Mutex<HashMap<u64, Option<Value>>>>, // None while running
    live: Arc<Mutex<HashMap<u64, Live>>>,
}

impl Jobs {
    /// Start `work` on a thread; returns the job id to poll.
    pub fn start(&self, work: impl FnOnce() -> Value + Send + 'static) -> u64 {
        self.start_live(move |_| work())
    }

    /// Like start, but `work` can add lines the page shows while it runs.
    pub fn start_live(&self, work: impl FnOnce(Live) -> Value + Send + 'static) -> u64 {
        let id = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        let mut done = self.done.lock().unwrap();
        if done.len() > 50 {
            done.retain(|_, v| v.is_none()); // forget old results nobody fetched
        }
        done.insert(id, None);
        drop(done);
        let live = Live::default();
        self.live.lock().unwrap().insert(id, live.clone());
        let (store, lives) = (self.done.clone(), self.live.clone());
        thread::spawn(move || {
            let result = work(live);
            lives.lock().unwrap().remove(&id);
            store.lock().unwrap().insert(id, Some(result));
        });
        id
    }

    /// A running job's live lines (the last 40).
    pub fn lines(&self, id: u64) -> Vec<String> {
        let live = self.live.lock().unwrap().get(&id).cloned().unwrap_or_default();
        let l = live.lock().unwrap();
        l[l.len().saturating_sub(40)..].to_vec()
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
