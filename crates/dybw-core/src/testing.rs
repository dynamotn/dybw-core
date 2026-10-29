//! Test fakes for the host ports (feature `testing`). All are `RefCell`-based, so `!Send` and `!Sync`.

use crate::ports::{Clock, PortError, Random, Secrets, Storage};
use std::cell::RefCell;
use std::collections::HashMap;
use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};
use zeroize::Zeroizing;

/// Poll `f` to completion with a no-op waker; fakes never return `Pending`.
pub fn block_on<F: Future>(f: F) -> F::Output {
    let mut f = pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    let mut polls = 0;
    loop {
        match f.as_mut().poll(&mut cx) {
            Poll::Ready(v) => return v,
            Poll::Pending => polls += 1,
        }
        assert!(polls < 10_000, "a fake port returned Pending");
    }
}

pub struct FixedClock {
    pub now_ms: i64,
}

impl Clock for FixedClock {
    fn now_ms(&self) -> i64 {
        self.now_ms
    }
    async fn sleep_ms(&self, _ms: u64) {}
}

/// splitmix64: deterministic test bytes, never key material outside tests.
pub struct SeededRandom(RefCell<u64>);

impl SeededRandom {
    pub fn new(seed: u64) -> Self {
        Self(RefCell::new(seed))
    }
}

impl Random for SeededRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), PortError> {
        let mut s = self.0.borrow_mut();
        for chunk in buf.chunks_mut(8) {
            *s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = *s;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            let bytes = z.to_le_bytes();
            let n = chunk.len();
            chunk.copy_from_slice(bytes.get(..n).unwrap_or(&bytes));
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct MemStorage(RefCell<HashMap<String, Vec<u8>>>);

impl Storage for MemStorage {
    async fn load(&self, key: &str) -> Result<Option<Vec<u8>>, PortError> {
        Ok(self.0.borrow().get(key).cloned())
    }
    async fn save(&self, key: &str, data: &[u8]) -> Result<(), PortError> {
        self.0.borrow_mut().insert(key.to_owned(), data.to_vec());
        Ok(())
    }
    async fn remove(&self, key: &str) -> Result<(), PortError> {
        self.0.borrow_mut().remove(key);
        Ok(())
    }
}

#[derive(Default)]
pub struct MemSecrets(RefCell<HashMap<String, Zeroizing<String>>>);

impl Secrets for MemSecrets {
    async fn load(&self, key: &str) -> Result<Option<Zeroizing<String>>, PortError> {
        Ok(self.0.borrow().get(key).cloned())
    }
    async fn save(&self, key: &str, data: &Zeroizing<String>) -> Result<(), PortError> {
        self.0.borrow_mut().insert(key.to_owned(), data.clone());
        Ok(())
    }
    async fn remove(&self, key: &str) -> Result<(), PortError> {
        self.0.borrow_mut().remove(key);
        Ok(())
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use std::pin::Pin;

    #[test]
    #[should_panic(expected = "Pending")]
    fn block_on_panics_on_pending() {
        // Boxed, so the ready and pending cases share one generic instantiation (line coverage counts each).
        block_on::<Pin<Box<dyn Future<Output = ()>>>>(Box::pin(std::future::pending::<()>()));
    }

    #[test]
    fn block_on_returns_ready() {
        block_on::<Pin<Box<dyn Future<Output = ()>>>>(Box::pin(async {}));
    }

    #[test]
    fn fakes_behave() {
        let c = FixedClock { now_ms: 5 };
        assert_eq!(c.now_ms(), 5);
        block_on(c.sleep_ms(1));

        let (a, b) = (SeededRandom::new(1), SeededRandom::new(1));
        let (mut x, mut y) = ([0u8; 13], [0u8; 13]);
        a.fill(&mut x).unwrap();
        b.fill(&mut y).unwrap();
        assert_eq!(x, y);
        assert_ne!(x, [0u8; 13]);

        let s = MemStorage::default();
        assert_eq!(block_on(s.load("k")).unwrap(), None);
        block_on(s.save("k", b"v")).unwrap();
        assert_eq!(block_on(s.load("k")).unwrap(), Some(b"v".to_vec()));
        block_on(s.remove("k")).unwrap();
        assert_eq!(block_on(s.load("k")).unwrap(), None);

        let s = MemSecrets::default();
        assert!(block_on(s.load("k")).unwrap().is_none());
        block_on(s.save("k", &Zeroizing::new("v".into()))).unwrap();
        assert_eq!(block_on(s.load("k")).unwrap().as_deref().map(String::as_str), Some("v"));
        block_on(s.remove("k")).unwrap();
        assert!(block_on(s.load("k")).unwrap().is_none());
    }
}
