use std::io;
use std::sync::{Arc, Mutex};

#[derive(Debug)]
struct PoolState {
    free: Vec<Vec<u8>>,
    checked_out: usize,
    capacity: usize,
    buffer_capacity: usize,
}

/// A fixed-capacity pool. Exhaustion is reported immediately; acquisition
/// never waits and never grows the pool.
#[derive(Clone, Debug)]
pub struct BoundedBufferPool {
    state: Arc<Mutex<PoolState>>,
}

impl BoundedBufferPool {
    pub fn new(capacity: usize, buffer_capacity: usize) -> io::Result<Self> {
        if capacity == 0 || buffer_capacity == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "buffer pool dimensions must be nonzero",
            ));
        }
        let mut free = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            free.push(Vec::with_capacity(buffer_capacity));
        }
        Ok(Self {
            state: Arc::new(Mutex::new(PoolState {
                free,
                checked_out: 0,
                capacity,
                buffer_capacity,
            })),
        })
    }

    pub fn try_acquire(&self) -> io::Result<Option<PooledBuffer>> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("buffer pool mutex poisoned"))?;
        let Some(mut bytes) = state.free.pop() else {
            return Ok(None);
        };
        bytes.clear();
        state.checked_out += 1;
        Ok(Some(PooledBuffer {
            bytes: Some(bytes),
            state: Arc::clone(&self.state),
        }))
    }

    pub fn snapshot(&self) -> io::Result<BufferPoolSnapshot> {
        let state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("buffer pool mutex poisoned"))?;
        Ok(BufferPoolSnapshot {
            capacity: state.capacity,
            available: state.free.len(),
            checked_out: state.checked_out,
            buffer_capacity: state.buffer_capacity,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BufferPoolSnapshot {
    pub capacity: usize,
    pub available: usize,
    pub checked_out: usize,
    pub buffer_capacity: usize,
}

pub struct PooledBuffer {
    bytes: Option<Vec<u8>>,
    state: Arc<Mutex<PoolState>>,
}

impl PooledBuffer {
    pub fn try_extend_from_slice(&mut self, bytes: &[u8]) -> io::Result<()> {
        let target = self
            .bytes
            .as_mut()
            .ok_or_else(|| io::Error::other("pooled buffer already returned"))?;
        if target.len().saturating_add(bytes.len()) > target.capacity() {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "record exceeds fixed pooled-buffer capacity",
            ));
        }
        target.extend_from_slice(bytes);
        Ok(())
    }

    pub fn as_slice(&self) -> &[u8] {
        self.bytes.as_deref().unwrap_or_default()
    }

    pub fn len(&self) -> usize {
        self.as_slice().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        let Some(mut bytes) = self.bytes.take() else {
            return;
        };
        bytes.clear();
        if let Ok(mut state) = self.state.lock() {
            if bytes.capacity() == state.buffer_capacity && state.free.len() < state.capacity {
                state.free.push(bytes);
            }
            state.checked_out = state.checked_out.saturating_sub(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exhaustion_is_nonblocking_and_drop_returns_capacity() {
        let pool = BoundedBufferPool::new(2, 16).unwrap();
        let first = pool.try_acquire().unwrap().unwrap();
        let second = pool.try_acquire().unwrap().unwrap();
        assert!(pool.try_acquire().unwrap().is_none());
        assert_eq!(pool.snapshot().unwrap().checked_out, 2);
        drop(first);
        assert!(pool.try_acquire().unwrap().is_some());
        drop(second);
    }

    #[test]
    fn oversized_record_is_rejected_without_growing_buffer() {
        let pool = BoundedBufferPool::new(1, 4).unwrap();
        let mut buffer = pool.try_acquire().unwrap().unwrap();
        let error = buffer.try_extend_from_slice(&[0; 5]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
        assert_eq!(buffer.len(), 0);
    }
}
