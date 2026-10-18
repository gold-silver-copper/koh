//! A fixed-capacity ring buffer for the replay recorder.

/// A FIFO queue of at most `capacity` items; pushing onto a full buffer drops the oldest item.
pub struct RingBuf<T> {
    slots: Vec<Option<T>>,
    head: usize,
    len: usize,
}

impl<T> RingBuf<T> {
    pub fn with_capacity(capacity: usize) -> Self {
        RingBuf { slots: (0..capacity).map(|_| None).collect(), head: 0, len: 0 }
    }

    pub fn capacity(&self) -> usize {
        self.slots.len()
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Adds an item at the back. When the buffer is full, the oldest item is dropped and returned.
    pub fn push(&mut self, item: T) -> Option<T> {
        let cap = self.capacity();
        if cap == 0 {
            return Some(item);
        }
        let tail = (self.head + self.len) % cap;
        if self.len == cap {
            let oldest = self.slots.get_mut(tail).and_then(|s| s.replace(item));
            self.head = (self.head + 1) % cap;
            oldest
        } else {
            if let Some(slot) = self.slots.get_mut(tail) {
                *slot = Some(item);
            }
            self.len += 1;
            None
        }
    }

    /// Removes and returns the oldest item.
    pub fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        let item = self.slots.get_mut(self.head).and_then(Option::take);
        self.head = (self.head + 1) % self.len;
        self.len -= 1;
        item
    }

    /// The items from oldest to newest.
    pub fn iter(&self) -> impl Iterator<Item = &T> + '_ {
        let cap = self.capacity().max(1);
        (0..self.len).filter_map(move |i| self.slots.get((self.head + i) % cap).and_then(Option::as_ref))
    }
}
