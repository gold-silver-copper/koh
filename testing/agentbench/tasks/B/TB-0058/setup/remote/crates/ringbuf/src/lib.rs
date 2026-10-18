//! A fixed-capacity ring buffer that overwrites its oldest element when full.

pub struct RingBuffer<T> {
    slots: Vec<Option<T>>,
    head: usize,
    len: usize,
}

impl<T> RingBuffer<T> {
    /// A buffer that holds at most `capacity` elements (at least 1).
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        RingBuffer { slots: (0..capacity).map(|_| None).collect(), head: 0, len: 0 }
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

    pub fn is_full(&self) -> bool {
        self.len == self.capacity()
    }

    /// Appends `value`; when full, drops and returns the oldest element.
    pub fn push(&mut self, value: T) -> Option<T> {
        let cap = self.capacity();
        if self.is_full() {
            let old = self.slots[self.head].replace(value);
            self.head = (self.head + 1) % cap;
            old
        } else {
            let tail = (self.head + self.len) % cap;
            self.slots[tail] = Some(value);
            self.len += 1;
            None
        }
    }

    /// Removes and returns the oldest element.
    pub fn pop(&mut self) -> Option<T> {
        if self.is_empty() {
            return None;
        }
        let v = self.slots[self.head].take();
        self.head = (self.head + 1) % self.capacity();
        self.len -= 1;
        v
    }

    /// The `i`-th element, oldest first.
    pub fn get(&self, i: usize) -> Option<&T> {
        if i >= self.len {
            return None;
        }
        self.slots[(self.head + i) % self.len].as_ref()
    }

    /// The elements, oldest first.
    pub fn iter(&self) -> impl Iterator<Item = &T> + '_ {
        (0..self.len).filter_map(move |i| self.get(i))
    }
}
