//! Containers of at most a fixed number of items, so nothing a peer or a program does grows one
//! without limit.
//!
//! [`Bounded`] is the only queue non-test code may use (`clippy.toml` bans `VecDeque` elsewhere);
//! [`at_most`] decodes the wire's sequences, refusing one past its bound before allocating for it.

#![expect(
    clippy::disallowed_types,
    reason = "the one home of `VecDeque`, behind a bound"
)]

use std::collections::VecDeque;

use serde::de::{self, Deserializer, SeqAccess, Visitor};
use serde::Deserialize;

/// At most `N` items, oldest first: read as the queue it is, grown only within its bound.
#[derive(Debug)]
pub struct Bounded<T, const N: usize>(VecDeque<T>);

impl<T, const N: usize> Default for Bounded<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> std::ops::Deref for Bounded<T, N> {
    type Target = VecDeque<T>;

    fn deref(&self) -> &VecDeque<T> {
        &self.0
    }
}

impl<T, const N: usize> Bounded<T, N> {
    pub const fn new() -> Self {
        Self(VecDeque::new())
    }

    pub fn is_full(&self) -> bool {
        self.0.len() >= N
    }

    /// Add `item` at the back, or give it back if the queue is full.
    pub fn push_back(&mut self, item: T) -> Result<(), T> {
        if self.is_full() {
            return Err(item);
        }
        self.0.push_back(item);
        Ok(())
    }

    /// Add `item` at the back, dropping the oldest to make room: a window of the newest.
    pub fn push_evicting(&mut self, item: T) {
        if self.is_full() {
            self.0.pop_front();
        }
        self.0.push_back(item);
    }

    /// Add `item` at the front, dropping the newest to make room.
    pub fn push_front_evicting(&mut self, item: T) {
        if self.is_full() {
            self.0.pop_back();
        }
        self.0.push_front(item);
    }

    pub fn pop_front(&mut self) -> Option<T> {
        self.0.pop_front()
    }

    pub fn back_mut(&mut self) -> Option<&mut T> {
        self.0.back_mut()
    }

    pub fn retain(&mut self, keep: impl FnMut(&T) -> bool) {
        self.0.retain(keep);
    }

    pub fn clear(&mut self) {
        self.0.clear();
    }
}

/// Decode a sequence of at most `N` items, for `#[serde(deserialize_with = "at_most::<N, _, _>")]`:
/// one announcing more is refused before anything is allocated for it.
pub fn at_most<'de, const N: usize, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    deserializer.deserialize_seq(AtMost::<N, T>(std::marker::PhantomData))
}

struct AtMost<const N: usize, T>(std::marker::PhantomData<T>);

impl<'de, const N: usize, T: Deserialize<'de>> Visitor<'de> for AtMost<N, T> {
    type Value = Vec<T>;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "a sequence of at most {N} items")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<T>, A::Error> {
        let announced = seq.size_hint().unwrap_or(0);
        if announced > N {
            return Err(de::Error::invalid_length(announced, &self));
        }
        let mut items = Vec::with_capacity(announced);
        while let Some(item) = seq.next_element()? {
            if items.len() == N {
                return Err(de::Error::invalid_length(N.saturating_add(1), &self));
            }
            items.push(item);
        }
        Ok(items)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_queue_refuses_or_evicts() {
        let mut q = Bounded::<u8, 2>::default();
        assert_eq!(q.push_back(1), Ok(()));
        assert_eq!(q.push_back(2), Ok(()));
        assert_eq!(q.push_back(3), Err(3));
        q.push_evicting(3);
        assert_eq!(q.iter().copied().collect::<Vec<_>>(), [2, 3]);
    }

    #[test]
    fn a_sequence_past_its_bound_is_refused_before_it_is_read() {
        #[derive(Deserialize)]
        struct Two(#[serde(deserialize_with = "at_most::<2, _, _>")] Vec<u8>);
        let two = postcard::to_allocvec(&vec![1_u8, 2]).unwrap();
        assert_eq!(postcard::from_bytes::<Two>(&two).unwrap().0, [1, 2]);
        let three = postcard::to_allocvec(&vec![1_u8, 2, 3]).unwrap();
        assert!(postcard::from_bytes::<Two>(&three).is_err());
        // A length announcing billions, with no items behind it.
        let huge = postcard::to_allocvec(&u32::MAX).unwrap();
        assert!(postcard::from_bytes::<Two>(&huge).is_err());
    }
}
