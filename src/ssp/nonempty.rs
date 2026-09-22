//! A sequence that always holds at least one element.
//!
//! The SSP transport keeps its sent and received state lists non-empty: the front is the acked
//! diff base and the back is the newest state. Storing the first element separately makes that
//! invariant structural, so `first`/`last` need no `unwrap` and no operation can empty the list.

use std::collections::VecDeque;

#[derive(Debug, Clone)]
pub struct NonEmpty<T> {
    head: T,
    tail: VecDeque<T>,
}

impl<T> NonEmpty<T> {
    pub const fn new(head: T) -> Self {
        Self {
            head,
            tail: VecDeque::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.tail.len() + 1
    }

    pub const fn first(&self) -> &T {
        &self.head
    }

    pub fn last(&self) -> &T {
        self.tail.back().unwrap_or(&self.head)
    }

    pub fn last_mut(&mut self) -> &mut T {
        self.tail.back_mut().unwrap_or(&mut self.head)
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        std::iter::once(&self.head).chain(self.tail.iter())
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        std::iter::once(&mut self.head).chain(self.tail.iter_mut())
    }

    pub fn push(&mut self, value: T) {
        self.tail.push_back(value);
    }

    /// Insert `value` at `index`, shifting later elements back. An `index` past the end appends.
    pub fn insert(&mut self, index: usize, value: T) {
        match index.checked_sub(1) {
            None => {
                let old_head = std::mem::replace(&mut self.head, value);
                self.tail.push_front(old_head);
            }
            Some(i) if i < self.tail.len() => self.tail.insert(i, value),
            Some(_) => self.tail.push_back(value),
        }
    }

    /// Remove and return the element at `index`. Returns `None` if `index` is out of bounds or
    /// removing it would leave the sequence empty.
    pub fn remove(&mut self, index: usize) -> Option<T> {
        match index.checked_sub(1) {
            None => {
                let next = self.tail.pop_front()?;
                Some(std::mem::replace(&mut self.head, next))
            }
            Some(i) => self.tail.remove(i),
        }
    }

    /// Drop the first `count` elements, always keeping at least the last one.
    pub fn drop_front(&mut self, count: usize) {
        for _ in 0..count {
            if self.remove(0).is_none() {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::NonEmpty;

    fn items(n: &NonEmpty<u32>) -> Vec<u32> {
        n.iter().copied().collect()
    }

    #[test]
    fn first_and_last_track_the_ends() {
        let mut n = NonEmpty::new(1);
        assert_eq!((*n.first(), *n.last(), n.len()), (1, 1, 1));
        n.push(2);
        n.push(3);
        assert_eq!((*n.first(), *n.last(), n.len()), (1, 3, 3));
        *n.last_mut() = 4;
        assert_eq!(items(&n), [1, 2, 4]);
        for x in n.iter_mut() {
            *x *= 10;
        }
        assert_eq!(items(&n), [10, 20, 40]);
    }

    #[test]
    fn insert_matches_vec_insert() {
        let mut n = NonEmpty::new(2);
        n.insert(0, 1);
        n.insert(2, 4);
        n.insert(2, 3);
        n.insert(99, 5);
        assert_eq!(items(&n), [1, 2, 3, 4, 5]);
    }

    #[test]
    fn remove_never_empties() {
        let mut n = NonEmpty::new(1);
        n.push(2);
        n.push(3);
        assert_eq!(n.remove(1), Some(2));
        assert_eq!(n.remove(5), None);
        assert_eq!(n.remove(0), Some(1));
        assert_eq!(n.remove(0), None);
        assert_eq!(items(&n), [3]);
    }

    #[test]
    fn drop_front_keeps_the_last_element() {
        let mut n = NonEmpty::new(1);
        n.push(2);
        n.push(3);
        n.drop_front(1);
        assert_eq!(items(&n), [2, 3]);
        n.drop_front(10);
        assert_eq!(items(&n), [3]);
    }
}
