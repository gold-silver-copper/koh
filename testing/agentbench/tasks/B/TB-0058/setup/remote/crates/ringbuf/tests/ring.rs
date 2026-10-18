use ringbuf::RingBuffer;

#[test]
fn starts_empty() {
    let r: RingBuffer<u8> = RingBuffer::new(4);
    assert!(r.is_empty());
    assert_eq!(r.len(), 0);
    assert_eq!(r.capacity(), 4);
}

#[test]
fn zero_capacity_becomes_one() {
    let mut r = RingBuffer::new(0);
    assert_eq!(r.capacity(), 1);
    assert_eq!(r.push(1), None);
    assert_eq!(r.push(2), Some(1));
}

#[test]
fn push_and_pop_in_order() {
    let mut r = RingBuffer::new(3);
    r.push(1);
    r.push(2);
    assert_eq!(r.pop(), Some(1));
    assert_eq!(r.pop(), Some(2));
    assert_eq!(r.pop(), None);
}

#[test]
fn full_push_overwrites_oldest() {
    let mut r = RingBuffer::new(3);
    for i in 1..=3 {
        assert_eq!(r.push(i), None);
    }
    assert!(r.is_full());
    assert_eq!(r.push(4), Some(1));
    assert_eq!(r.len(), 3);
}

#[test]
fn get_out_of_range_is_none() {
    let mut r = RingBuffer::new(2);
    r.push('a');
    assert_eq!(r.get(0), Some(&'a'));
    assert_eq!(r.get(1), None);
}

#[test]
fn iter_after_wrap_is_oldest_first() {
    let mut r = RingBuffer::new(4);
    for i in 0..6 {
        r.push(i);
    }
    r.pop();
    assert_eq!(r.iter().copied().collect::<Vec<_>>(), vec![3, 4, 5]);
}

#[test]
fn many_wraps() {
    let mut r = RingBuffer::new(5);
    for i in 0..1000u32 {
        r.push(i);
    }
    assert_eq!(r.iter().copied().collect::<Vec<_>>(), vec![995, 996, 997, 998, 999]);
}
