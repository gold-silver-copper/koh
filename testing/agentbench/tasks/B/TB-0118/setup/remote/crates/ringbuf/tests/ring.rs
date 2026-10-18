use ringbuf::RingBuf;

#[test]
fn push_then_pop_is_fifo() {
    let mut r = RingBuf::with_capacity(3);
    r.push(1);
    r.push(2);
    assert_eq!(r.pop(), Some(1));
    assert_eq!(r.pop(), Some(2));
    assert_eq!(r.pop(), None);
}

#[test]
fn full_buffer_drops_the_oldest() {
    let mut r = RingBuf::with_capacity(3);
    for i in 0..3 {
        assert_eq!(r.push(i), None);
    }
    assert_eq!(r.push(3), Some(0));
    assert_eq!(r.iter().copied().collect::<Vec<_>>(), vec![1, 2, 3]);
}

#[test]
fn drains_in_order_after_wrapping() {
    let mut r = RingBuf::with_capacity(4);
    for i in 0..6 {
        r.push(i);
    }
    let mut out = Vec::new();
    while let Some(x) = r.pop() {
        out.push(x);
    }
    assert_eq!(out, vec![2, 3, 4, 5]);
    assert!(r.is_empty());
}

#[test]
fn interleaved_push_and_pop() {
    let mut r = RingBuf::with_capacity(5);
    let mut want = std::collections::VecDeque::new();
    for i in 0..40 {
        r.push(i);
        want.push_back(i);
        if want.len() > 5 {
            want.pop_front();
        }
        if i % 3 == 0 {
            assert_eq!(r.pop(), want.pop_front());
        }
        assert_eq!(r.iter().copied().collect::<Vec<_>>(), want.iter().copied().collect::<Vec<_>>());
    }
}
