#![cfg(feature = "registry")]
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tracing::{Level, Subscriber};
use tracing_mock::{expect, layer};
use tracing_subscriber::{filter, prelude::*};

#[test]
fn layer_filter_interests_are_cached() {
    let seen = Arc::new(Mutex::new(HashMap::new()));
    let seen2 = seen.clone();
    let filter = filter::filter_fn(move |meta| {
        *seen
            .lock()
            .unwrap()
            .entry(meta.callsite())
            .or_insert(0usize) += 1;
        meta.level() == &Level::INFO
    });

    let (expect, handle) = layer::mock()
        .event(expect::event().at_level(Level::INFO))
        .event(expect::event().at_level(Level::INFO))
        .only()
        .run_with_handle();

    let subscriber = tracing_subscriber::registry().with(expect.with_filter(filter));
    assert!(subscriber.max_level_hint().is_none());

    let _subscriber = subscriber.set_default();

    fn events() {
        tracing::trace_internal!("hello trace");
        tracing::debug_internal!("hello debug");
        tracing::info_internal!("hello info");
        tracing::warn_internal!("hello warn");
        tracing::error_internal!("hello error");
    }

    events();
    {
        let lock = seen2.lock().unwrap();
        for (callsite, &count) in lock.iter() {
            assert_eq!(
                count, 1,
                "callsite {:?} should have been seen 1 time (after first set of events)",
                callsite
            );
        }
    }

    events();
    {
        let lock = seen2.lock().unwrap();
        for (callsite, &count) in lock.iter() {
            assert_eq!(
                count, 1,
                "callsite {:?} should have been seen 1 time (after second set of events)",
                callsite
            );
        }
    }

    handle.assert_finished();
}
