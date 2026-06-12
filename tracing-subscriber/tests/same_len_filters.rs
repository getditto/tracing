// These tests include field filters with no targets, so they have to go in a
// separate file.
#![cfg(feature = "env-filter")]

use tracing::{self, subscriber::with_default, Level};
use tracing_mock::*;
use tracing_subscriber::{filter::EnvFilter, prelude::*};

#[test]
fn same_length_targets() {
    let filter: EnvFilter = "foo=trace,bar=trace".parse().expect("filter should parse");
    let (subscriber, finished) = subscriber::mock()
        .event(expect::event().at_level(Level::TRACE))
        .event(expect::event().at_level(Level::TRACE))
        .only()
        .run_with_handle();
    let subscriber = subscriber.with(filter);

    with_default(subscriber, || {
        tracing::trace_internal!(target: "foo", "foo");
        tracing::trace_internal!(target: "bar", "bar");
    });

    finished.assert_finished();
}

#[test]
fn same_num_fields_event() {
    let filter: EnvFilter = "[{foo}]=trace,[{bar}]=trace"
        .parse()
        .expect("filter should parse");
    let (subscriber, finished) = subscriber::mock()
        .event(
            expect::event()
                .at_level(Level::TRACE)
                .with_fields(expect::field("foo")),
        )
        .event(
            expect::event()
                .at_level(Level::TRACE)
                .with_fields(expect::field("bar")),
        )
        .only()
        .run_with_handle();
    let subscriber = subscriber.with(filter);
    with_default(subscriber, || {
        tracing::trace_internal!(foo = 1);
        tracing::trace_internal!(bar = 3);
    });

    finished.assert_finished();
}

#[test]
fn same_num_fields_and_name_len() {
    let filter: EnvFilter = "[foo{bar=1}]=trace,[baz{boz=1}]=trace"
        .parse()
        .expect("filter should parse");
    let (subscriber, finished) = subscriber::mock()
        .new_span(
            expect::span()
                .named("foo")
                .at_level(Level::TRACE)
                .with_fields(expect::field("bar")),
        )
        .new_span(
            expect::span()
                .named("baz")
                .at_level(Level::TRACE)
                .with_fields(expect::field("boz")),
        )
        .only()
        .run_with_handle();
    let subscriber = subscriber.with(filter);
    with_default(subscriber, || {
        tracing::trace_span_internal!("foo", bar = 1);
        tracing::trace_span_internal!("baz", boz = 1);
    });

    finished.assert_finished();
}
