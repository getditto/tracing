#![cfg(feature = "env-filter")]

use tracing::{self, subscriber::with_default, Level};
use tracing_mock::*;
use tracing_subscriber::{filter::EnvFilter, prelude::*};

#[test]
#[cfg_attr(not(flaky_tests), ignore)]
fn field_filter_events() {
    let filter: EnvFilter = "[{thing}]=debug".parse().expect("filter should parse");
    let (subscriber, finished) = subscriber::mock()
        .event(
            expect::event()
                .at_level(Level::INFO)
                .with_fields(expect::field("thing")),
        )
        .event(
            expect::event()
                .at_level(Level::DEBUG)
                .with_fields(expect::field("thing")),
        )
        .only()
        .run_with_handle();
    let subscriber = subscriber.with(filter);

    with_default(subscriber, || {
        tracing::trace_internal!(disabled = true);
        tracing::info_internal!("also disabled");
        tracing::info_internal!(thing = 1);
        tracing::debug_internal!(thing = 2);
        tracing::trace_internal!(thing = 3);
    });

    finished.assert_finished();
}

#[test]
#[cfg_attr(not(flaky_tests), ignore)]
fn field_filter_spans() {
    let filter: EnvFilter = "[{enabled=true}]=debug"
        .parse()
        .expect("filter should parse");
    let (subscriber, finished) = subscriber::mock()
        .enter(expect::span().named("span1"))
        .event(
            expect::event()
                .at_level(Level::INFO)
                .with_fields(expect::field("something")),
        )
        .exit(expect::span().named("span1"))
        .enter(expect::span().named("span2"))
        .exit(expect::span().named("span2"))
        .enter(expect::span().named("span3"))
        .event(
            expect::event()
                .at_level(Level::DEBUG)
                .with_fields(expect::field("something")),
        )
        .exit(expect::span().named("span3"))
        .only()
        .run_with_handle();
    let subscriber = subscriber.with(filter);

    with_default(subscriber, || {
        tracing::trace_internal!("disabled");
        tracing::info_internal!("also disabled");
        tracing::info_span_internal!("span1", enabled = true).in_scope(|| {
            tracing::info_internal!(something = 1);
        });
        tracing::debug_span_internal!("span2", enabled = false, foo = "hi").in_scope(|| {
            tracing::warn_internal!(something = 2);
        });
        tracing::trace_span_internal!("span3", enabled = true, answer = 42).in_scope(|| {
            tracing::debug_internal!(something = 2);
        });
    });

    finished.assert_finished();
}

#[test]
fn record_after_created() {
    let filter: EnvFilter = "[{enabled=true}]=debug"
        .parse()
        .expect("filter should parse");
    let (subscriber, finished) = subscriber::mock()
        .enter(expect::span().named("span"))
        .exit(expect::span().named("span"))
        .record(
            expect::span().named("span"),
            expect::field("enabled").with_value(&true),
        )
        .enter(expect::span().named("span"))
        .event(expect::event().at_level(Level::DEBUG))
        .exit(expect::span().named("span"))
        .only()
        .run_with_handle();
    let subscriber = subscriber.with(filter);

    with_default(subscriber, || {
        let span = tracing::info_span_internal!("span", enabled = false);
        span.in_scope(|| {
            tracing::debug_internal!("i'm disabled!");
        });

        span.record("enabled", true);
        span.in_scope(|| {
            tracing::debug_internal!("i'm enabled!");
        });

        tracing::debug_internal!("i'm also disabled");
    });

    finished.assert_finished();
}
