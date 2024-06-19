//! Tests to ensure events cannot escape through per-layer filters as the result
//! of re-entrant event or span construction. These are regression tests for the
//! following issues:
//!
//! - <https://github.com/tokio-rs/tracing/issues/2704>
//! - <https://github.com/tokio-rs/tracing/issues/2448>
//!
//! Per-layer filters use thread-local state to record whether they enabled an
//! event or span, and then read that state later to determine whether they
//! should process said event or span. Since the sequence of events that the
//! `event!()` macro performs is roughly as follows...
//!
//! 1. Construct the metadata of the event and let the subscriber determine
//!    whether it will be globally disabled (at which point per-layer filters
//!    set their thread-local enablement state)
//! 2. If the event is not globally disabled, construct the event, including the
//!    values of all its fields
//! 3. Pass the event to the subscriber (at which point per-layer filters read
//!    their thread-local enablement state)
//!
//! ...then if, in the process of constructing the event, any *other* spans or
//! events are created, they had the potential to cause the per-layer filters to
//! clobber their thread-local state from the outer event. By the time step 3 is
//! reached, they would believe they had not disabled the outer event,
//! regardless of whether they actually had.
//!
//! This could actually happen in two different ways, the upshot of which is
//! that it doesn't actually matter if the re-entrant event/span would have been
//! enabled by the filter or not; it *still* would cause the outer one to escape
//! the filter. There are tests for both cases.

use super::*;

/// Test that a disabled span, created inside the fields or message of an event,
/// does not cause the outer event to escape a per-layer filter that would
/// otherwise have disabled it.
///
/// This particular test uses a nested span that, like the outer message, should
/// *not* pass the filter (it's at TRACE level, while the filter is at ERROR).
/// This causes the filter to correctly determine that the span is disabled, but
/// when the span is processed, the filter clears its bit in the filter state.
/// The information that the outer event was disabled is therefore clobbered,
/// and it gets through the filter.
#[test]
fn disabled_span_inside_event() {
    let (expect, handle) = layer::named("plf_error").only().run_with_handle();

    let _subscriber = tracing_subscriber::registry()
        .with(expect.with_filter(LevelFilter::ERROR))
        .with(LevelFilter::TRACE)
        .set_default();

    // Regardless of anything else, the layer should *not* receive this event.
    // If this one gets through, something else is wrong!
    tracing::trace!("plain event");

    #[tracing::instrument(level = "trace")]
    fn instrumented() -> &'static str {
        "foo"
    }

    // These events demonstrate the filter escape behaviour. `instrumented()` is
    // run between the enablement determination of the event and its actual
    // processing, causing buggy per-layer filters to clobber their own filter
    // state.
    tracing::trace!("formatted into the message: {}", instrumented());
    tracing::trace!(bar = %instrumented(), "as the value of a field");

    handle.assert_finished();
}

/// Test that an enabled span, created inside the fields or message of an event,
/// does not cause the outer event to escape a per-layer filter that would
/// otherwise have disabled it.
///
/// This test uses a nested span that *should* pass the filter (it's at ERROR
/// level, the only level the filter lets through). This directly clobbers the
/// enablement information of the outer event, since when the per-layer filter
/// first sees the span metadata, it sets its filter state to enabled,
/// overwriting the disabled state that it recorded for the outer event.
#[test]
fn enabled_span_inside_event() {
    let (expect, handle) = layer::named("plf_error")
        .new_span(expect::span().at_level(Level::ERROR))
        .enter(expect::span().at_level(Level::ERROR))
        .exit(expect::span().at_level(Level::ERROR))
        .new_span(expect::span().at_level(Level::ERROR))
        .enter(expect::span().at_level(Level::ERROR))
        .exit(expect::span().at_level(Level::ERROR))
        .only()
        .run_with_handle();

    let _subscriber = tracing_subscriber::registry()
        .with(expect.with_filter(LevelFilter::ERROR))
        .with(LevelFilter::TRACE)
        .set_default();

    // Regardless of anything else, the layer should *not* receive this event.
    // If this one gets through, something else is wrong!
    tracing::trace!("plain event");

    #[tracing::instrument(level = "error")]
    fn instrumented() -> &'static str {
        "foo"
    }

    // These events demonstrate the filter escape behaviour. `instrumented()` is
    // run between the enablement determination of the event and its actual
    // processing, causing buggy per-layer filters to clobber their own filter
    // state.
    tracing::trace!("formatted into the message: {}", instrumented());
    tracing::trace!(bar = %instrumented(), "as the value of a field");

    handle.assert_finished();
}

/// This is exactly like [`disabled_span_inside_event()`], but it uses an
/// *event* nested inside an event. The mechanism of the bug is exactly the
/// same.
#[test]
fn disabled_event_inside_event() {
    let (expect, handle) = layer::named("error").only().run_with_handle();

    let _subscriber = tracing_subscriber::registry()
        .with(expect.with_filter(LevelFilter::ERROR))
        .with(LevelFilter::TRACE)
        .set_default();

    // Regardless of anything else, the layer should *not* receive this event.
    // If this one gets through, something else is wrong!
    tracing::trace!("plain event");

    fn nested_event() -> &'static str {
        tracing::trace!("this is a nested event");
        "foo"
    }

    // These events demonstrate the filter escape behaviour. `instrumented()` is
    // run between the enablement determination of the event and its actual
    // processing, causing buggy per-layer filters to clobber their own filter
    // state.
    tracing::trace!("formatted into the message: {}", nested_event());
    tracing::trace!(bar = %nested_event(), "as the value of a field");

    handle.assert_finished();
}

/// This is exactly like [`enabled_span_inside_event()`], but it uses an *event*
/// nested inside an event. The mechanism of the bug is exactly the same.
#[test]
fn enabled_event_inside_event() {
    let (expect, handle) = layer::named("error")
        .event(expect::event().at_level(Level::ERROR))
        .event(expect::event().at_level(Level::ERROR))
        .only()
        .run_with_handle();

    let _subscriber = tracing_subscriber::registry()
        .with(expect.with_filter(LevelFilter::ERROR))
        .with(LevelFilter::TRACE)
        .set_default();

    // Regardless of anything else, the layer should *not* receive this event.
    // If this one gets through, something else is wrong!
    tracing::trace!("plain event");

    fn nested_event() -> &'static str {
        tracing::error!("this is a nested event");
        "foo"
    }

    // These events demonstrate the filter escape behaviour. `instrumented()` is
    // run between the enablement determination of the event and its actual
    // processing, causing buggy per-layer filters to clobber their own filter
    // state.
    tracing::trace!("formatted into the message: {}", nested_event());
    tracing::trace!(bar = %nested_event(), "as the value of a field");

    handle.assert_finished();
}

/// Just a test for good measure, that this can also be caused by a nested event
/// that appears directly inline in the event macro.
#[test]
fn inline_event_in_event_macro() {
    let (expect, handle) = layer::named("error").only().run_with_handle();

    let _subscriber = tracing_subscriber::registry()
        .with(expect.with_filter(LevelFilter::ERROR))
        .with(LevelFilter::TRACE)
        .set_default();

    tracing::trace!("in the message: {:?}", tracing::trace!("inline event"));
    tracing::trace!(bar = ?tracing::trace!("inline event"), "in a field");

    handle.assert_finished();
}

/// This is again similar to the above tests, but ensures that the *fix* for the
/// bug doesn't rely on keying per-layer filter enablement status by callsite
/// identifier. Otherwise, this event would still escape, because the inner
/// (re-entrant) event comes from exactly the same callsite.
#[test]
fn recursive_events() {
    let (expect, handle) = layer::named("error").only().run_with_handle();

    let _subscriber = tracing_subscriber::registry()
        .with(expect.with_filter(LevelFilter::ERROR))
        .with(LevelFilter::TRACE)
        .set_default();

    fn recurse(n: usize) -> usize {
        if n == 0 {
            return 0;
        }

        tracing::trace!(result = %recurse(n - 1), "recursing");
        n
    }

    recurse(2);

    handle.assert_finished();
}
