use tracing::Level;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn prefixed_span_macros() {
    tracing::span_internal!(Level::DEBUG, "foo");
    tracing::trace_span_internal!("foo");
    tracing::debug_span_internal!("foo");
    tracing::info_span_internal!("foo");
    tracing::warn_span_internal!("foo");
    tracing::error_span_internal!("foo");
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn prefixed_event_macros() {
    tracing::event_internal!(Level::DEBUG, "foo");
    tracing::trace_internal!("foo");
    tracing::debug_internal!("foo");
    tracing::info_internal!("foo");
    tracing::warn_internal!("foo");
    tracing::error_internal!("foo");
}
