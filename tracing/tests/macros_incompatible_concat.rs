use tracing::{Level, enabled, event_internal, span_internal};

#[macro_export]
macro_rules! concat {
    () => {};
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn span() {
    span_internal!(Level::DEBUG, "foo");
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn event() {
    event_internal!(Level::DEBUG, "foo");
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn enabled() {
    enabled!(Level::DEBUG);
}
