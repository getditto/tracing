use tracing::Level;

fn main() {
    tracing_subscriber::fmt()
        // all spans/events with a level higher than TRACE (e.g, info, warn, etc.)
        // will be written to stdout.
        .with_max_level(Level::TRACE)
        // sets this to be the default, global subscriber for this application.
        .init();

    tracing::error_internal!("SOMETHING IS SERIOUSLY WRONG!!!");
    tracing::warn_internal!("important informational messages; might indicate an error");
    tracing::info_internal!("general informational messages relevant to users");
    tracing::debug_internal!("diagnostics used for internal debugging of a library or application");
    tracing::trace_internal!("very verbose diagnostic events");
}
