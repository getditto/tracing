#![deny(rust_2018_idioms)]
use std::io;
use tracing::error_internal;

fn main() {
    let subscriber = tracing_subscriber::fmt().with_writer(io::stderr).finish();

    tracing::subscriber::with_default(subscriber, || {
        error_internal!("This event will be printed to `stderr`.");
    });
}
