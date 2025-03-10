#![deny(rust_2018_idioms)]

use tracing::{debug_internal, info_internal};
use tracing_attributes::instrument;

#[instrument]
fn nth_fibonacci(n: u64) -> u64 {
    if n == 0 || n == 1 {
        debug_internal!("Base case");
        1
    } else {
        debug_internal!("Recursing");
        nth_fibonacci(n - 1) + nth_fibonacci(n - 2)
    }
}

#[instrument]
fn fibonacci_seq(to: u64) -> Vec<u64> {
    let mut sequence = vec![];

    for n in 0..=to {
        debug_internal!("Pushing {n} fibonacci", n = n);
        sequence.push(nth_fibonacci(n));
    }

    sequence
}

fn main() {
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter("attrs_args=trace")
        .finish();

    tracing::subscriber::with_default(subscriber, || {
        let n = 5;
        let sequence = fibonacci_seq(n);
        info_internal!("The first {} fibonacci numbers are {:?}", n, sequence);
    })
}
