#![cfg(feature = "registry")]
use tracing_futures::{Instrument, WithSubscriber};
use tracing_subscriber::prelude::*;

#[tokio::test]
async fn future_with_subscriber() {
    tracing_subscriber::registry().init();
    let span = tracing::info_span_internal!("foo");
    let _e = span.enter();
    let span = tracing::info_span_internal!("bar");
    let _e = span.enter();
    tokio::spawn(
        async {
            async {
                let span = tracing::Span::current();
                println!("{:?}", span);
            }
            .instrument(tracing::info_span_internal!("hi"))
            .await
        }
        .with_subscriber(tracing_subscriber::registry()),
    )
    .await
    .unwrap();
}
