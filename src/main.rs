use anyhow::Result;
use dotenv::dotenv;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();

    // 1. JSON file appender for DEBUG/TRACE logging
    // Creates daily rotating logs in the "logs" directory
    let file_appender = tracing_appender::rolling::daily("logs", "nexuscore.json");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    let file_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(non_blocking)
        .with_filter(EnvFilter::new("debug")); // Detailed logs to file

    // 2. StdErr layer for INFO logging (MCP requires stdout for communication)
    let stderr_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_filter(EnvFilter::new("info")); // Terse logs to console

    // 3. Optional OpenTelemetry layer (Jaeger/OTLP)
    #[cfg(feature = "observability")]
    let otel_layer = {
        use opentelemetry_otlp::WithExportConfig;
        use opentelemetry::trace::TracerProvider as _;
        use opentelemetry_sdk::Resource;
        use opentelemetry::KeyValue;

        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint("http://localhost:4317")
            .build()
            .expect("Failed to create OTLP exporter");

        let tracer_provider = opentelemetry_sdk::trace::TracerProvider::builder()
            .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
            .with_resource(Resource::new(vec![KeyValue::new(
                "service.name",
                "nexuscore-mcp",
            )]))
            .build();

        let tracer = tracer_provider.tracer("nexuscore-mcp");
        opentelemetry::global::set_tracer_provider(tracer_provider);

        tracing_opentelemetry::layer().with_tracer(tracer)
    };

    // 4. Initialize the registry globally
    let registry = tracing_subscriber::registry()
        .with(file_layer)
        .with(stderr_layer);

    #[cfg(feature = "observability")]
    let registry = registry.with(otel_layer);

    registry.init();

    tracing::info!("Starting NexusCore MCP Server (RMCP Standard)...");
    nexuscore_mcp::server::run_server().await
}
