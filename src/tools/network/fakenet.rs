use anyhow::Result;
use serde_json::Value;
use crate::tools::Tool;
use async_trait::async_trait;
use tokio::net::{UdpSocket, TcpListener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct FakeNet;

#[async_trait]
impl Tool for FakeNet {
    fn name(&self) -> &str { "start_fakenet" }
    fn description(&self) -> &str { "Starts FakeNet simulator (DNS Sinkhole + HTTP 200 OK). Args: http_port (default 80), dns_port (default 53)" }

    async fn execute(&self, args: Value) -> Result<Value> {
        let http_port = args["http_port"].as_u64().unwrap_or(8080) as u16;
        let dns_port = args["dns_port"].as_u64().unwrap_or(5353) as u16;

        // DNS Sinkhole Task
        let dns_port_clone = dns_port;
        tokio::spawn(async move {
            match UdpSocket::bind(format!("0.0.0.0:{}", dns_port_clone)).await {
                Ok(socket) => {
                    tracing::info!("FakeNet DNS listening on port {}", dns_port_clone);
                    let mut buf = [0u8; 512];
                    loop {
                        if let Ok((amt, src)) = socket.recv_from(&mut buf).await {
                            tracing::info!("FakeNet DNS Query from {} ({} bytes)", src, amt);
                            // Simple DNS response: copy query, set response flag, add answer
                            // For simplicity, just echo back (malware will see a response)
                            if amt > 12 {
                                let mut response = buf[..amt].to_vec();
                                response[2] = 0x81; // QR=1, Opcode=0, AA=0, TC=0, RD=1
                                response[3] = 0x80; // RA=1, Z=0, RCODE=0
                                let _ = socket.send_to(&response, src).await;
                            }
                        }
                    }
                },
                Err(e) => tracing::error!("FakeNet DNS bind failed: {}", e),
            }
        });

        // HTTP Server Task
        let http_port_clone = http_port;
        tokio::spawn(async move {
            match TcpListener::bind(format!("0.0.0.0:{}", http_port_clone)).await {
                Ok(listener) => {
                    tracing::info!("FakeNet HTTP listening on port {}", http_port_clone);
                    loop {
                        if let Ok((mut socket, addr)) = listener.accept().await {
                            tracing::info!("FakeNet HTTP connection from {}", addr);
                            tokio::spawn(async move {
                                let mut buf = [0u8; 4096];
                                let _ = socket.read(&mut buf).await;
                                let response = "HTTP/1.1 200 OK\r\n\
                                    Content-Type: text/html\r\n\
                                    Content-Length: 45\r\n\
                                    Connection: close\r\n\r\n\
                                    <html><body>NexusCore FakeNet</body></html>";
                                let _ = socket.write_all(response.as_bytes()).await;
                            });
                        }
                    }
                },
                Err(e) => tracing::error!("FakeNet HTTP bind failed: {}", e),
            }
        });

        Ok(serde_json::json!({
            "status": "fakenet_started",
            "http_port": http_port,
            "dns_port": dns_port,
            "note": "Running in background. Use ports > 1024 if not running as admin."
        }))
    }
}
