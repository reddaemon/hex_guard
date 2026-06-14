mod grpc;

use hex_guard::HeuristicEngine;
use hex_guard::HexGuard;
use hex_guard::HiddenLinkDetector;
use hex_guard::NetworkChecker;
use hex_guard::SafetyReport;
use grpc::AnalyzeRequest;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::mpsc;

const TELEGRAM_API: &str = "https://api.telegram.org";

#[derive(Debug)]
struct Config {
    bot_token: String,
    alert_chat_id: i64,
    alert_threshold: u8,
    queue_size: usize,
    blacklist_chats: HashSet<i64>,
    listen_addr: String,
}

impl Config {
    fn load() -> anyhow::Result<Self> {
        let config_str = std::fs::read_to_string("config.toml")?;
        let config: toml::Value = config_str.parse()?;

        Ok(Self {
            bot_token: config
                .get("bot")
                .and_then(|b| b.get("token"))
                .and_then(|t| t.as_str())
                .unwrap_or("")
                .to_string(),
            alert_chat_id: config
                .get("bot")
                .and_then(|b| b.get("alert_chat_id"))
                .and_then(|c| c.as_integer())
                .unwrap_or(0),
            alert_threshold: config
                .get("analysis")
                .and_then(|a| a.get("alert_threshold"))
                .and_then(|t| t.as_integer())
                .map(|t| t as u8)
                .unwrap_or(50),
            queue_size: config
                .get("analysis")
                .and_then(|a| a.get("queue_size"))
                .and_then(|q| q.as_integer())
                .map(|q| q as usize)
                .unwrap_or(1000),
            blacklist_chats: config
                .get("filter")
                .and_then(|f| f.get("blacklist_chats"))
                .and_then(|b| b.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_integer())
                        .collect()
                })
                .unwrap_or_default(),
            listen_addr: config
                .get("grpc")
                .and_then(|g| g.get("listen_addr"))
                .and_then(|a| a.as_str())
                .unwrap_or("127.0.0.1:50051")
                .to_string(),
        })
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let config = Config::load()?;
    log::info!("HexGuard gRPC daemon starting on {}", config.listen_addr);
    log::info!(
        "Alert threshold: {}, Queue size: {}, Blacklist: {} chats",
        config.alert_threshold,
        config.queue_size,
        config.blacklist_chats.len()
    );

    let tracer = NetworkChecker::new();
    let guard = Arc::new(HexGuard::new(
        config.queue_size,
        HeuristicEngine::new(),
        HiddenLinkDetector::new(),
        tracer,
    ));
    let client = reqwest::Client::new();

    let (tx, rx) = mpsc::channel::<AnalyzeRequest>(config.queue_size);
    let server = grpc::create_server(tx);

    let listener = tokio::net::TcpListener::bind(&config.listen_addr).await?;
    log::info!("gRPC server listening on {}", config.listen_addr);

    let server_handle = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(server)
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
    });

    let blacklist = config.blacklist_chats;
    let threshold = config.alert_threshold;
    let bot_token = config.bot_token.clone();
    let alert_chat_id = config.alert_chat_id;
    let worker_handle = tokio::spawn(async move {
        process_messages(rx, guard, client, blacklist, threshold, bot_token, alert_chat_id).await
    });

    let shutdown = tokio::signal::ctrl_c();
    tokio::select! {
        _ = shutdown => {
            log::info!("Received shutdown signal");
        }
        result = server_handle => {
            match result {
                Ok(Ok(())) => log::info!("Server exited cleanly"),
                Ok(Err(e)) => log::error!("Server error: {}", e),
                Err(e) => log::error!("Server task error: {}", e),
            }
        }
        result = worker_handle => {
            match result {
                Ok(()) => log::info!("Worker exited cleanly"),
                Err(e) => log::error!("Worker task error: {}", e),
            }
        }
    }

    Ok(())
}

async fn process_messages(
    mut rx: mpsc::Receiver<AnalyzeRequest>,
    guard: Arc<HexGuard<NetworkChecker>>,
    client: reqwest::Client,
    blacklist: HashSet<i64>,
    threshold: u8,
    bot_token: String,
    alert_chat_id: i64,
) {
    while let Some(req) = rx.recv().await {
        if blacklist.contains(&req.chat_id) {
            log::debug!("Skipping blacklisted chat {}", req.chat_id);
            continue;
        }

        log::debug!(
            "Analyzing: chat={}, sender={}, text={}",
            req.chat_id,
            req.sender_name,
            &req.text[..req.text.len().min(100)]
        );

        let report = guard.full_inspect(req.text.as_bytes()).await;

        if report.score >= threshold || !report.zones.is_empty() {
            log::info!(
                "Alert: score={}, zones={:?}, chat={}, sender={}",
                report.score,
                report.zones,
                req.chat_id,
                req.sender_name
            );

            if report.score >= threshold {
                send_alert(&client, &bot_token, alert_chat_id, &req, &report).await;
            }
        }
    }
}

async fn send_alert(
    client: &reqwest::Client,
    bot_token: &str,
    alert_chat_id: i64,
    req: &AnalyzeRequest,
    report: &SafetyReport,
) {
    let score = report.score;
    let zones: Vec<String> = report.zones.iter().map(|z| format!("{:?}", z)).collect();

    let alert_text = if score >= 80 {
        format!(
            "🚨 CRITICAL THREAT\n\
             Score: {} / 100\n\
             Zones: {}\n\
             Chat: {} (@{})\n\
             Sender: {} (ID: {})\n\
             Text: {}",
            score,
            zones.join(", "),
            req.chat_id,
            req.chat_id,
            req.sender_name,
            req.sender_id,
            req.text.chars().take(200).collect::<String>()
        )
    } else if score >= 50 {
        format!(
            "⚠️ SUSPICIOUS\n\
             Score: {} / 100\n\
             Zones: {}\n\
             Chat: {} (@{})\n\
             Sender: {} (ID: {})\n\
             Text: {}",
            score,
            zones.join(", "),
            req.chat_id,
            req.chat_id,
            req.sender_name,
            req.sender_id,
            req.text.chars().take(200).collect::<String>()
        )
    } else {
        format!(
            "🔍 LOW THREAT\n\
             Score: {} / 100\n\
             Zones: {}\n\
             Chat: {} (@{})\n\
             Sender: {} (ID: {})",
            score,
            zones.join(", "),
            req.chat_id,
            req.chat_id,
            req.sender_name,
            req.sender_id
        )
    };

    let url = format!("{}/bot{}/sendMessage", TELEGRAM_API, bot_token);

    let body = serde_json::json!({
        "chat_id": alert_chat_id,
        "text": alert_text,
    });

    match client.post(&url).json(&body).send().await {
        Ok(res) => {
            if res.status().is_success() {
                log::info!("Alert sent");
            } else {
                log::error!("Failed to send alert: {}", res.status());
            }
        }
        Err(e) => log::error!("Send error: {}", e),
    }
}
