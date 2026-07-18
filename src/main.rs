mod grpc;

use hex_guard::HeuristicEngine;
use hex_guard::HexGuard;
use hex_guard::HiddenLinkDetector;
use hex_guard::MessageContext;
use hex_guard::SafetyReport;
use grpc::AnalyzeRequest;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::mpsc;

const TELEGRAM_API: &str = "https://api.telegram.org";

#[derive(Debug, serde::Deserialize)]
struct Config {
    #[serde(default = "default_bot")]
    bot: BotConfig,
    #[serde(default = "default_analysis")]
    analysis: AnalysisConfig,
    #[serde(default = "default_filter")]
    filter: FilterConfig,
    #[serde(default = "default_grpc")]
    grpc: GrpcConfig,
}

#[derive(Debug, serde::Deserialize)]
struct BotConfig {
    #[serde(default)]
    token: String,
    #[serde(default)]
    alert_chat_id: i64,
}

#[derive(Debug, serde::Deserialize)]
struct AnalysisConfig {
    #[serde(default = "default_threshold")]
    alert_threshold: u8,
    #[serde(default = "default_queue_size")]
    queue_size: usize,
}

#[derive(Debug, serde::Deserialize)]
struct FilterConfig {
    #[serde(default)]
    blacklist_chats: HashSet<i64>,
}

#[derive(Debug, serde::Deserialize)]
struct GrpcConfig {
    #[serde(default = "default_listen_addr")]
    listen_addr: String,
}

fn default_bot() -> BotConfig {
    BotConfig {
        token: String::new(),
        alert_chat_id: 0,
    }
}

fn default_analysis() -> AnalysisConfig {
    AnalysisConfig {
        alert_threshold: 50,
        queue_size: 1000,
    }
}

fn default_filter() -> FilterConfig {
    FilterConfig {
        blacklist_chats: HashSet::new(),
    }
}

fn default_grpc() -> GrpcConfig {
    GrpcConfig {
        listen_addr: "127.0.0.1:50051".into(),
    }
}

fn default_threshold() -> u8 {
    50
}

fn default_queue_size() -> usize {
    1000
}

fn default_listen_addr() -> String {
    "127.0.0.1:50051".into()
}

impl Config {
    fn load() -> anyhow::Result<Self> {
        let config_str = std::fs::read_to_string("config.toml")?;
        Ok(toml::from_str(&config_str)?)
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("debug"),
    ).init();

    let config = Config::load()?;
    log::info!("HexGuard gRPC daemon starting on {}", config.grpc.listen_addr);
    log::info!(
        "Alert threshold: {}, Queue size: {}, Blacklist: {} chats",
        config.analysis.alert_threshold,
        config.analysis.queue_size,
        config.filter.blacklist_chats.len()
    );

    let guard = Arc::new(HexGuard::new(
        config.analysis.queue_size,
        HeuristicEngine::new(),
        HiddenLinkDetector::new(),
    ));
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("Failed to build client");

    let (tx, rx) = mpsc::channel::<AnalyzeRequest>(config.analysis.queue_size);
    let server = grpc::create_server(tx);

    let listener = tokio::net::TcpListener::bind(&config.grpc.listen_addr).await?;
    log::info!("gRPC server listening on {}", config.grpc.listen_addr);

    let server_handle = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(server)
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
    });

    let blacklist = config.filter.blacklist_chats;
    let threshold = config.analysis.alert_threshold;
    let bot_token = config.bot.token.clone();
    let alert_chat_id = config.bot.alert_chat_id;
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
    guard: Arc<HexGuard>,
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

        log::info!(
            "Analyzing: chat={}, sender={}, buttons={}, entities={}, text={}",
            req.chat_id,
            req.sender_name,
            req.button_urls.len(),
            req.entity_urls.len(),
            &req.text.chars().take(100).collect::<String>()
        );

        let ctx = MessageContext {
            text: req.text.clone(),
            button_urls: req.button_urls.clone(),
            entity_urls: req.entity_urls.clone(),
            mentions: req.mentions.clone(),
            sender_bio: req.sender_bio.clone(),
        };

        let report = guard.analyze(&ctx).await;

        log::info!(
            "Result: score={}, zones={:?}, chat={}",
            report.score,
            report.zones,
            req.chat_id
        );

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

    let button_info = if req.button_urls.is_empty() {
        String::new()
    } else {
        format!(
            "\n  Buttons: {}",
            req.button_urls
                .iter()
                .map(|u| u.chars().take(60).collect::<String>())
                .collect::<Vec<_>>()
                .join(", ")
        )
    };

    let alert_text = if score >= 80 {
        format!(
            "🚨 CRITICAL THREAT\n\
             Score: {} / 100\n\
             Zones: {}\n\
             Chat: {} (@{})\n\
             Sender: {} (ID: {}){}\n\
             Text: {}",
            score,
            zones.join(", "),
            req.chat_id,
            req.chat_id,
            req.sender_name,
            req.sender_id,
            button_info,
            req.text.chars().take(200).collect::<String>()
        )
    } else if score >= 50 {
        format!(
            "⚠️ SUSPICIOUS\n\
             Score: {} / 100\n\
             Zones: {}\n\
             Chat: {} (@{})\n\
             Sender: {} (ID: {}){}\n\
             Text: {}",
            score,
            zones.join(", "),
            req.chat_id,
            req.chat_id,
            req.sender_name,
            req.sender_id,
            button_info,
            req.text.chars().take(200).collect::<String>()
        )
    } else {
        format!(
            "🔍 LOW THREAT\n\
             Score: {} / 100\n\
             Zones: {}\n\
             Chat: {} (@{})\n\
             Sender: {} (ID: {}){}",
            score,
            zones.join(", "),
            req.chat_id,
            req.chat_id,
            req.sender_name,
            req.sender_id,
            button_info
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
