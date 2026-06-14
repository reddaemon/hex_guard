use rand::prelude::IndexedRandom;

use crate::hex_guard::{SafetyReport, UrlTracer};

pub struct NetworkChecker {
    pub client: reqwest::Client,
}

impl Default for NetworkChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkChecker {
    pub fn new() -> Self {
        let user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        ];

        let mut rng = rand::rng();
        let random_ua = user_agents.choose(&mut rng).unwrap_or(&user_agents[0]);

        let client = reqwest::Client::builder()
            .user_agent(*random_ua)
            .build()
            .expect("Failed to build client");

        Self { client }
    }

    pub async fn trace_url(&self, raw_url: &str) -> Result<String, String> {
        let response = self
            .client
            .head(raw_url)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        Ok(response.url().to_string())
    }
}

impl UrlTracer for NetworkChecker {
    async fn trace_url(&self, url: &str) -> Result<SafetyReport, String> {
        let final_url = NetworkChecker::trace_url(self, url).await?;
        Ok(SafetyReport {
            score: 0,
            zones: vec![],
            final_url: Some(final_url),
        })
    }
}
