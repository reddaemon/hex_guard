use crate::heuristics::HeuristicEngine;
use crate::hidden_links::{HiddenLinkDetector, HiddenLinkType};
use crate::text_analysis::DangerZone;

use lru::LruCache;
use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct SafetyReport {
    pub score: u8,
    pub zones: Vec<DangerZone>,
    pub final_url: Option<String>,
}

#[allow(async_fn_in_trait)]
pub trait UrlTracer: Send + Sync {
    async fn trace_url(&self, url: &str) -> Result<SafetyReport, String>;
}

pub struct HexGuard<T: UrlTracer> {
    heuristics: HeuristicEngine,
    hidden_links: HiddenLinkDetector,
    cache: Mutex<LruCache<u64, SafetyReport>>,
    tracer: T,
}

impl<T: UrlTracer> HexGuard<T> {
    pub fn new(capacity: usize, heuristics: HeuristicEngine, hidden_links: HiddenLinkDetector, tracer: T) -> Self {
        Self {
            heuristics,
            hidden_links,
            cache: Mutex::new(LruCache::new(
                std::num::NonZeroUsize::new(capacity).unwrap(),
            )),
            tracer,
        }
    }

    fn calculate_hash(&self, data: &[u8]) -> u64 {
        let mut hasher = DefaultHasher::new();
        hasher.write(data);
        hasher.finish()
    }

    pub async fn full_inspect(&self, raw_data: &[u8]) -> SafetyReport {
        let data_hash = self.calculate_hash(raw_data);

        // 1. Быстрый чек кэша
        {
            let mut cache_lock = self.cache.lock().await;
            if let Some(cached_report) = cache_lock.get(&data_hash) {
                return cached_report.clone();
            }
        }

        // 2. Локальный анализ через HeuristicEngine
        let text_content = std::str::from_utf8(raw_data).unwrap_or("");
        let heuristic_score = self.heuristics.check_text(text_content);

        // 2.5. Детекция скрытых ссылок
        let hidden_links = self.hidden_links.detect(text_content);
        let mut hidden_score: u8 = 0;
        let mut hidden_zones: Vec<DangerZone> = Vec::new();

        for link in &hidden_links {
            hidden_score = (hidden_score + link.risk_level).min(100);
            hidden_zones.push(match link.link_type {
                HiddenLinkType::ZeroWidthChars => DangerZone::ZeroWidthChars,
                HiddenLinkType::InvisibleUrl => DangerZone::InvisibleUrl,
                HiddenLinkType::HomographUrl => DangerZone::Homograph,
                HiddenLinkType::DangerousScheme => DangerZone::DangerousScheme,
                HiddenLinkType::UrlMismatch => DangerZone::UrlMismatch,
                HiddenLinkType::ObfuscatedUrl => DangerZone::ObfuscatedUrl,
                HiddenLinkType::RedirectChain => DangerZone::RedirectLoop,
            });
        }

        let mut report = SafetyReport {
            score: (heuristic_score + hidden_score).min(100),
            zones: hidden_zones,
            final_url: None,
        };

        // 3. Вызов внешней трассировки через абстрактный tracer
        if !text_content.is_empty() {
            if let Ok(network_report) = self.tracer.trace_url(text_content).await {
                report.score = std::cmp::max(report.score, network_report.score);
                report.zones.extend(network_report.zones);
                report.final_url = network_report.final_url;
            }
        }

        // 4. Пишем итоговый отчет в кэш
        {
            let mut cache_lock = self.cache.lock().await;
            cache_lock.put(data_hash, report.clone());
        }

        report
    }
}
