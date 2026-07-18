use crate::heuristics::HeuristicEngine;
use crate::hidden_links::{HiddenLinkDetector, HiddenLinkType};
use crate::text_analysis::DangerZone;
use crate::url_analyzer::UrlAnalyzer;

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

#[derive(Debug, Clone)]
pub struct MessageContext {
    pub text: String,
    pub button_urls: Vec<String>,
    pub entity_urls: Vec<String>,
    pub mentions: Vec<String>,
    pub sender_bio: String,
}

pub struct HexGuard {
    heuristics: HeuristicEngine,
    hidden_links: HiddenLinkDetector,
    url_analyzer: UrlAnalyzer,
    cache: Mutex<LruCache<u64, SafetyReport>>,
}

impl HexGuard {
    pub fn new(capacity: usize, heuristics: HeuristicEngine, hidden_links: HiddenLinkDetector) -> Self {
        Self {
            heuristics,
            hidden_links,
            url_analyzer: UrlAnalyzer::new(),
            cache: Mutex::new(LruCache::new(
                std::num::NonZeroUsize::new(capacity).unwrap(),
            )),
        }
    }

    fn calculate_hash(&self, ctx: &MessageContext) -> u64 {
        let mut hasher = DefaultHasher::new();
        hasher.write(ctx.text.as_bytes());
        hasher.write(ctx.button_urls.join("\0").as_bytes());
        hasher.write(ctx.entity_urls.join("\0").as_bytes());
        hasher.write(ctx.sender_bio.as_bytes());
        hasher.finish()
    }

    pub async fn analyze(&self, ctx: &MessageContext) -> SafetyReport {
        let data_hash = self.calculate_hash(ctx);

        // 1. Quick cache check
        {
            let mut cache_lock = self.cache.lock().await;
            if let Some(cached_report) = cache_lock.get(&data_hash) {
                return cached_report.clone();
            }
        }

        let mut score: u8 = 0;
        let mut zones: Vec<DangerZone> = Vec::new();
        let mut has_soft_pattern = false;

        // 2. Heuristic check on text
        let (text_score, text_has_soft) = self.heuristics.check_text(&ctx.text);
        score = (score + text_score).min(100);
        has_soft_pattern = has_soft_pattern || text_has_soft;

        // 2.5. Heuristic check on sender bio
        if !ctx.sender_bio.is_empty() {
            let (bio_score, bio_has_soft) = self.heuristics.check_text(&ctx.sender_bio);
            score = (score + bio_score).min(100);
            has_soft_pattern = has_soft_pattern || bio_has_soft;
            if bio_score > 0 {
                zones.push(DangerZone::SenderBioSuspicious);
            }
        }

        // 3. Hidden link detection in text
        let hidden_links = self.hidden_links.detect(&ctx.text);
        for link in &hidden_links {
            score = (score + link.risk_level).min(100);
            zones.push(match link.link_type {
                HiddenLinkType::ZeroWidthChars => DangerZone::ZeroWidthChars,
                HiddenLinkType::InvisibleUrl => DangerZone::InvisibleUrl,
                HiddenLinkType::HomographUrl => DangerZone::Homograph,
                HiddenLinkType::DangerousScheme => DangerZone::DangerousScheme,
                HiddenLinkType::UrlMismatch => DangerZone::UrlMismatch,
                HiddenLinkType::ObfuscatedUrl => DangerZone::ObfuscatedUrl,
                HiddenLinkType::RedirectChain => DangerZone::RedirectLoop,
            });
        }

        // 4. Button URL scoring (+40 each)
        for btn_url in &ctx.button_urls {
            score = (score + 40).min(100);
            zones.push(DangerZone::ButtonUrl);

            // Dry analysis of button URL
            let (url_score, url_findings) = self.url_analyzer.analyze(btn_url);
            score = (score + url_score).min(100);
            for finding in &url_findings {
                match finding.as_str() {
                    "UrlShortener" => zones.push(DangerZone::UrlShortener),
                    "SuspiciousTld" => zones.push(DangerZone::SuspiciousTld),
                    "IpInsteadOfDomain" => zones.push(DangerZone::IpInsteadOfDomain),
                    _ => {}
                }
            }
        }

        // 5. Entity URL scoring (+20 each)
        for entity_url in &ctx.entity_urls {
            score = (score + 20).min(100);
            zones.push(DangerZone::EntityUrl);

            let (url_score, url_findings) = self.url_analyzer.analyze(entity_url);
            score = (score + url_score).min(100);
            for finding in &url_findings {
                match finding.as_str() {
                    "UrlShortener" => zones.push(DangerZone::UrlShortener),
                    "SuspiciousTld" => zones.push(DangerZone::SuspiciousTld),
                    "IpInsteadOfDomain" => zones.push(DangerZone::IpInsteadOfDomain),
                    _ => {}
                }
            }
        }

        // 6. Soft pattern + button bonus (+10)
        if has_soft_pattern && !ctx.button_urls.is_empty() {
            score = (score + 10).min(100);
        }

        let report = SafetyReport {
            score,
            zones,
            final_url: None,
        };

        // 7. Cache result
        {
            let mut cache_lock = self.cache.lock().await;
            cache_lock.put(data_hash, report.clone());
        }

        report
    }
}
