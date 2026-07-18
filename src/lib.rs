mod heuristics;
mod hex_guard;
mod hidden_links;
mod string_scanner;
mod text_analysis;
mod url_analyzer;

pub mod pb {
    include!(concat!(env!("OUT_DIR"), "/hex_guard.rs"));
}
pub use heuristics::HeuristicEngine;
pub use hex_guard::{HexGuard, MessageContext, SafetyReport};
pub use hidden_links::{HiddenLink, HiddenLinkDetector, HiddenLinkType};
pub use string_scanner::scan_for_strings;
pub use text_analysis::{
    AnalysisResult, DangerZone, analyze_text, are_visually_similar, clean_text, is_homograph_attack,
};
pub use url_analyzer::UrlAnalyzer;

#[cfg(test)]
mod tests {}
