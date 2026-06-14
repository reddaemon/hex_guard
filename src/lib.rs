mod heuristics;
mod hex_guard;
mod hidden_links;
mod network;
mod string_scanner;
mod text_analysis;

pub mod pb {
    include!(concat!(env!("OUT_DIR"), "/hex_guard.rs"));
}
pub use heuristics::HeuristicEngine;
pub use hex_guard::{HexGuard, SafetyReport, UrlTracer};
pub use hidden_links::{HiddenLink, HiddenLinkDetector, HiddenLinkType};
pub use network::NetworkChecker;
pub use string_scanner::scan_for_strings;
pub use text_analysis::{
    AnalysisResult, DangerZone, analyze_text, are_visually_similar, clean_text, is_homograph_attack,
};

#[cfg(test)]
mod tests {}
