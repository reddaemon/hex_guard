use unicode_normalization::UnicodeNormalization;
use unicode_skeleton::UnicodeSkeleton;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DangerZone {
    Homograph,
    PhishingKeywords,
    HiddenUrl,
    SuspiciousParams,
    RedirectLoop,
    ZeroWidthChars,
    InvisibleUrl,
    DangerousScheme,
    UrlMismatch,
    ObfuscatedUrl,
    Clear,
}

pub struct AnalysisResult {
    pub is_suspicious: bool,
    pub has_hidden_chars: bool,
    pub detected_skeleton: String,
    pub original_cleaned: String,
}

/// Analyze text for hidden chars, homoglyphs, and visual tricks.
pub fn analyze_text(raw_text: &str) -> AnalysisResult {
    let has_hidden = raw_text
        .chars()
        .any(|c| c == '\u{200b}' || c == '\u{feff}' || c.is_control());
    let cleaned: String = raw_text.nfc().collect();
    let skeleton: String = cleaned.skeleton_chars().collect();
    let is_suspicious = has_hidden || is_homograph_attack(&cleaned);

    AnalysisResult {
        is_suspicious,
        has_hidden_chars: has_hidden,
        detected_skeleton: skeleton,
        original_cleaned: cleaned,
    }
}

pub fn is_homograph_attack(text: &str) -> bool {
    let mut has_latin = false;
    let mut has_cyrillic = false;

    for c in text.chars() {
        if c.is_alphabetic() {
            if c.is_ascii() {
                has_latin = true;
            } else {
                has_cyrillic = true;
            }
        }
    }

    has_latin && has_cyrillic
}

pub fn clean_text(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control() && *c != '\u{200b}' && *c != '\u{feff}')
        .collect()
}

pub fn are_visually_similar(url1: &str, url2: &str) -> bool {
    let skel1 = clean_text(url1).skeleton_chars().collect::<String>();
    let skel2 = clean_text(url2).skeleton_chars().collect::<String>();
    skel1 == skel2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_homograph_detection() {
        let fake_google = "g\u{043e}\u{043e}gle.com";
        let real_google = "google.com";

        assert!(is_homograph_attack(fake_google));
        assert!(!is_homograph_attack(real_google));
        assert_eq!(get_skeleton(fake_google), get_skeleton(real_google));
    }

    #[test]
    fn test_extreme_unicode_obfuscation() {
        let sneaky_url = "g\u{043e}\u{03bf}gle.com\u{200b}";
        let result = analyze_text(sneaky_url);

        assert!(result.has_hidden_chars, "Must detect zero-width space");
        assert!(result.is_suspicious, "This is an attack");
        assert!(
            result.detected_skeleton.contains("corn") || result.detected_skeleton.contains("com")
        );
        assert_ne!(result.original_cleaned, "google.com");
    }

    fn get_skeleton(text: &str) -> String {
        text.skeleton_chars().collect()
    }
}
