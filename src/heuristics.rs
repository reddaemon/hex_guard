#[derive(Debug)]
pub struct HeuristicEngine {
    pub bad_patterns: Vec<&'static str>,
}

impl Default for HeuristicEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl HeuristicEngine {
    pub fn new() -> Self {
        Self {
            bad_patterns: vec![
                "confirm your password",
                "введите ваш пароль",
                "account will be deleted",
                "official support",
                "base64,",
                "eval(",
                "javascript:",
                "onerror=",
                "script",
                "blob:",
            ],
        }
    }

    pub fn check_text(&self, text: &str) -> u8 {
        let mut score = 0;
        let lower_text = text.to_lowercase();

        for pattern in &self.bad_patterns {
            if lower_text.contains(pattern) {
                score += 35;
            }
        }
        score.min(100)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_heuristic_check_clear_text() {
        let engine = HeuristicEngine::new();
        assert_eq!(engine.check_text("Hello world"), 0);
    }

    #[test]
    fn test_heuristic_check_suspicious_text() {
        let engine = HeuristicEngine::new();
        assert!(engine.check_text("confirm your password") > 0);
        assert!(engine.check_text("javascript:alert(1)") > 0);
    }
}
