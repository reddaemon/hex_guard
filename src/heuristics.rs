#[derive(Debug)]
pub struct HeuristicEngine {
    pub hard_patterns: Vec<&'static str>,
    pub soft_patterns: Vec<&'static str>,
}

impl Default for HeuristicEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl HeuristicEngine {
    pub fn new() -> Self {
        Self {
            hard_patterns: vec![
                "confirm your password",
                "введите ваш пароль",
                "account will be deleted",
                "official support",
                "base64,",
                "eval(",
                "javascript:",
                "onerror=",
                "blob:",
            ],
            soft_patterns: vec![
                "перейти по ссылке",
                "перейдите по ссылке",
                "нажмите на ссылку",
                "кликните по ссылке",
                "ссылка ниже",
                "нажмите сюда",
                "перейдите",
                "click the link",
                "click here",
                "verify your account",
                "limited time",
                "act now",
                "срочно",
                "последний шанс",
                "бесплатно",
                "только сегодня",
            ],
        }
    }

    pub fn check_text(&self, text: &str) -> (u8, bool) {
        let mut score = 0;
        let mut has_soft = false;
        let lower_text = text.to_lowercase();

        for pattern in &self.hard_patterns {
            if lower_text.contains(pattern) {
                score += 35;
            }
        }
        for pattern in &self.soft_patterns {
            if lower_text.contains(pattern) {
                score += 5;
                has_soft = true;
            }
        }

        (score.min(100), has_soft)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_heuristic_check_clear_text() {
        let engine = HeuristicEngine::new();
        let (score, has_soft) = engine.check_text("Hello world");
        assert_eq!(score, 0);
        assert!(!has_soft);
    }

    #[test]
    fn test_heuristic_check_suspicious_text() {
        let engine = HeuristicEngine::new();
        let (score, _) = engine.check_text("confirm your password");
        assert!(score > 0);
        let (score2, _) = engine.check_text("javascript:alert(1)");
        assert!(score2 > 0);
    }

    #[test]
    fn test_soft_pattern() {
        let engine = HeuristicEngine::new();
        let (score, has_soft) = engine.check_text("перейти по ссылке");
        assert_eq!(score, 5);
        assert!(has_soft);
    }

    #[test]
    fn test_hard_and_soft_combined() {
        let engine = HeuristicEngine::new();
        let (score, has_soft) = engine.check_text("javascript:alert(1) перейдите по ссылке");
        assert_eq!(score, 45);
        assert!(has_soft);
    }
}
