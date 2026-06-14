use crate::text_analysis::clean_text;
use url::Url;

#[derive(Debug, Clone, PartialEq)]
pub enum HiddenLinkType {
    ZeroWidthChars,
    InvisibleUrl,
    HomographUrl,
    DangerousScheme,
    UrlMismatch,
    ObfuscatedUrl,
    RedirectChain,
}

#[derive(Debug)]
pub struct HiddenLink {
    pub link_type: HiddenLinkType,
    pub visible_text: String,
    pub actual_url: String,
    pub risk_level: u8,
}

pub struct HiddenLinkDetector {
    dangerous_schemes: Vec<&'static str>,
}

impl Default for HiddenLinkDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl HiddenLinkDetector {
    pub fn new() -> Self {
        Self {
            dangerous_schemes: vec!["javascript:", "data:", "vnd.telegram://", "tel:", "mailto:"],
        }
    }

    /// Extract all URLs from text and detect hidden link patterns.
    pub fn detect(&self, text: &str) -> Vec<HiddenLink> {
        let mut results = Vec::new();

        self.detect_zero_width_links(text, &mut results);
        self.detect_invisible_urls(text, &mut results);
        self.detect_homograph_links(text, &mut results);
        self.detect_dangerous_schemes(text, &mut results);
        self.detect_url_mismatch(text, &mut results);
        self.detect_obfuscated_urls(text, &mut results);

        results
    }

    fn detect_zero_width_links(&self, text: &str, results: &mut Vec<HiddenLink>) {
        let zero_width_chars = ['\u{200b}', '\u{200c}', '\u{200d}', '\u{feff}', '\u{2060}'];
        let mut has_zw = false;
        let mut zw_count = 0;

        for c in text.chars() {
            if zero_width_chars.contains(&c) {
                has_zw = true;
                zw_count += 1;
            }
        }

        if has_zw
            && zw_count >= 2
            && let Some(url) = extract_url_from_text(text)
        {
            results.push(HiddenLink {
                link_type: HiddenLinkType::ZeroWidthChars,
                visible_text: clean_text(text),
                actual_url: url,
                risk_level: 60,
            });
        }
    }

    fn detect_invisible_urls(&self, text: &str, results: &mut Vec<HiddenLink>) {
        // Проверяем, есть ли в тексте хотя бы один невидимый символ
        let has_zw_chars = text
            .chars()
            .any(|c| c == '\u{200b}' || c == '\u{200c}' || c == '\u{200d}' || c == '\u{feff}');

        if has_zw_chars {
            // Очищаем строку ОТ невидимых символов (инвертируем фильтр)
            let cleaned_text: String = text
                .chars()
                .filter(|c| {
                    *c != '\u{200b}' && *c != '\u{200c}' && *c != '\u{200d}' && *c != '\u{feff}'
                })
                .collect();

            // Теперь сканируем очищенную строку нашей функцией extract_url_from_text
            if let Some(url) = extract_url_from_text(&cleaned_text) {
                // Защита от дубликатов в результатах
                if !results.iter().any(|l| l.actual_url == url) {
                    results.push(HiddenLink {
                        link_type: HiddenLinkType::InvisibleUrl,
                        visible_text: cleaned_text, // Показываем чистый текст без мусора
                        actual_url: url,
                        risk_level: 80,
                    });
                }
            }
        }
    }

    fn detect_homograph_links(&self, text: &str, results: &mut Vec<HiddenLink>) {
        let text_lower = text.to_lowercase();

        for word in text_lower.split_whitespace() {
            if word.contains("http://") || word.contains("https://") || word.contains('.') {
                let mut has_ascii_alpha = false;
                let mut has_non_ascii_alpha = false;

                for c in word.chars() {
                    if c.is_alphabetic() {
                        if c.is_ascii() {
                            has_ascii_alpha = true;
                        } else {
                            has_non_ascii_alpha = true;
                        }
                    }
                }

                // Смешивание алфавитов в одном домене — это омограф
                if has_ascii_alpha && has_non_ascii_alpha {
                    let raw_url = word.to_string();
                    if !results.iter().any(|l| l.actual_url == raw_url) {
                        results.push(HiddenLink {
                            link_type: HiddenLinkType::HomographUrl, // Целевой тип для этого теста
                            visible_text: clean_text(text),
                            actual_url: raw_url,
                            risk_level: 95,
                        });
                    }
                }
            }
        }
    }

    fn detect_dangerous_schemes(&self, text: &str, results: &mut Vec<HiddenLink>) {
        let lower = text.to_lowercase();

        for scheme in &self.dangerous_schemes {
            let mut start_pos = 0;

            // Ищем все вхождения опасной схемы (например, "javascript:")
            while let Some(found_idx) = lower[start_pos..].find(*scheme) {
                let absolute_idx = start_pos + found_idx;
                let remaining_text = &text[absolute_idx..];

                // Извлекаем всю опасную строку целиком (до первого пробела)
                let actual_url = remaining_text
                    .split_whitespace()
                    .next()
                    .unwrap_or(remaining_text)
                    .to_string();

                // Избегаем дубликатов в векторе результатов
                if !results.iter().any(|l| l.actual_url == actual_url) {
                    results.push(HiddenLink {
                        link_type: HiddenLinkType::DangerousScheme,
                        visible_text: text.to_string(), // Для javascript: видимый текст — это сама строка
                        actual_url,
                        risk_level: 90,
                    });
                }

                // Сдвигаем указатель, чтобы не зациклиться
                start_pos = absolute_idx + scheme.len();
            }
        }
    }

    fn detect_url_mismatch(&self, text: &str, results: &mut Vec<HiddenLink>) {
        if let Some(url) = extract_url_from_text(text)
            && let Ok(parsed) = Url::parse(&url)
            && let Some(domain) = parsed.host()
        {
            let domain_str = domain.to_string();
            let domain_lower = domain_str.to_lowercase();

            let text_words: Vec<&str> = text.split_whitespace().collect();
            for word in text_words {
                // Убираем точки, запятые, скобки на концах слов, которые часто ставят в предложениях
                let clean_word = word.trim_matches(|c: char| c.is_ascii_punctuation());
                let word_lower = clean_word.to_lowercase();
                if word_lower.contains(".")
                    && word_lower.len() > 5
                    && word_lower != domain_lower
                    && !word_lower.contains(&domain_lower)
                    && !domain_str.contains(&word_lower)
                {
                    // Если это слово само по себе было URL с http/https, то это не mismatch
                    if word_lower.contains("http") {
                        continue;
                    }

                    results.push(HiddenLink {
                        link_type: HiddenLinkType::UrlMismatch,
                        visible_text: clean_text(text),
                        actual_url: url,
                        risk_level: 70,
                    });
                    break;
                }
            }
        }
    }

    fn detect_obfuscated_urls(&self, text: &str, results: &mut Vec<HiddenLink>) {
        let text_lower = text.to_lowercase();

        for word in text_lower.split_whitespace() {
            if word.contains("http") || word.contains("://") || word.contains('.') {
                let mut is_obfuscated = false;

                // Техническая обфускация 1: Скрытый хост через @ (UserInfo abuse)
                if word.contains('@') && (word.contains("http://") || word.contains("https://")) {
                    is_obfuscated = true;
                }

                // Техническая обфускация 2: Двойное или избыточное кодирование спецсимволов
                if word.contains("%25") || word.contains("%2e") || word.contains("%2f") {
                    is_obfuscated = true;
                }

                if is_obfuscated {
                    let raw_url = word.to_string();
                    if !results.iter().any(|l| l.actual_url == raw_url) {
                        results.push(HiddenLink {
                            link_type: HiddenLinkType::ObfuscatedUrl, // Чистая техническая обфускация
                            visible_text: clean_text(text),
                            actual_url: raw_url,
                            risk_level: 75,
                        });
                    }
                }
            }
        }
    }
}

pub fn extract_url_from_text(text: &str) -> Option<String> {
    let text = text.trim();

    // 1. Быстрая проверка: вдруг весь текст — это уже чистая ссылка
    if let Ok(parsed) = Url::parse(text) {
        let scheme = parsed.scheme();
        if scheme == "http" || scheme == "https" {
            return Some(parsed.to_string());
        }
    }

    // 2. Ищем начало ссылки (без выделения памяти)
    let start_idx = text.find("http://").or_else(|| text.find("https://"))?;

    // Берем срез строки начиная с "http"
    let remaining = &text[start_idx..];

    // 3. Ищем конец ссылки (первый пробел или угловые скобки)
    let end_idx = remaining
        .find(|c: char| c.is_whitespace() || c == '<' || c == '>')
        .unwrap_or(remaining.len()); // Если пробелов нет, берем до конца строки

    // 4. Вырезаем потенциальную ссылку
    let extracted_str = &remaining[..end_idx];

    // 5. Строго валидируем через парсер
    if let Ok(parsed) = Url::parse(extracted_str) {
        let scheme = parsed.scheme();
        if scheme == "http" || scheme == "https" {
            return Some(parsed.to_string());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_width_url_hiding() {
        let detector = HiddenLinkDetector::new();
        let text = "Проверка\u{200b}https://evil.com\u{200b}аккаунта";
        let links = detector.detect(text);
        assert!(
            links
                .iter()
                .any(|l| l.link_type == HiddenLinkType::ZeroWidthChars),
            "Should detect zero-width URL hiding"
        );
    }

    #[test]
    fn test_homograph_url() {
        let detector = HiddenLinkDetector::new();
        let text = "https://g\u{043e}ogle.com";
        let links = detector.detect(text);
        assert!(
            links
                .iter()
                .any(|l| l.link_type == HiddenLinkType::HomographUrl),
            "Should detect homograph URL"
        );
    }

    #[test]
    fn test_dangerous_scheme() {
        let detector = HiddenLinkDetector::new();
        let text = "javascript:alert(document.cookie)";
        let links = detector.detect(text);
        assert!(
            links
                .iter()
                .any(|l| l.link_type == HiddenLinkType::DangerousScheme),
            "Should detect dangerous scheme"
        );
    }

    #[test]
    fn test_normal_url_no_flags() {
        let detector = HiddenLinkDetector::new();
        let text = "https://google.com";
        let links = detector.detect(text);
        assert!(links.is_empty(), "Normal URL should not be flagged");
    }

    #[test]
    fn test_invisible_url() {
        let detector = HiddenLinkDetector::new();
        let text = "\u{200b}\u{200c}\u{200d}https://evil.com\u{200b}\u{200c}\u{200d}";
        let links = detector.detect(text);
        assert!(
            links
                .iter()
                .any(|l| l.link_type == HiddenLinkType::InvisibleUrl),
            "Should detect invisible URL"
        );
    }

    #[test]
    fn test_obfuscated_url() {
        let detector = HiddenLinkDetector::new();
        // Используем обфускацию через URL-кодирование или @-авторизацию
        let text = "https://google.com%252eattacksite.com";
        let links = detector.detect(text);
        assert!(
            links
                .iter()
                .any(|l| l.link_type == HiddenLinkType::ObfuscatedUrl),
            "Should detect obfuscated URL"
        );
    }

    #[test]
    fn test_extract_url_from_text() {
        let url = extract_url_from_text("Click here: https://example.com/path");
        assert_eq!(
            url.expect("Failed to unwrap URL - check input validity"),
            "https://example.com/path"
        );
    }

    #[test]
    fn test_extract_url_from_text_no_url() {
        let url = extract_url_from_text("No URL here");
        assert!(url.is_none());
    }
}
