use url::Url;

pub struct UrlAnalyzer;

impl UrlAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, url_str: &str) -> (u8, Vec<String>) {
        let mut score: u8 = 0;
        let mut findings: Vec<String> = Vec::new();

        let parsed = match Url::parse(url_str) {
            Ok(u) => u,
            Err(_) => return (score, findings),
        };

        let host = match parsed.host() {
            Some(url::Host::Domain(d)) => d.to_string(),
            Some(url::Host::Ipv4(_) | url::Host::Ipv6(_)) => {
                score = (score + 20).min(100);
                findings.push("IpInsteadOfDomain".to_string());
                return (score, findings);
            }
            None => return (score, findings),
        };

        let host_lower = host.to_lowercase();

        // URL shorteners
        let shorteners = [
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd",
            "ow.ly", "buff.ly", "adf.ly", "lnk.to", "short.link",
            "cutt.ly", "cli.gs", "tr.im", "j.mp", "su.pr",
        ];
        for s in &shorteners {
            if host_lower == *s || host_lower.ends_with(&format!(".{}", s)) {
                score = (score + 15).min(100);
                findings.push("UrlShortener".to_string());
                break;
            }
        }

        // Suspicious TLD
        let suspicious_tlds = [
            ".xyz", ".top", ".club", ".work", ".site",
            ".online", ".bid", ".win", ".date", ".stream",
            ".download", ".rsvp", ".science", ".faith", ".loan",
        ];
        let domain_lower = host_lower.to_lowercase();
        for tld in &suspicious_tlds {
            if domain_lower.ends_with(tld) {
                score = (score + 10).min(100);
                findings.push("SuspiciousTld".to_string());
                break;
            }
        }

        (score, findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normal_url() {
        let analyzer = UrlAnalyzer::new();
        let (score, findings) = analyzer.analyze("https://google.com");
        assert_eq!(score, 0);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_ip_instead_of_domain() {
        let analyzer = UrlAnalyzer::new();
        let (score, findings) = analyzer.analyze("http://192.168.1.1/page");
        assert_eq!(score, 20);
        assert!(findings.contains(&"IpInsteadOfDomain".to_string()));
    }

    #[test]
    fn test_url_shortener() {
        let analyzer = UrlAnalyzer::new();
        let (score, findings) = analyzer.analyze("https://bit.ly/3abc");
        assert_eq!(score, 15);
        assert!(findings.contains(&"UrlShortener".to_string()));
    }

    #[test]
    fn test_suspicious_tld() {
        let analyzer = UrlAnalyzer::new();
        let (score, findings) = analyzer.analyze("https://example.xyz");
        assert_eq!(score, 10);
        assert!(findings.contains(&"SuspiciousTld".to_string()));
    }

    #[test]
    fn test_shortener_and_suspicious_tld() {
        let analyzer = UrlAnalyzer::new();
        let (score, _) = analyzer.analyze("https://bit.ly/xyz");
        assert_eq!(score, 15);
    }
}
