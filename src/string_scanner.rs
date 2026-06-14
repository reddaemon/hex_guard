#[derive(Debug)]
pub struct FoundString {
    pub content: String,
    pub offset: usize,
    pub is_ascii: bool,
}

fn push_part(results: &mut Vec<FoundString>, part: &mut String, offset: usize, min_len: usize) {
    if part.chars().count() >= min_len {
        results.push(FoundString {
            is_ascii: part.is_ascii(),
            content: part.clone(),
            offset,
        });
    }
    part.clear();
}

pub fn scan_for_strings(data: &[u8], min_len: usize) -> Vec<FoundString> {
    let mut results = Vec::new();
    let mut i = 0;

    while i < data.len() {
        let chunk = &data[i..];

        match std::str::from_utf8(chunk) {
            Ok(s) => {
                extract_if_valid(&mut results, s, i, min_len);
                break;
            }
            Err(e) => {
                let valid_up_to = e.valid_up_to();
                if valid_up_to > 0 {
                    let valid_part = std::str::from_utf8(&chunk[..valid_up_to]).unwrap();
                    extract_if_valid(&mut results, valid_part, i, min_len);
                }
                i += valid_up_to + 1;
            }
        }
    }
    results
}

fn extract_if_valid(results: &mut Vec<FoundString>, s: &str, offset: usize, min_len: usize) {
    let mut current_part = String::new();
    let mut last_was_ascii = None;

    for c in s.chars() {
        if c.is_control() {
            push_part(results, &mut current_part, offset, min_len);
            last_was_ascii = None;
            continue;
        }

        let is_ascii = c.is_ascii();
        if c.is_alphanumeric() {
            if let Some(was_ascii) = last_was_ascii
                && was_ascii != is_ascii {
                    push_part(results, &mut current_part, offset, min_len);
                }
            last_was_ascii = Some(is_ascii);
        }

        current_part.push(c);
    }
    push_part(results, &mut current_part, offset, min_len);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_hidden_utf8() {
        let mut binary_data = vec![0xFF, 0x00, 0x89, 0x50];
        let target_str = "Привет, мир!";
        binary_data.extend_from_slice(target_str.as_bytes());
        binary_data.extend_from_slice(&[0x00, 0x01, 0x02]);

        let found = scan_for_strings(&binary_data, 5);

        for f in &found {
            println!("Found: '{}' at offset {}", f.content, f.offset);
        }

        assert!(
            found.iter().any(|s| s.content == target_str),
            "String not found in results: {:?}",
            found.iter().map(|f| &f.content).collect::<Vec<_>>()
        );
    }
}
