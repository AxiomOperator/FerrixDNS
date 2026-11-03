use idna::AsciiDenyList;
use thiserror::Error;

const MAX_NAME_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

/// Why a string could not be normalized into a [`DomainName`].
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum NameError {
    #[error("name is empty")]
    Empty,
    #[error("name is longer than {MAX_NAME_LEN} bytes")]
    TooLong,
    #[error("name has an empty label")]
    EmptyLabel,
    #[error("name has a label longer than {MAX_LABEL_LEN} bytes")]
    LabelTooLong,
    #[error("name contains whitespace or control characters")]
    InvalidCharacter,
    #[error("name failed IDNA conversion")]
    Idna,
}

/// A fully qualified domain name in lowercase ASCII (A-label) form, without the trailing dot.
///
/// The root name is represented by the empty string.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DomainName(Box<str>);

impl DomainName {
    /// Normalizes a name: applies IDNA conversion, lowercases it and removes one trailing dot.
    pub fn parse(input: &str) -> Result<Self, NameError> {
        if input.is_empty() {
            return Err(NameError::Empty);
        }
        if input == "." {
            return Ok(Self("".into()));
        }

        let trimmed = input.strip_suffix('.').unwrap_or(input);
        let ascii = if trimmed.is_ascii() {
            trimmed.to_ascii_lowercase()
        } else {
            idna::domain_to_ascii_cow(trimmed.as_bytes(), AsciiDenyList::EMPTY)
                .map_err(|_| NameError::Idna)?
                .into_owned()
        };

        validate(&ascii)?;
        Ok(Self(ascii.into_boxed_str()))
    }

    /// The normalized name. It is empty for the root.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this is the root name.
    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    /// This name followed by each parent, on label boundaries, excluding the root.
    pub(crate) fn suffixes(&self) -> impl Iterator<Item = &str> {
        let mut rest = (!self.is_root()).then_some(self.as_str());
        std::iter::from_fn(move || {
            let current = rest?;
            rest = current.split_once('.').map(|(_, parent)| parent);
            Some(current)
        })
    }
}

fn validate(name: &str) -> Result<(), NameError> {
    if name.len() > MAX_NAME_LEN {
        return Err(NameError::TooLong);
    }
    for label in name.split('.') {
        if label.is_empty() {
            return Err(NameError::EmptyLabel);
        }
        if label.len() > MAX_LABEL_LEN {
            return Err(NameError::LabelTooLong);
        }
        if !label.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(NameError::InvalidCharacter);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn norm(input: &str) -> String {
        DomainName::parse(input).unwrap().as_str().to_owned()
    }

    #[test]
    fn lowercases_and_removes_the_trailing_dot() {
        assert_eq!(norm("WWW.Example.COM."), "www.example.com");
    }

    #[test]
    fn converts_unicode_to_a_labels() {
        assert_eq!(norm("BÜCHER.example"), "xn--bcher-kva.example");
        assert_eq!(norm("xn--bcher-kva.example"), "xn--bcher-kva.example");
    }

    #[test]
    fn keeps_underscores_for_service_names() {
        assert_eq!(norm("_dmarc.example.com"), "_dmarc.example.com");
    }

    #[test]
    fn represents_the_root_as_empty() {
        assert!(DomainName::parse(".").unwrap().is_root());
    }

    #[test]
    fn rejects_invalid_names() {
        assert_eq!(DomainName::parse(""), Err(NameError::Empty));
        assert_eq!(DomainName::parse("a..b"), Err(NameError::EmptyLabel));
        assert_eq!(DomainName::parse(".."), Err(NameError::EmptyLabel));
        assert_eq!(
            DomainName::parse("a b.com"),
            Err(NameError::InvalidCharacter)
        );
        assert_eq!(
            DomainName::parse(&format!("{}.com", "a".repeat(64))),
            Err(NameError::LabelTooLong)
        );
        let long = vec!["a".repeat(60); 5].join(".");
        assert_eq!(DomainName::parse(&long), Err(NameError::TooLong));
    }

    #[test]
    fn suffixes_stop_at_label_boundaries() {
        let name = DomainName::parse("a.b.example.com").unwrap();
        let suffixes: Vec<_> = name.suffixes().collect();
        assert_eq!(
            suffixes,
            ["a.b.example.com", "b.example.com", "example.com", "com"]
        );
        assert_eq!(DomainName::parse(".").unwrap().suffixes().count(), 0);
    }
}
