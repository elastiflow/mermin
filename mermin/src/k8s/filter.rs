/// Filters items based on include/exclude rules.
///
/// Rules:
/// 1. If an item matches an exclusion rule, it is immediately removed
/// 2. If inclusion list is empty, everything is considered a match
/// 3. Items must match at least one inclusion rule if the list is non-empty
pub struct IncludeExcludeFilter {
    include: Vec<String>,
    exclude: Vec<String>,
}

impl IncludeExcludeFilter {
    pub fn new(include: Vec<String>, exclude: Vec<String>) -> Self {
        Self { include, exclude }
    }

    /// Returns true if the item passes the filter (should be included)
    pub fn matches(&self, item: &str) -> bool {
        // Rule 1: Exclusions override everything
        if self.exclude.iter().any(|e| e.eq_ignore_ascii_case(item)) {
            return false;
        }

        // Rule 2: Empty include list means match everything (that wasn't excluded)
        if self.include.is_empty() {
            return true;
        }

        // Rule 3: Must match at least one inclusion rule
        self.include.iter().any(|i| i.eq_ignore_ascii_case(item))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_lists_matches_everything() {
        let filter = IncludeExcludeFilter::new(vec![], vec![]);
        assert!(filter.matches("anything"));
    }

    #[test]
    fn test_exclude_overrides_include() {
        let filter =
            IncludeExcludeFilter::new(vec!["Service".to_string()], vec!["Service".to_string()]);
        assert!(!filter.matches("Service"));
    }

    #[test]
    fn test_include_with_empty_exclude() {
        let filter =
            IncludeExcludeFilter::new(vec!["Pod".to_string(), "Service".to_string()], vec![]);
        assert!(filter.matches("Pod"));
        assert!(filter.matches("Service"));
        assert!(!filter.matches("Deployment"));
    }

    #[test]
    fn test_case_insensitive() {
        let filter = IncludeExcludeFilter::new(vec!["Pod".to_string()], vec![]);
        assert!(filter.matches("pod"));
        assert!(filter.matches("POD"));
        assert!(filter.matches("Pod"));
    }
}
