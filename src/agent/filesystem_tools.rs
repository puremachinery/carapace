//! Filesystem tools — read, search, write, and move files within configured roots.

use std::path::PathBuf;

use glob::Pattern;

/// Validate that a requested path is allowed by the configured roots and exclude patterns.
pub fn validate_path(
    requested: &str,
    roots: &[PathBuf],
    exclude_patterns: &[Pattern],
) -> Result<PathBuf, String> {
    let canonical = std::fs::canonicalize(requested)
        .map_err(|e| format!("cannot resolve path \"{}\": {}", requested, e))?;

    let matching_root = roots.iter().find(|root| canonical.starts_with(root));
    if matching_root.is_none() {
        return Err(format!(
            "path \"{}\" is outside all configured filesystem roots",
            canonical.display()
        ));
    }
    let root = matching_root.unwrap();

    let relative = canonical.strip_prefix(root).unwrap_or(&canonical);
    for pattern in exclude_patterns {
        if pattern.matches_path(relative) {
            return Err(format!(
                "path \"{}\" is excluded by pattern \"{}\"",
                canonical.display(),
                pattern
            ));
        }
        for component in relative.components() {
            if let std::path::Component::Normal(name) = component {
                if pattern.matches(name.to_str().unwrap_or("")) {
                    return Err(format!(
                        "path \"{}\" is excluded by pattern \"{}\"",
                        canonical.display(),
                        pattern
                    ));
                }
            }
        }
    }

    Ok(canonical)
}

/// Validate a path for write operations where the target file may not exist yet.
pub fn validate_write_path(
    requested: &str,
    roots: &[PathBuf],
    exclude_patterns: &[Pattern],
    create_dirs: bool,
) -> Result<PathBuf, String> {
    let path = PathBuf::from(requested);
    let filename = path
        .file_name()
        .ok_or_else(|| format!("path \"{}\" has no filename", requested))?;

    let parent = path
        .parent()
        .ok_or_else(|| format!("path \"{}\" has no parent directory", requested))?;

    if !parent.exists() {
        if !create_dirs {
            return Err(format!(
                "parent directory \"{}\" does not exist",
                parent.display()
            ));
        }
        let mut ancestor = parent.to_path_buf();
        while !ancestor.exists() {
            ancestor = ancestor
                .parent()
                .ok_or_else(|| "cannot find existing ancestor directory".to_string())?
                .to_path_buf();
        }
        let canonical_ancestor = std::fs::canonicalize(&ancestor)
            .map_err(|e| format!("cannot resolve ancestor \"{}\": {}", ancestor.display(), e))?;

        if !roots
            .iter()
            .any(|root| canonical_ancestor.starts_with(root))
        {
            return Err(format!(
                "path \"{}\" is outside all configured filesystem roots",
                requested
            ));
        }

        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create directories: {}", e))?;
    }

    let canonical_parent = std::fs::canonicalize(parent)
        .map_err(|e| format!("cannot resolve parent \"{}\": {}", parent.display(), e))?;

    let matching_root = roots.iter().find(|root| canonical_parent.starts_with(root));
    if matching_root.is_none() {
        return Err(format!(
            "path \"{}\" is outside all configured filesystem roots",
            requested
        ));
    }
    let root = matching_root.unwrap();

    let full_path = canonical_parent.join(filename);

    let relative = full_path.strip_prefix(root).unwrap_or(&full_path);
    for pattern in exclude_patterns {
        if pattern.matches_path(relative) {
            return Err(format!(
                "path \"{}\" is excluded by pattern \"{}\"",
                full_path.display(),
                pattern
            ));
        }
        for component in relative.components() {
            if let std::path::Component::Normal(name) = component {
                if pattern.matches(name.to_str().unwrap_or("")) {
                    return Err(format!(
                        "path \"{}\" is excluded by pattern \"{}\"",
                        full_path.display(),
                        pattern
                    ));
                }
            }
        }
    }

    Ok(full_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn setup_test_tree() -> TempDir {
        let tmp = TempDir::new().unwrap();
        fs::create_dir_all(tmp.path().join("subdir")).unwrap();
        fs::write(tmp.path().join("hello.txt"), "hello world").unwrap();
        fs::write(tmp.path().join("subdir/nested.txt"), "nested content").unwrap();
        fs::write(tmp.path().join("secret.log"), "sensitive data").unwrap();
        tmp
    }

    #[test]
    fn test_validate_path_within_root() {
        let tmp = setup_test_tree();
        let roots = vec![tmp.path().canonicalize().unwrap()];
        let result = validate_path(tmp.path().join("hello.txt").to_str().unwrap(), &roots, &[]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_path_outside_root() {
        let tmp = setup_test_tree();
        let roots = vec![tmp.path().join("subdir").canonicalize().unwrap()];
        let result = validate_path(tmp.path().join("hello.txt").to_str().unwrap(), &roots, &[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("outside"));
    }

    #[test]
    fn test_validate_path_dotdot_escape() {
        let tmp = setup_test_tree();
        let roots = vec![tmp.path().join("subdir").canonicalize().unwrap()];
        let escaped = tmp.path().join("subdir/../hello.txt");
        let result = validate_path(escaped.to_str().unwrap(), &roots, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_path_exclude_pattern() {
        let tmp = setup_test_tree();
        let roots = vec![tmp.path().canonicalize().unwrap()];
        let pattern = Pattern::new("*.log").unwrap();
        let result = validate_path(
            tmp.path().join("secret.log").to_str().unwrap(),
            &roots,
            &[pattern],
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("excluded"));
    }

    #[test]
    fn test_validate_path_multiple_roots() {
        let tmp1 = TempDir::new().unwrap();
        let tmp2 = TempDir::new().unwrap();
        fs::write(tmp2.path().join("file.txt"), "content").unwrap();
        let roots = vec![
            tmp1.path().canonicalize().unwrap(),
            tmp2.path().canonicalize().unwrap(),
        ];
        let result = validate_path(tmp2.path().join("file.txt").to_str().unwrap(), &roots, &[]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_path_empty_roots() {
        let tmp = setup_test_tree();
        let result = validate_path(tmp.path().join("hello.txt").to_str().unwrap(), &[], &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_path_nonexistent() {
        let tmp = setup_test_tree();
        let roots = vec![tmp.path().canonicalize().unwrap()];
        let result = validate_path(
            tmp.path().join("no_such_file.txt").to_str().unwrap(),
            &roots,
            &[],
        );
        assert!(result.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn test_validate_path_symlink_outside_root() {
        let tmp = setup_test_tree();
        let outside = TempDir::new().unwrap();
        fs::write(outside.path().join("secret.txt"), "outside").unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("secret.txt"),
            tmp.path().join("link.txt"),
        )
        .unwrap();
        let roots = vec![tmp.path().canonicalize().unwrap()];
        let result = validate_path(tmp.path().join("link.txt").to_str().unwrap(), &roots, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_write_path_new_file() {
        let tmp = setup_test_tree();
        let roots = vec![tmp.path().canonicalize().unwrap()];
        let result = validate_write_path(
            tmp.path().join("new_file.txt").to_str().unwrap(),
            &roots,
            &[],
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_write_path_new_dir_with_create() {
        let tmp = setup_test_tree();
        let roots = vec![tmp.path().canonicalize().unwrap()];
        let result = validate_write_path(
            tmp.path().join("newdir/file.txt").to_str().unwrap(),
            &roots,
            &[],
            true,
        );
        assert!(result.is_ok());
        assert!(tmp.path().join("newdir").exists());
    }

    #[test]
    fn test_validate_write_path_no_create_dirs() {
        let tmp = setup_test_tree();
        let roots = vec![tmp.path().canonicalize().unwrap()];
        let result = validate_write_path(
            tmp.path()
                .join("nonexistent_dir/file.txt")
                .to_str()
                .unwrap(),
            &roots,
            &[],
            false,
        );
        assert!(result.is_err());
    }
}
