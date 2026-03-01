use rust_backend::infrastructure::repositories::utils::escape_like_pattern;

#[test]
fn utils_escape_like_pattern_escapes_percent() {
    let input = "100%";
    let escaped = escape_like_pattern(input);
    assert_eq!(escaped, "100\\%");
}

#[test]
fn utils_escape_like_pattern_escapes_underscore() {
    let input = "test_value";
    let escaped = escape_like_pattern(input);
    assert_eq!(escaped, "test\\_value");
}

#[test]
fn utils_escape_like_pattern_escapes_backslash() {
    let input = "path\\to\\file";
    let escaped = escape_like_pattern(input);
    assert_eq!(escaped, "path\\\\to\\\\file");
}

#[test]
fn utils_escape_like_pattern_escapes_multiple_special_chars() {
    let input = "100%_test\\value%";
    let escaped = escape_like_pattern(input);
    assert_eq!(escaped, "100\\%\\_test\\\\value\\%");
}

#[test]
fn utils_escape_like_pattern_preserves_normal_text() {
    let input = "normal text 123";
    let escaped = escape_like_pattern(input);
    assert_eq!(escaped, "normal text 123");
}

#[test]
fn utils_escape_like_pattern_empty_string() {
    let input = "";
    let escaped = escape_like_pattern(input);
    assert_eq!(escaped, "");
}

#[test]
fn utils_escape_like_pattern_only_special_chars() {
    let input = "%_\\";
    let escaped = escape_like_pattern(input);
    assert_eq!(escaped, "\\%\\_\\\\");
}

#[test]
fn utils_escape_like_pattern_special_chars_at_start() {
    let input = "%start";
    let escaped = escape_like_pattern(input);
    assert_eq!(escaped, "\\%start");
}

#[test]
fn utils_escape_like_pattern_special_chars_at_end() {
    let input = "end%";
    let escaped = escape_like_pattern(input);
    assert_eq!(escaped, "end\\%");
}

#[test]
fn utils_escape_like_pattern_consecutive_special_chars() {
    let input = "%%__\\\\";
    let escaped = escape_like_pattern(input);
    assert_eq!(escaped, "\\%\\%\\_\\_\\\\\\\\");
}
