use std::fs;

#[test]
fn minimal_frontend_exists_and_covers_api_groups() {
    let html = fs::read_to_string("frontend/index.html")
        .expect("expected frontend/index.html to exist for backend smoke testing");

    for needle in [
        "Rust Backend Smoke UI",
        "/health",
        "/ready",
        "/api/auth/register",
        "/api/auth/login",
        "/api/users/",
        "/api/categories",
        "/api/equipment",
        "/api/conversations",
        "/ws",
        "id=\"request-presets\"",
        "id=\"send-request\"",
        "id=\"ws-connect\"",
    ] {
        assert!(
            html.contains(needle),
            "frontend/index.html is missing required marker: {needle}"
        );
    }
}
