use actix_web::{web, HttpResponse};

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/ws", web::get().to(ws_upgrade));
}

async fn ws_upgrade() -> HttpResponse {
    HttpResponse::NotImplemented().finish()
}
