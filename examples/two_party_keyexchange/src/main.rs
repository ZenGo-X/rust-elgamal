use actix_web::{web, App, HttpRequest, HttpServer, Responder};

mod common;


async fn key_exchange(req: HttpRequest) -> impl Responder {
    format!("Hello, the 2-Party, or better, Key Exchange has not been implemted yet. Ya''ll call back soon!")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .route("/", web::get().to(key_exchange))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}