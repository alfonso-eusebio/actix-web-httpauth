use actix_web::dev::ServiceRequest;
use actix_web::{middleware, web, App, Error, HttpResponse, HttpServer};

use actix_web_httpauth::extractors::basic::BasicAuth;
use actix_web_httpauth::middleware::HttpAuthentication;
use futures::future::{self, Ready};

fn validator(
    req: ServiceRequest,
    _credentials: BasicAuth,
) -> Ready<Result<ServiceRequest, Error>> {
    future::ok(req)
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        let auth = HttpAuthentication::basic(validator);
        App::new()
            .wrap(middleware::Logger::default())
            .wrap(auth)
            .service(
                web::resource("/")
                    .to(|| async { HttpResponse::Ok().body("Test\r\n") }),
            )
    })
    .bind("127.0.0.1:8080")?
    .workers(1)
    .run()
    .await
}
