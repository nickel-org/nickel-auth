#[macro_use] extern crate nickel;
extern crate rustc_serialize;
extern crate nickel_auth;
extern crate time;

use nickel::{Nickel, HttpRouter, JsonBody, Middleware, Router};
use nickel_auth::Authenticator;
use time::{Duration};

#[derive(RustcDecodable, RustcEncodable)]
struct User {
    name: String,
    password:  String,
}

fn get_authenticator(access_denied: Box<Middleware + Sized + Send + Sync>,
               access_granted: Box<Middleware + Sized + Send + Sync>) -> Authenticator
{
    Authenticator::new(
        Box::new(|req| {
                req.json_as::<User>().ok().map_or(None,
                    |user|
                        if user.name == "foo".to_owned()
                                    && user.password == "bar".to_owned() {
                                        Some(user.name)
                                    } else {
                                        None
                                    },
                )
            }
        ),
        Box::new(|username| if username == "foo" {true} else { false}),
        Duration::seconds(30),
        access_denied,
        access_granted
    )
}

fn main() {
    let mut server = Nickel::new();

    /* Anyone should be able to reach thist route. */
    server.get("/", middleware!{"Public route\n"});

    /* Only signed in people should be able to reach routes in this router.
     * Begin by creating a router like normal. */
    let mut secret_router = Router::new();
    /* Add a routes that are protected. */
    secret_router.post("/login", middleware!{"Successfully logged in.\n"});
    secret_router.get("/very/secret", middleware!{"Some hidden information!\n"});

    /* Wrap the whole router in an Authenticator */
    let protected_route = get_authenticator(Box::new(middleware!{"Access denied!\n"}),
                                   Box::new(secret_router)
                        );
    
    server.utilize(protected_route);

    server.listen("127.0.0.1:6767");
}
