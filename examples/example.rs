#[macro_use] extern crate nickel;
extern crate rustc_serialize;
extern crate nickel_auth;
extern crate time;

use std::io::Write;
use nickel::{Nickel, NickelError, Halt, Continue, Request, Action, HttpRouter, JsonBody, Middleware, Router};
use nickel_auth::{CreateSession, ReadSession, SessionConfig, AuthenticatedSession, Authorizer};
use nickel::cookies::Cookies;
use time::{Duration};
use nickel::status::StatusCode;

#[derive(RustcDecodable, RustcEncodable)]
struct User {
    name: String,
    password:  String,
}

fn main() {
    let mut server = Nickel::with_data(SessionConfig::new_with_random_key(Box::new(|_| true), Duration::seconds(10)));

    /* Anyone should be able to reach thist route. */
    server.get("/", middleware!{|req, res| {
                        format!("You are logged in as: {:?}\n", req.authenticated_session())
    }}
        );
    server.post("/login", middleware!{|req, mut res| {
        if let Ok(u) = req.json_as::<User>() {
            if u.name == "foo" && u.password == "bar" {
                res.set_session_cookie(u.name);
                return res.send((StatusCode::Ok, "Successfully logged in."))
            }
        }
        (StatusCode::BadRequest, "Access denied.")
    }});

    server.get("/secret",
               Authorizer::new(
                   Box::new(|user| user=="foo"),
                   Box::new(middleware!{"Some hidden information!\n"})
                )
            ); 
    
    fn custom_403<'a>(err: &mut NickelError<SessionConfig>, _req: &mut Request<SessionConfig>) -> Action {
        if let Some(ref mut res) = err.stream {
            if res.status() == StatusCode::Forbidden {
                let _ = res.write_all(b"Access denied!\n");
                return Halt(())
            }
        }

        Continue(())
    }

    // issue #20178
    let custom_handler: fn(&mut NickelError<SessionConfig>, &mut Request<SessionConfig>) -> Action = custom_403;

    server.handle_error(custom_handler);

    server.listen("127.0.0.1:6767");
}
