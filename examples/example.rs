#[macro_use]
extern crate nickel;
extern crate nickel_session;
extern crate nickel_cookies;
extern crate rustc_serialize;
extern crate nickel_auth;
extern crate time;

use std::io::Write;
use nickel::*;
use nickel::status::StatusCode;
use nickel_cookies::{KeyProvider, SecretKey};
use nickel_session::{Store, CookieSession, Session};
use nickel_auth::{Authorize, AuthorizeSession};
use time::Duration;

#[derive(RustcDecodable, RustcEncodable, Debug, Default)]
struct User {
    name: String,
    password: String,
}

#[derive(RustcDecodable, RustcEncodable, Debug, Default)]
struct SessionType(Option<String>);

#[derive(Eq, PartialEq)]
enum UserClass {User, Admin}

impl AuthorizeSession for SessionType {
    type Permissions = UserClass;

    fn has_permission(&self, permission: &UserClass) -> bool {
        match *permission {
            UserClass::User => {
                match *self {
                    SessionType(Some(ref u)) => &*u == "foo" || &*u == "admin",
                    SessionType(None) => false
                }
            },
            UserClass::Admin => {
                match *self {
                    SessionType(Some(ref u)) => &*u == "admin",
                    SessionType(None) => false
                }
            }
        }
    }
}

struct ServerData;

static SECRET_KEY: &'static SecretKey = &SecretKey([0; 32]);

impl KeyProvider for ServerData {
    fn key(&self) -> SecretKey {
        SECRET_KEY.clone()
    }
}

impl Store for ServerData {
    type Session = SessionType;

    fn timeout() -> Duration {
        Duration::seconds(5)
    }
}

fn main() {
    let mut server = Nickel::with_data(ServerData);

    /* Anyone should be able to reach thist route. */
    server.get("/", middleware!{|req, mut res| <ServerData>
         format!("You are logged in as: {:?}\n", CookieSession::get_mut(req, &mut res))
    }
        );
    server.post("/login", middleware!{ |req, mut res| <ServerData> 
        if let Ok(u) = req.json_as::<User>() {
            if u.name == "foo" && u.password == "bar" {
                *CookieSession::get_mut(req, &mut res) = SessionType(Some(u.name));
                return res.send("Successfully logged in.")
            }
        }
        (StatusCode::BadRequest, "Access denied.")
    });

    server.get("/secret", Authorize::any(vec![UserClass::User, UserClass::Admin],
                                         middleware! { "Some hidden information!\n" })
    );

    fn custom_403<'a>(err: &mut NickelError<ServerData>, _: &mut Request<ServerData>) -> Action {
        if let Some(ref mut res) = err.stream {
            if res.status() == StatusCode::Forbidden {
                let _ = res.write_all(b"Access denied!\n");
                return Halt(())
            }
        }

        Continue(())
    }

    // issue #20178
    let custom_handler: fn(&mut NickelError<ServerData>, &mut Request<ServerData>) -> Action = custom_403;

    server.handle_error(custom_handler);

    server.listen("127.0.0.1:6767");
}
