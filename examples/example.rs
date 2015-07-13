#[macro_use]
extern crate nickel;
extern crate rustc_serialize;
extern crate nickel_auth;
extern crate time;

use std::io::Write;
use nickel::*;
use nickel::status::StatusCode;
use nickel_auth::Authorizer;
use time::Duration;

#[derive(RustcDecodable, RustcEncodable, Debug, Default)]
struct User {
    name: String,
    password: String,
}

fn authorize(user: &Option<String>) -> bool {
    if let Some(u) = user.as_ref() {
        if u == "foo" {
            return true;
        }
    }
    false
}

struct ServerData;

static SECRET_KEY: &'static cookies::SecretKey = &cookies::SecretKey([0; 32]);

impl AsRef<cookies::SecretKey> for ServerData {
    fn as_ref(&self) -> &cookies::SecretKey {
        SECRET_KEY
    }
}

impl SessionStore for ServerData {
    type Store = Option<String>;

    fn timeout() -> Duration {
        Duration::seconds(5)
    }
}

fn main() {
    let mut server = Nickel::with_data(ServerData);

    /* Anyone should be able to reach thist route. */
    server.get("/", middleware!{|mut res| {
         format!("You are logged in as: {:?}\n", res.session())
    }}
        );
    server.post("/login", middleware!{|mut res| {
        if let Ok(u) = res.request.json_as::<User>() {
            if u.name == "foo" && u.password == "bar" {
                *res.session_mut() = Some(u.name);
                return res.send("Successfully logged in.")
            }
        }
        (StatusCode::BadRequest, "Access denied.")
    }});

    server.get("/secret",
               Authorizer::new(
                   Box::new(authorize),
                   Box::new(middleware!{"Some hidden information!\n"})
                )
            );

    fn custom_403<'a>(err: &mut NickelError<ServerData>) -> Action {
        if let Some(ref mut res) = err.response_mut() {
            if res.status() == StatusCode::Forbidden {
                let _ = res.write_all(b"Access denied!\n");
                return Halt(())
            }
        }

        Continue(())
    }

    // issue #20178
    let custom_handler: fn(&mut NickelError<ServerData>) -> Action = custom_403;

    server.handle_error(custom_handler);

    server.listen("127.0.0.1:6767");
}
