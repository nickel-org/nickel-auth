use plugin::{Plugin, Pluggable};
use cookie::{CookieJar, Cookie};
use nickel::{Request, Response, Middleware, MiddlewareResult, cookies, Continue, NickelError};
use openssl::crypto::symm::{Type, encrypt, decrypt};
use rand::{OsRng, Rng};
use rustc_serialize::base64::{ToBase64, FromBase64, STANDARD};
use byteorder::{ByteOrder, BigEndian};
use time::{now, Timespec, Duration};
use std::str::from_utf8;
use nickel::cookies::Cookies;
use plugin::Extensible;
use typemap::Key;
use nickel::status::StatusCode::{Forbidden};
use super::ReadSession;

pub type ValidateUserFunc = Box<Fn(&str) -> bool + Send + Sync>;

struct SessionPlugin;
impl Key for SessionPlugin { type Value = String; }

impl<'a, 'b, 'k, D: AsRef<cookies::SecretKey> + AsRef<Duration> + AsRef<ValidateUserFunc>> Plugin<Request<'a, 'b, 'k, D>> for SessionPlugin {
    type Error = ();

    fn eval(req: &mut Request<D>) -> Result<String, ()> {
        if let Some(username) = req.get_session() {
            let validate_func: &ValidateUserFunc = req.data().as_ref();
            if (*validate_func)(&*username) {
                return Ok(username);
            }
        }
        Err(())
    }
}

pub trait AuthenticatedSession {
    fn authenticated_session(&mut self) -> Option<&String>;
}

impl<'a, 'b, 'k, D: AsRef<cookies::SecretKey> + AsRef<Duration> + AsRef<ValidateUserFunc>> AuthenticatedSession for Request<'a, 'b, 'k, D> {
    fn authenticated_session(&mut self) -> Option<&String> {
        self.get_ref::<SessionPlugin>().ok()
    }
}
