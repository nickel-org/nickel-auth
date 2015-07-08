#[macro_use] extern crate nickel;
extern crate openssl;
extern crate rand;
extern crate rustc_serialize;
extern crate byteorder;
extern crate time;
extern crate cookie;
extern crate plugin;
extern crate typemap;

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

mod session;
mod authenticated_session;
mod authorizer; 

pub use authenticated_session::{AuthenticatedSession, ValidateUserFunc};
pub use session::{ReadSession, CreateSession};
pub use authorizer::Authorizer;

pub struct SessionConfig {
    secret_key: cookies::SecretKey,
    session_length: Duration,
    authenticate: ValidateUserFunc
}

impl AsRef<cookies::SecretKey> for SessionConfig {
    fn as_ref(&self) -> &cookies::SecretKey {
        &self.secret_key
    }
}

impl AsRef<Duration> for SessionConfig {
    fn as_ref(&self) -> &Duration {
        &self.session_length
    }
}

impl AsRef<ValidateUserFunc> for SessionConfig {
    fn as_ref(&self) -> &ValidateUserFunc {
        &self.authenticate
    }
}


impl SessionConfig {
    pub fn new(secret_key: cookies::SecretKey, authenticate: ValidateUserFunc, session_length: Duration) -> SessionConfig
    {
        SessionConfig { secret_key: secret_key, authenticate: authenticate, session_length: session_length }
    }

    pub fn new_with_random_key(authenticate: ValidateUserFunc, session_length: Duration) -> SessionConfig
    {
        let mut rand_gen = OsRng::new()
                                .ok()
                                .expect("Could not get OS random generator.");
        let mut key = [0u8; 32];
        rand_gen.fill_bytes(&mut key);
        SessionConfig { secret_key: cookies::SecretKey(key), authenticate: authenticate, session_length: session_length }
    }
}
