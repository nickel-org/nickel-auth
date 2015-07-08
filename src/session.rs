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

pub trait ReadSession {
    fn get_session(&mut self) -> Option<String>;
}

trait ParseSession {
    fn get_session_from_token_str(&self, token: &str) -> Option<String>;
}

impl<'a, 'b, 'k, D: AsRef<cookies::SecretKey> + AsRef<Duration>> ReadSession for Request<'a, 'b, 'k, D> {
    fn get_session(&mut self) -> Option<String> {
        self.cookies()
            .encrypted()
            .find("__token")
            .and_then(|c| 
            {
                self.get_session_from_token_str(&*c.value)
            }
        )
    }
}

impl<'a, 'b, 'k, D: AsRef<cookies::SecretKey> + AsRef<Duration>> ParseSession for Request<'a, 'b, 'k, D> {
    fn get_session_from_token_str(&self, token: &str) -> Option<String> {
        let timestamp_and_plaintext = token
                                        .from_base64()
                                        .ok()
                                        .expect(
                                            "Could not parse message as Base64.
                                        ");
        let (timestamp, plaintext) = timestamp_and_plaintext.split_at(8);
        let timestamp = BigEndian::read_i64(timestamp);
        let plaintext = from_utf8(plaintext)
                            .ok()
                            .expect("Could not read plaintext as UTF8.");
        let timestamp = Timespec::new(timestamp, 0);
        if timestamp + *self.data().as_ref() > now().to_timespec() {
            Some(plaintext.to_owned())
        } else {
            None
        }
    }
}

pub trait CreateSession {
    fn set_session_cookie(&mut self, plaintext: String);
    // Doesn't compile without self as a parameter. Compiler bug?
    fn create_session_token_str(&self, plaintext: &str) -> String {
        /* make 8 byte buffer */
        let mut timestamp = [0u8; 8];
        /* write bytes of the current unix timestamp to buffer */
        BigEndian::write_i64(&mut timestamp, now().to_timespec().sec);
        /* concatenate timestamp and username */
        timestamp.iter()
                  .chain(plaintext.as_bytes().iter())
                  .map(|&x| x)
                  .collect::<Vec<u8>>()
                  .to_base64(STANDARD)
    }
}


impl<'a, D: AsRef<cookies::SecretKey>> CreateSession for Response<'a, D> {
    fn set_session_cookie(&mut self, plaintext: String) {
        // Doesn't compile without self as a parameter. Compiler bug?
        let token = CreateSession::create_session_token_str(self, &*plaintext);
        let mut cookie = Cookie::new("__token".to_owned(), token);
        self.cookies_mut().encrypted().add(cookie);
    }
}
