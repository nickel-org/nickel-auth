#[macro_use] extern crate nickel;
extern crate openssl;
extern crate rand;
extern crate rustc_serialize;
extern crate byteorder;
extern crate time;

use nickel::{Request, Response, Middleware, MiddlewareResult, SetCookie, GetCookies};
use openssl::crypto::symm::{Type, encrypt, decrypt};
use rand::{OsRng, Rng};
use rustc_serialize::base64::{ToBase64, FromBase64, STANDARD};
use byteorder::{ByteOrder, BigEndian};
use time::{now, Timespec, Duration};
use std::str::from_utf8;

pub type LoginFunc = Box<Fn(&mut Request) -> Option<String> + Send + Sync>;
pub type ValidateUserFunc = Box<Fn(&str) -> bool + Send + Sync>;

/* use 1 byte secret key (128 bit) */
const KEY_SIZE: usize = 16;

pub struct Authenticator {
    /* Verifies a login attempt */
    login: LoginFunc,
    validate_username: ValidateUserFunc,
    session_length: Duration,
    secret_key: Box<[u8]>,
    access_denied: Box<Middleware + Send + Sync + 'static>,
    access_granted: Box<Middleware + Send + Sync + 'static>
}

impl Authenticator {
    pub fn new(l: LoginFunc,
               v: ValidateUserFunc,
               t: Duration,
               access_denied: Box<Middleware + Sized + Send + Sync>,
               access_granted: Box<Middleware + Sized + Send + Sync>
            ) -> Authenticator {
        let mut rand_gen = OsRng::new()
                                .ok()
                                .expect("Could not get OS random generator.");
        let mut key = [0; KEY_SIZE];
        rand_gen.fill_bytes(&mut key);

        Authenticator {
            login: l,
            validate_username: v,
            session_length: t,
            secret_key: Box::new(key),
            access_denied: access_denied,
            access_granted: access_granted,
        }
    }

    fn create_cookie_str<'a>(&self, username: &'a str) -> String {
        let mut rand_gen = OsRng::new()
                                .ok()
                                .expect("Could not get OS random generator.");
        /* initialisation vector used by the crypto algorithm, must be random */
        let mut iv = [0; KEY_SIZE];
        rand_gen.fill_bytes(&mut iv);

        /* make 8 byte buffer */
        let mut timestamp = [0u8; 8];
        /* write bytes of the current unix timestamp to buffer */
        BigEndian::write_i64(&mut timestamp, now().to_timespec().sec);
        /* concatenate timestamp and username */
        let time_and_username: Vec<u8> = timestamp.iter()
                                                  .chain(username.as_bytes().iter())
                                                  .map(|&x| x)
                                                  .collect();
        /* encrypt time and username together */ 
        let mut encrypted = encrypt(Type::AES_128_CBC,
                                &*self.secret_key,
                                &mut iv,
                                &*time_and_username
                            ).to_base64(STANDARD);
        /* append a separater and the initialisation vector */
        encrypted.push('|');
        encrypted = encrypted.chars().chain(iv.to_base64(STANDARD).chars()).collect();
        encrypted
    }

    fn decrypt_cookie_str<'a>(&self, cookie_str: &'a str) -> (String, Timespec) {
        let encrypted_data: Vec<&str> = cookie_str.split('|').collect();
        if encrypted_data.len() != 2 {
            panic!("Couldn't find both message and iv in cookie!");
        }
        let encrypted_time_and_username = encrypted_data[0].from_base64()
                                                    .ok()
                                                    .expect("Couldn't parse message from Base64.");
        let iv = encrypted_data[1].from_base64()
                                            .ok()
                                            .expect("Couldn't parse iv from Base64.");
        let decrypted_data = decrypt(Type::AES_128_CBC,
                                    &*self.secret_key,
                                    iv,
                                    &*encrypted_time_and_username);
        /* first 8 bytes belong to the timestamp */
        let (timestamp, username) = decrypted_data.split_at(8);
        let timestamp = BigEndian::read_i64(timestamp);
        let username = from_utf8(username).ok().expect("Could not read username as UTF8.");
        println!("{}", username);
        (username.to_owned(), Timespec::new(timestamp, 0))
    }
    
    fn validate_cookie<'a>(&self, req: &Request) -> bool {
        let cookies = req.get_cookies();
        cookies.iter().find(|&c| c.name == "token".to_owned()).map_or(false,
            |cookie| {
                    let (username, session_created) = self.decrypt_cookie_str(&*cookie.value);
                    (self.validate_username)(&*username)
                        && session_created +  self.session_length > now().to_timespec()
                    }
        )
    }

    fn set_cookie<'a>(&self, res: &mut Response, username: &'a str) {
            res.set_cookie_string_pair("token".to_owned(), self.create_cookie_str(username));
    }
}

impl Middleware for Authenticator {
    fn invoke<'a, 'b>(&'a self, req: &mut Request<'b, 'a, 'b>, mut res: Response<'a>) -> MiddlewareResult<'a> {
        if let Some(username) = (*self.login)(req) {
            self.set_cookie(&mut res, &*username);
            self.access_granted.invoke(req, res)
        } else if self.validate_cookie(req) {
            self.access_granted.invoke(req, res)
        } else {
            self.access_denied.invoke(req, res)
        }
    }
}

#[test]
fn encrypt_and_decrypt() {
    let a = Authenticator::new(
                                    Box::new(|_| false),
                                    Box::new(|_| false),
                                    Duration::seconds(1),
                                    Box::new(middleware!("denied")),
                                    Box::new(middleware!("granted"))
                                    );
    let username = "Hello world!";
    let cookie = a.create_cookie_str(username);
    let (decrypted_cookie, _) = a.decrypt_cookie_str(&*cookie);
    assert!(username.to_owned() == decrypted_cookie);
}
