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
use super::{ValidateUserFunc, AuthenticatedSession};

pub struct Authorizer<D: AsRef<Duration> + AsRef<cookies::SecretKey> + AsRef<ValidateUserFunc>> {
    authenticate: ValidateUserFunc,
    access_granted: Box<Middleware<D> + Sized + Send + Sync>
}

impl<D: AsRef<Duration> + AsRef<cookies::SecretKey> + AsRef<ValidateUserFunc>> Authorizer<D> {
    pub fn new(authenticate: ValidateUserFunc, access_granted: Box<Middleware<D> + Sized + Send + Sync>) -> Authorizer<D> {
        Authorizer{ access_granted: access_granted, authenticate: authenticate }
    }
}

impl<D: 'static + AsRef<Duration> + AsRef<cookies::SecretKey> + AsRef<ValidateUserFunc>> Middleware<D> for Authorizer<D> {
    fn invoke<'a, 'b>(&'a self,
          req: &mut Request<'b, 'a, 'b, D>,
          mut res: Response<'a, D>)
            -> MiddlewareResult<'a, D> {
            /* 
             * introduce a new scope so that req is not mutably borrowed twice
             * in the same scope.
             */
            {
                let session = (*req).authenticated_session();
                let denied = session.map_or(true, |s| !(*self.authenticate)(s));
                if denied {
                    return Err(NickelError::new(res, "Access denied.", Forbidden))
                }
            }
            self.access_granted.invoke(req, res)
        }
}
