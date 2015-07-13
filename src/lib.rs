#[macro_use]
extern crate nickel;
extern crate openssl;
extern crate rand;
extern crate rustc_serialize;
extern crate byteorder;
extern crate time;
extern crate cookie;
extern crate plugin;
extern crate typemap;

use std::fmt::Debug;
use rustc_serialize::{Encodable, Decodable};
use std::any::Any;
use nickel::{Response, Middleware, MiddlewareResult, cookies, NickelError, Session, SessionStore};
use nickel::status::StatusCode::Forbidden;

pub type ValidateUserFunc<T> = Box<Fn(&T) -> bool + Send + Sync>;

pub struct Authorizer<T, D> {
    authorize: ValidateUserFunc<T>,
    access_granted: Box<Middleware<D>+ Sized + Send + Sync>,
}

impl<T, D> Authorizer<T, D> {
    pub fn new(authorize: ValidateUserFunc<T>,
               access_granted: Box<Middleware<D> + Sized + Send + Sync>)
               -> Authorizer<T, D> {
        Authorizer { authorize: authorize, access_granted: access_granted }
    }
}

impl< T, D: 'static> Middleware<D> for Authorizer<T, D>
    where
    D: AsRef<cookies::SecretKey> + SessionStore<Store=T>,
    T: 'static + Any + Encodable + Decodable + Default + Debug
{
    fn invoke<'a, 'b>(&'a self, mut res: Response<'a, 'b, D>) -> MiddlewareResult<'a, 'b, D> {
        let mut access_granted: bool;
        /*
         * introduce a new scope so that req is not mutably borrowed twice
         * in the same scope.
         */
        {
            let session = res.session();
            access_granted = (*self.authorize)(&session);
        }
        if access_granted {
                self.access_granted.invoke(res)
        } else {
            Err(NickelError::new(res, "Access denied.", Forbidden))
        }
    }
}
