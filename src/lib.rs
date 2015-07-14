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
use nickel::{Response, Middleware, MiddlewareResult, cookies, Session, SessionStore};
use nickel::status::StatusCode::Forbidden;

pub trait AuthorizeSession {
    type Permissions = bool;

    fn permission(&self) -> Self::Permissions;
}

pub struct Authorize<T, D, P>
    where
    P: 'static + Send + Sync + Eq,
    D: 'static + AsRef<cookies::SecretKey> + SessionStore<Store=T>,
    T: 'static + Any + Encodable + Decodable + Default + Debug + AuthorizeSession<Permissions=P>
{ 
    access_granted: Box<Middleware<D>+ Sized + Send + Sync>,
    permissions: P
}

impl<T, D, P> Authorize<T, D, P>
    where
    P: 'static + Send + Sync + Eq,
    D: 'static + AsRef<cookies::SecretKey> + SessionStore<Store=T>,
    T: 'static + Any + Encodable + Decodable + Default + Debug + AuthorizeSession<Permissions=P>
{
    pub fn only(permissions: P,
               access_granted: Box<Middleware<D> + Sized + Send + Sync>)
               -> Authorize<T, D, P> {
        Authorize { access_granted: access_granted, permissions: permissions }
    }
}

impl< T, D, P> Middleware<D> for Authorize<T, D, P>
    where
    P: 'static + Send + Sync + Eq,
    D: 'static + AsRef<cookies::SecretKey> + SessionStore<Store=T>,
    T: 'static + Any + Encodable + Decodable + Default + Debug + AuthorizeSession<Permissions=P>
{
    fn invoke<'a, 'b>(&'a self, mut res: Response<'a, 'b, D>) -> MiddlewareResult<'a, 'b, D> {
        let access_granted = {
            res.session().permission() == self.permissions
        };

        if access_granted {
                self.access_granted.invoke(res)
        } else {
            res.error(Forbidden, "Access denied.")
        }
    }
}
