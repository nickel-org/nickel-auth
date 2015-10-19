#[macro_use] extern crate nickel;
extern crate nickel_session;
extern crate nickel_cookies;

use std::any::Any;
use nickel_session::session::{Session, Store, CookieSession};
use nickel::{Response, Request, Middleware, MiddlewareResult};
use nickel::status::StatusCode::Forbidden;

pub trait AuthorizeSession {
    type Permissions;

    fn has_permission(&self, permission: &Self::Permissions) -> bool;
}

pub struct Authorize<P, M> {
    access_granted: M,
    permissions: Permit<P>,
}

enum Permit<P> {
    Only(P),
    Any(Vec<P>),
    All(Vec<P>)
}

impl<P, M> Authorize<P, M> {
    pub fn only(permission: P, access_granted: M) -> Authorize<P, M> {
        Authorize {
            access_granted: access_granted,
            permissions: Permit::Only(permission),
        }
    }

    pub fn any(permissions: Vec<P>, access_granted: M) -> Authorize<P, M> {
        Authorize {
            access_granted: access_granted,
            permissions: Permit::Any(permissions),
        }
    }

    pub fn all(permissions: Vec<P>, access_granted: M) -> Authorize<P, M> {
        Authorize {
            access_granted: access_granted,
            permissions: Permit::All(permissions),
        }
    }
}

impl<P, M, D> Middleware<D> for Authorize<P, M>
where M: Middleware<D> + Send + Sync + 'static,
      D: Store,
      D::Session: AuthorizeSession<Permissions=P> + Any,
      P: PartialEq +'static + Send + Sync {
    fn invoke<'a, 'b>(&'a self, req: &mut Request<'a, 'b, D>, mut res: Response<'a, D>)
        -> MiddlewareResult<'a, D> {
        let allowed = {
            match self.permissions {
                Permit::Only(ref p) => CookieSession::get_mut(req, &mut res).has_permission(p),
                Permit::Any(ref ps) => ps.iter().any(|p| CookieSession::get_mut(req, &mut res).has_permission(p)),
                Permit::All(ref ps) => ps.iter().all(|p| CookieSession::get_mut(req, &mut res).has_permission(p)),
            }
        };

        if allowed {
            self.access_granted.invoke(req, res)
        } else {
            res.error(Forbidden, "Access denied.")
        }
    }
}
