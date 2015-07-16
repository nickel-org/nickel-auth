#[macro_use] extern crate nickel;

use std::any::Any;
use nickel::{Response, Middleware, MiddlewareResult, Session, SessionStore, Cookies};
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
    pub fn only<D, S>(permission: P, access_granted: M) -> Authorize<P, M>
    where for<'a, 'k> Response<'a, 'k, D>: Cookies + Session<S>,
          M: Middleware<D> + Send + Sync + 'static,
          S: AuthorizeSession<Permissions=P> {
        Authorize {
            access_granted: access_granted,
            permissions: Permit::Only(permission),
        }
    }

    pub fn any<D, S>(permissions: Vec<P>, access_granted: M) -> Authorize<P, M>
    where for<'a, 'k> Response<'a, 'k, D>: Cookies + Session<S>,
          M: Middleware<D> + Send + Sync + 'static,
          S: AuthorizeSession<Permissions=P> {
        Authorize {
            access_granted: access_granted,
            permissions: Permit::Any(permissions),
        }
    }

    pub fn all<D, S>(permissions: Vec<P>, access_granted: M) -> Authorize<P, M>
    where for<'a, 'k> Response<'a, 'k, D>: Cookies + Session<S>,
          M: Middleware<D> + Send + Sync + 'static,
          S: AuthorizeSession<Permissions=P> {
        Authorize {
            access_granted: access_granted,
            permissions: Permit::All(permissions),
        }
    }
}

impl<P, M, D> Middleware<D> for Authorize<P, M>
where for<'a, 'k> Response<'a, 'k, D>: Cookies,
      M: Middleware<D> + Send + Sync + 'static,
      D: SessionStore,
      D::Store: AuthorizeSession<Permissions=P> + Any,
      P: PartialEq +'static + Send + Sync {
    fn invoke<'a, 'b>(&'a self, mut res: Response<'a, 'b, D>) -> MiddlewareResult<'a, 'b, D> {
        let allowed = {
            match self.permissions {
                Permit::Only(ref p) => res.session().has_permission(p),
                Permit::Any(ref ps) => ps.iter().any(|p| res.session().has_permission(p)),
                Permit::All(ref ps) => ps.iter().all(|p| res.session().has_permission(p)),
            }
        };

        if allowed {
            self.access_granted.invoke(res)
        } else {
            res.error(Forbidden, "Access denied.")
        }
    }
}
