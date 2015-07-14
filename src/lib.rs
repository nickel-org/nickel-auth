#[macro_use] extern crate nickel;

use std::any::Any;
use nickel::{Response, Middleware, MiddlewareResult, Session, SessionStore, Cookies};
use nickel::status::StatusCode::Forbidden;

pub trait AuthorizeSession {
    type Permissions;

    fn permissions(&self) -> Self::Permissions;
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
      P: Eq +'static + Send + Sync {
    fn invoke<'a, 'b>(&'a self, mut res: Response<'a, 'b, D>) -> MiddlewareResult<'a, 'b, D> {
        let allowed = {
            let current_permission = &res.session().permissions();
            match self.permissions {
                Permit::Only(ref p) => p == current_permission,
                Permit::Any(ref ps) => ps.iter().any(|p| p == current_permission),
                Permit::All(ref ps) => ps.iter().all(|p| p == current_permission),
            }
        };

        if allowed {
            self.access_granted.invoke(res)
        } else {
            res.error(Forbidden, "Access denied.")
        }
    }
}
