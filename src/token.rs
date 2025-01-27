pub use biscuit::jws::Compact as Jws;
use biscuit::CompactJson;

use crate::{bearer::IdBearer, Bearer, Claims, IdToken, StandardClaims};

/// An OpenID Connect token. This is the only token allowed by spec.
/// Has an `access_token` for bearer, and the `id_token` for authentication.
/// Wraps an oauth bearer token.
#[allow(missing_debug_implementations)]
pub struct Token<C: CompactJson + Claims = StandardClaims, B = Bearer> {
    /// Bearer Token.
    ///
    /// `access_token`
    pub bearer: B,
    /// ID Token
    ///
    /// `id_token`
    pub id_token: Option<IdToken<C>>,
}

impl<C: CompactJson + Claims, B: IdBearer> From<B> for Token<C, B> {
    fn from(bearer: B) -> Self {
        let id_token = bearer
            .id_token()
            .map(|token| Jws::new_encoded(token));
        Self { bearer, id_token }
    }
}
