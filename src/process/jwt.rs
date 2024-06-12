use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Ok, Result};
use jsonwebtoken::{DecodingKey, EncodingKey, TokenData, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub aud: String,
    pub exp: u64,
}

impl std::fmt::Display for Claims {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub fn process_jwt_sign(sub: String, aud: String, exp: Duration) -> Result<String> {
    let claims = Claims {
        sub,
        aud,
        exp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + exp.as_secs(),
    };
    let token = jsonwebtoken::encode(
        &Default::default(),
        &claims,
        &EncodingKey::from_secret("secret".as_ref()),
    )?;
    Ok(token)
}

pub fn process_jwt_verify(token: &str) -> Result<Claims> {
    let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.validate_aud = false;
    let token_data : TokenData<Claims> = jsonwebtoken::decode(token, &DecodingKey::from_secret("secret".as_ref()), &validation)?;
    Ok(token_data.claims)
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::{process_jwt_sign, process_jwt_verify};

    #[test]
    fn test_sign_and_verify() {
        let d = std::time::Duration::from_secs(120);
        let token = process_jwt_sign("sub".to_owned(), "aud".to_owned(), d);
        assert!(!token.is_err());
        let t = token.unwrap();
        let claims = process_jwt_verify(t.as_str());
        assert!(!claims.is_err());
        let c = claims.unwrap();
        assert_eq!(c.sub, "sub");
        assert_eq!(c.aud, "aud");
        assert!(c.exp > SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs());
    }
}