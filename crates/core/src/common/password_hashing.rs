// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

use std::cmp::max;
use std::str;
use thiserror::Error;
use tokio::sync::OnceCell;
use tokio::task;
use tracing::warn;

use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use pbkdf2::Pbkdf2;
use pbkdf2::password_hash::rand_core::OsRng;
use pbkdf2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use scrypt::Scrypt;
use sha2::Digest;

use openstack_keystone_config::{Config, PasswordHashingAlgo};

// Create a thread-safe, async-friendly global cache for the dummy hash
static DUMMY_HASH_CACHE: OnceCell<String> = OnceCell::const_new();

/// Gets the cached dummy hash, or generates it if it's the very first time.
pub async fn get_or_init_dummy_hash(conf: &Config) -> Result<&String, PasswordHashError> {
    DUMMY_HASH_CACHE
        .get_or_try_init(|| async { generate_dummy_hash(conf).await })
        .await
}

/// Password hashing related errors.
#[derive(Error, Debug)]
pub enum PasswordHashError {
    /// Bcrypt error.
    #[error(transparent)]
    BCrypt {
        /// The source of the error.
        #[from]
        source: bcrypt::BcryptError,
    },

    /// Crypto password-hash crate error (handles scrypt/pbkdf2 formatting).
    #[error("Password hashing framework error: {0}")]
    CryptoHash(String),

    /// Async task join error.
    #[error(transparent)]
    Join {
        /// The source of the error.
        #[from]
        source: tokio::task::JoinError,
    },

    /// Non UTF8 data.
    #[error(transparent)]
    Utf8 {
        /// The source of the error.
        #[from]
        source: str::Utf8Error,
    },
}

/// Verify the password length and truncate if necessary.
///
/// # Parameters
/// - `password`: The password bytes.
/// - `max_length`: The maximum allowed length.
///
/// # Returns
/// - `&[u8]` - The password bytes, truncated if they exceeded `max_length`.
fn verify_length_and_trunc_password(password: &[u8], max_length: usize) -> &[u8] {
    if password.len() > max_length {
        let mut end = max_length;
        // Step backward while the byte is a UTF-8 continuation byte.
        // A continuation byte falls in the range 128..192.
        while end > 0 && password[end] >= 128 && password[end] < 192 {
            end -= 1;
        }
        warn!("Truncating password to the specified value");
        return &password[..end];
    }
    password
}

/// Generate a dummy password hash matching the configured algorithm.
///
/// Used for timing attack prevention: when a user is not found, a dummy hash
/// is generated and verified against the provided password, so the response
/// time is approximately the same as when the user exists but the password is
/// wrong.
///
/// # Parameters
/// - `conf`: The service configuration.
///
/// # Returns
/// - `Ok(String)` - A dummy hash string matching the configured algorithm.
/// - `Err(PasswordHashError)` - If hash generation failed.
pub async fn generate_dummy_hash(conf: &Config) -> Result<String, PasswordHashError> {
    // Generate a random 16`-character printable ASCII string.
    // This guarantees valid UTF-8, which is required if the fallback algorithm is `None`.
    let dummy_password: String = rand::random::<[u8; 16]>()
        .iter()
        .map(|b| (b % 95 + 32) as char)
        .collect();

    hash_password(conf, dummy_password).await
}

/// Calculate password hash with the configuration defaults.
///
/// # Parameters
/// - `conf`: The service configuration.
/// - `password`: The password to hash.
///
/// # Returns
/// - `Ok(String)` - The hashed password.
/// - `Err(PasswordHashError)` - If hashing failed.
pub async fn hash_password<S: AsRef<[u8]>>(
    conf: &Config,
    password: S,
) -> Result<String, PasswordHashError> {
    match conf.identity.password_hashing_algorithm {
        PasswordHashingAlgo::Bcrypt => {
            let password_bytes = verify_length_and_trunc_password(
                password.as_ref(),
                max(conf.identity.max_password_length, 72),
            )
            .to_owned();
            let rounds = conf.identity.password_hash_rounds.unwrap_or(12);
            let hash =
                task::spawn_blocking(move || bcrypt::hash(password_bytes, rounds as u32)).await??;
            Ok(hash)
        }

        PasswordHashingAlgo::BcryptSha256 => {
            let password_bytes = verify_length_and_trunc_password(
                password.as_ref(),
                max(conf.identity.max_password_length, 72),
            )
            .to_owned();
            let rounds = conf.identity.password_hash_rounds.unwrap_or(12);
            let hash = task::spawn_blocking(move || {
                let digest = sha2::Sha256::digest(password_bytes);
                let hex_digest = digest
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>();
                bcrypt::hash(hex_digest, rounds as u32)
            })
            .await??;
            Ok(hash)
        }

        PasswordHashingAlgo::Scrypt => {
            let password_bytes = password.as_ref().to_owned();
            let salt = SaltString::generate(&mut OsRng);
            let hash = task::spawn_blocking(move || {
                Scrypt
                    .hash_password(&password_bytes, &salt)
                    .map(|hash| hash.to_string())
                    .map_err(|e| PasswordHashError::CryptoHash(e.to_string()))
            })
            .await??;
            Ok(hash)
        }

        PasswordHashingAlgo::Pbkdf2Sha512 => {
            let password_bytes = password.as_ref().to_owned();
            let salt = SaltString::generate(&mut OsRng);
            let hash = task::spawn_blocking(move || {
                Pbkdf2
                    .hash_password_customized(
                        &password_bytes,
                        Some(pbkdf2::Algorithm::Pbkdf2Sha512.ident()),
                        None,
                        pbkdf2::Params::default(),
                        &salt,
                    )
                    .map(|h| h.to_string())
                    .map_err(|e| PasswordHashError::CryptoHash(e.to_string()))
            })
            .await??;
            Ok(hash)
        }

        //#[cfg(test)]
        PasswordHashingAlgo::None => Ok(str::from_utf8(password.as_ref())?.to_string()),
    }
}

/// Verify the password matches the hashed value.
///
/// # Parameters
/// - `conf`: The service configuration.
/// - `password`: The password to verify.
/// - `hash`: The hash to compare against.
///
/// # Returns
/// - `Ok(bool)` - True if the password matches the hash, false otherwise.
/// - `Err(PasswordHashError)` - If verification failed.
pub async fn verify_password<P: AsRef<[u8]>, H: AsRef<str>>(
    conf: &Config,
    password: P,
    hash: H,
) -> Result<bool, PasswordHashError> {
    let password_hash = hash.as_ref().to_string();

    // Dynamically auto-detect the algorithm based on the actual database hash prefix
    let algo = if password_hash.starts_with("$2b$") || password_hash.starts_with("$2a$") {
        PasswordHashingAlgo::Bcrypt
    } else if password_hash.starts_with("$bcrypt-sha256$") {
        PasswordHashingAlgo::BcryptSha256
    } else if password_hash.starts_with("$scrypt$") {
        PasswordHashingAlgo::Scrypt
    } else if password_hash.starts_with("$pbkdf2-sha512$") {
        PasswordHashingAlgo::Pbkdf2Sha512
    } else {
        // Fallback to config default if it's unhashed/None
        conf.identity.password_hashing_algorithm.clone()
    };

    match algo {
        PasswordHashingAlgo::Bcrypt => {
            let password_bytes = verify_length_and_trunc_password(
                password.as_ref(),
                max(conf.identity.max_password_length, 72),
            )
            .to_owned();
            match task::spawn_blocking(move || bcrypt::verify(password_bytes, &password_hash))
                .await?
            {
                Ok(res) => Ok(res),
                Err(bcrypt::BcryptError::InvalidHash(..)) => {
                    warn!("Bcrypt hash verification error: bad hash");
                    Ok(false)
                }
                other => {
                    warn!("Bcrypt hash verification error: {other:?}");
                    Ok(false)
                }
            }
        }

        PasswordHashingAlgo::BcryptSha256 => {
            let password_bytes = verify_length_and_trunc_password(
                password.as_ref(),
                max(conf.identity.max_password_length, 72),
            )
            .to_owned();
            match task::spawn_blocking(move || {
                let digest = sha2::Sha256::digest(password_bytes);
                let hex_digest = digest
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>();
                bcrypt::verify(hex_digest, &password_hash)
            })
            .await?
            {
                Ok(res) => Ok(res),
                Err(bcrypt::BcryptError::InvalidHash(..)) => {
                    warn!("BcryptSha256 hash verification error: bad hash");
                    Ok(false)
                }
                other => {
                    warn!("BcryptSha256 hash verification error: {other:?}");
                    Ok(false)
                }
            }
        }

        PasswordHashingAlgo::Scrypt => {
            let password_bytes = password.as_ref().to_owned();
            let res = task::spawn_blocking(move || {
                // FIX: Normalize dots to plus signs for legacy Python Scrypt hashes in production
                let normalized_hash = password_hash.replace('.', "+");
                let parsed_hash = PasswordHash::new(&normalized_hash)
                    .map_err(|e| PasswordHashError::CryptoHash(e.to_string()))?;
                Ok::<bool, PasswordHashError>(
                    Scrypt
                        .verify_password(&password_bytes, &parsed_hash)
                        .is_ok(),
                )
            })
            .await??;
            Ok(res)
        }

        PasswordHashingAlgo::Pbkdf2Sha512 => {
            let password_bytes = password.as_ref().to_owned();
            let res = task::spawn_blocking(move || {
                if let Ok(parsed_hash) = PasswordHash::new(&password_hash) {
                    return Ok::<bool, PasswordHashError>(
                        Pbkdf2
                            .verify_password(&password_bytes, &parsed_hash)
                            .is_ok(),
                    );
                }

                // Fallback to Legacy Passlib parsing
                let parts: Vec<&str> = password_hash.split('$').collect();
                if parts.len() == 5 && parts[1] == "pbkdf2-sha512" {
                    let rounds: u32 = parts[2].parse().unwrap_or(25000);
                    let salt_str = parts[3].replace('.', "+");
                    let digest_str = parts[4].replace('.', "+");

                    let salt = STANDARD_NO_PAD
                        .decode(salt_str.as_bytes())
                        .map_err(|_| PasswordHashError::CryptoHash("Invalid legacy salt".into()))?;
                    let expected_digest = STANDARD_NO_PAD
                        .decode(digest_str.as_bytes())
                        .map_err(|_| PasswordHashError::CryptoHash("Invalid legacy hash".into()))?;

                    let mut computed_digest = vec![0u8; expected_digest.len()];
                    pbkdf2::pbkdf2_hmac::<sha2::Sha512>(
                        &password_bytes,
                        &salt,
                        rounds,
                        &mut computed_digest,
                    );

                    return Ok(computed_digest == expected_digest);
                }

                Err(PasswordHashError::CryptoHash(
                    "Invalid hash format".to_string(),
                ))
            })
            .await??;
            Ok(res)
        }

        PasswordHashingAlgo::None => Ok(str::from_utf8(password.as_ref())?.eq(hash.as_ref())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::distr::{Alphanumeric, SampleString};
    use tracing_test::traced_test;

    #[test]
    fn test_verify_length_and_trunc_password() {
        assert_eq!(
            b"abcdefg",
            verify_length_and_trunc_password("abcdefg".as_bytes(), 70)
        );
        assert_eq!(
            b"abcd",
            verify_length_and_trunc_password("abcdefg".as_bytes(), 4)
        );
        // In UTF8 bytes a single unicode is taking 3 bytes already
        assert_eq!(
            b"\xE2\x98\x81a",
            verify_length_and_trunc_password("☁abcdefg".as_bytes(), 4)
        );
    }

    #[tokio::test]
    #[traced_test]
    async fn test_hash_bcrypt() {
        let builder = config::Config::builder()
            .set_override("auth.methods", "")
            .unwrap()
            .set_override("database.connection", "dummy")
            .unwrap();
        let conf: Config = Config::try_from(builder).expect("can build a valid config");
        let pass = "abcdefg";
        let hashed = hash_password(&conf, &pass).await.unwrap();
        assert!(!logs_contain(pass));
        assert!(!logs_contain(&hashed));
    }

    #[tokio::test]
    #[traced_test]
    async fn test_roundtrip_bcrypt() {
        let builder = config::Config::builder()
            .set_override("auth.methods", "")
            .unwrap()
            .set_override("database.connection", "dummy")
            .unwrap();
        let conf: Config = Config::try_from(builder).expect("can build a valid config");
        let pass = "abcdefg";
        let hashed = hash_password(&conf, &pass).await.unwrap();
        assert!(verify_password(&conf, &pass, &hashed).await.unwrap());
        assert!(!logs_contain(pass));
        assert!(!logs_contain(&hashed));
    }

    #[tokio::test]
    #[traced_test]
    async fn test_roundtrip_bcrypt_longer_than_72() {
        let builder = config::Config::builder()
            .set_override("auth.methods", "")
            .unwrap()
            .set_override("database.connection", "dummy")
            .unwrap();
        let conf: Config = Config::try_from(builder).expect("can build a valid config");
        let pass = Alphanumeric.sample_string(&mut rand::rng(), 80);
        let hashed = hash_password(&conf, &pass).await.unwrap();
        assert!(verify_password(&conf, &pass, &hashed).await.unwrap());
        assert!(!logs_contain(&pass));
        assert!(!logs_contain(&hashed));
    }

    #[tokio::test]
    #[traced_test]
    async fn test_roundtrip_bcrypt_mismatch() {
        let builder = config::Config::builder()
            .set_override("auth.methods", "")
            .unwrap()
            .set_override("database.connection", "dummy")
            .unwrap();
        let conf: Config = Config::try_from(builder).expect("can build a valid config");
        let pass = Alphanumeric.sample_string(&mut rand::rng(), 80);
        let hashed = hash_password(&conf, "other password").await.unwrap();
        assert!(!verify_password(&conf, &pass, &hashed).await.unwrap());
        assert!(!logs_contain(&pass));
        assert!(!logs_contain(&hashed));
    }

    #[tokio::test]
    #[traced_test]
    async fn test_roundtrip_bcrypt_bad_hash() {
        let builder = config::Config::builder()
            .set_override("auth.methods", "")
            .unwrap()
            .set_override("database.connection", "dummy")
            .unwrap();
        let conf: Config = Config::try_from(builder).expect("can build a valid config");
        let pass = Alphanumeric.sample_string(&mut rand::rng(), 80);
        assert!(!verify_password(&conf, &pass, "foobar").await.unwrap());
        assert!(!logs_contain("foobar"));
        assert!(!logs_contain(&pass));
    }

    #[tokio::test]
    #[traced_test]
    async fn test_generate_and_verify_dummy_hash_bcrypt() {
        let builder = config::Config::builder()
            .set_override("auth.methods", "")
            .unwrap()
            .set_override("database.connection", "dummy")
            .unwrap();
        let conf: Config = Config::try_from(builder).expect("can build a valid config");
        let dummy_hash = generate_dummy_hash(&conf).await.unwrap();
        // Dummy hash should be a valid bcrypt hash (starts with $2b$)
        assert!(
            dummy_hash.starts_with("$2b$"),
            "Dummy hash should be a valid bcrypt hash"
        );
        // Verify should return false for any random password
        let pass = Alphanumeric.sample_string(&mut rand::rng(), 32);
        let result = verify_password(&conf, &pass, &dummy_hash).await.unwrap();
        // Result should be false (password doesn't match dummy hash)
        assert!(!result, "Dummy hash should not match random password");
        assert!(!logs_contain(&pass));
        assert!(!logs_contain(&dummy_hash));
    }

    #[tokio::test]
    #[traced_test]
    async fn test_generate_dummy_hash_none() {
        let builder = config::Config::builder()
            .set_override("auth.methods", "")
            .unwrap()
            .set_override("database.connection", "dummy")
            .unwrap()
            .set_override("identity.password_hashing_algorithm", "None")
            .unwrap();
        let conf: Config = Config::try_from(builder).expect("can build a valid config");
        let dummy_hash = generate_dummy_hash(&conf).await.unwrap();
        // Dummy hash should be a non-empty string
        assert!(!dummy_hash.is_empty(), "Dummy hash should not be empty");
        // Verify should return false for any random password
        let pass = Alphanumeric.sample_string(&mut rand::rng(), 32);
        let result = verify_password(&conf, &pass, &dummy_hash).await.unwrap();
        // Result should almost certainly be false (random password unlikely to match)
        assert!(!result, "Dummy hash should not match random password");
        assert!(!logs_contain(&pass));
        assert!(!logs_contain(&dummy_hash));
    }

    #[tokio::test]
    async fn test_dummy_hash_is_actually_cached() {
        let builder = config::Config::builder()
            .set_override("auth.methods", "")
            .unwrap()
            .set_override("database.connection", "dummy")
            .unwrap();
        let conf = Config::try_from(builder).expect("can build valid config");

        // Fetch it twice
        let first_fetch = get_or_init_dummy_hash(&conf).await.unwrap();
        let second_fetch = get_or_init_dummy_hash(&conf).await.unwrap();

        // They must be identical strings
        assert_eq!(
            first_fetch, second_fetch,
            "The OnceCell cache failed to preserve the dummy hash!"
        );
    }
}
#[cfg(test)]
mod passlib_migration_tests {
    use super::*; // Imports hash_password / verify_password functions
    use pbkdf2::Pbkdf2;
    use pbkdf2::password_hash::{PasswordHash, PasswordVerifier};
    use scrypt::Scrypt;

    const TEST_PASSWORD: &str = "openstack123";

    /// Custom verifier required for OpenStack database migrations.
    /// Replicates Passlib's legacy quirk of base64-decoding the salt
    /// (whereas the modern PHC standard uses the raw salt string directly).
    /// Custom verifier required for OpenStack database migrations.
    /// Replicates Passlib's legacy quirk of base64-decoding the salt
    /// (whereas the modern PHC standard uses the raw salt string directly).
    pub fn verify_legacy_passlib_pbkdf2(password: &str, raw_python_hash: &str) -> bool {
        let parts: Vec<&str> = raw_python_hash.split('$').collect();
        if parts.len() != 5 || parts[1] != "pbkdf2-sha512" {
            return false;
        }

        let rounds: u32 = parts[2].parse().unwrap_or(25000);
        let passlib_salt_ascii = parts[3];
        let checksum_b64 = parts[4];

        // Replace '.' with standard base64 '+'
        let salt_str = passlib_salt_ascii.replace('.', "+");
        let digest_str = checksum_b64.replace('.', "+");

        let decoded_salt = match STANDARD_NO_PAD.decode(salt_str.as_bytes()) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let expected_bytes = match STANDARD_NO_PAD.decode(digest_str.as_bytes()) {
            Ok(b) => b,
            Err(_) => return false,
        };

        // Compute hash manually using the DECODED salt bytes
        let mut computed_hash = vec![0u8; expected_bytes.len()];
        pbkdf2::pbkdf2_hmac::<sha2::Sha512>(
            password.as_bytes(),
            &decoded_salt,
            rounds,
            &mut computed_hash,
        );

        computed_hash == expected_bytes
    }

    /// Normalizes Python Passlib Scrypt hashes (which DO follow standards!)
    fn normalize_scrypt_hash(passlib_hash: &str) -> String {
        let parts: Vec<&str> = passlib_hash.split('$').collect();
        if parts.len() != 5 || parts[1] != "scrypt" {
            return passlib_hash.to_string();
        }
        let salt = parts[3].replace('.', "+");
        let checksum = parts[4].replace('.', "+");
        format!("$scrypt${}${}${}", parts[2], salt, checksum)
    }

    #[test]
    fn test_roundtrip_pbkdf2() {
        let salt =
            pbkdf2::password_hash::SaltString::generate(pbkdf2::password_hash::rand_core::OsRng);
        let hash = pbkdf2::password_hash::PasswordHasher::hash_password(
            &Pbkdf2,
            TEST_PASSWORD.as_bytes(),
            &salt,
        )
        .unwrap();
        let hash_string = hash.to_string();
        let parsed_hash = PasswordHash::new(&hash_string).unwrap();
        assert!(
            Pbkdf2
                .verify_password(TEST_PASSWORD.as_bytes(), &parsed_hash)
                .is_ok()
        );
    }

    #[test]
    fn test_roundtrip_scrypt() {
        let salt =
            pbkdf2::password_hash::SaltString::generate(pbkdf2::password_hash::rand_core::OsRng);
        let hash = pbkdf2::password_hash::PasswordHasher::hash_password(
            &Scrypt,
            TEST_PASSWORD.as_bytes(),
            &salt,
        )
        .unwrap();
        let hash_string = hash.to_string();
        let parsed_hash = PasswordHash::new(&hash_string).unwrap();
        assert!(
            Scrypt
                .verify_password(TEST_PASSWORD.as_bytes(), &parsed_hash)
                .is_ok()
        );
    }

    #[test]
    fn test_rejection_wrong_password() {
        let salt =
            pbkdf2::password_hash::SaltString::generate(pbkdf2::password_hash::rand_core::OsRng);
        let hash = pbkdf2::password_hash::PasswordHasher::hash_password(
            &Pbkdf2,
            TEST_PASSWORD.as_bytes(),
            &salt,
        )
        .unwrap();
        let hash_string = hash.to_string();
        let parsed_hash = PasswordHash::new(&hash_string).unwrap();
        assert!(
            Pbkdf2
                .verify_password(b"wrongpassword", &parsed_hash)
                .is_err()
        );
    }

    #[test]
    fn test_rejection_empty_password() {
        let salt =
            pbkdf2::password_hash::SaltString::generate(pbkdf2::password_hash::rand_core::OsRng);
        let hash = pbkdf2::password_hash::PasswordHasher::hash_password(
            &Pbkdf2,
            TEST_PASSWORD.as_bytes(),
            &salt,
        )
        .unwrap();
        let hash_string = hash.to_string();
        let parsed_hash = PasswordHash::new(&hash_string).unwrap();
        assert!(Pbkdf2.verify_password(b"", &parsed_hash).is_err());
    }

    #[test]
    fn test_python_passlib_compatibility() {
        let python_pbkdf2_hash = "$pbkdf2-sha512$25000$bo2REsLY.z9HCCFESEmJkQ$qX0JhkudwUVXpDKfMkDrWRgiP2AcYLbocxVkQrOmX4i0SGANHAB8KQUd1vbwVYJEBpbi4RvyvP5QJWZfIhnWTQ";
        let python_scrypt_hash = "$scrypt$ln=16,r=8,p=1$FoLwnnPuvVdKqbWWEuK8lw$zaI+PjacJwDMwu4NoXmY9spmyrB4qnc8kGAJ4I6oABo";

        // 1. Verify PBKDF2 using our OpenStack legacy manual verifier
        assert!(
            verify_legacy_passlib_pbkdf2(TEST_PASSWORD, python_pbkdf2_hash),
            "Custom verifier rejected Python's legacy PBKDF2 hash!"
        );

        // 2. Verify SCRYPT using standard tools (Passlib Scrypt is fully standard compliant)
        let norm_scrypt_str = normalize_scrypt_hash(python_scrypt_hash);
        let parsed_scrypt = PasswordHash::new(&norm_scrypt_str).unwrap();
        assert!(
            Scrypt
                .verify_password(TEST_PASSWORD.as_bytes(), &parsed_scrypt)
                .is_ok(),
            "Rust rejected Python's valid SCRYPT hash!"
        );
    }

    #[tokio::test]
    async fn test_production_verify_password_integration_with_legacy_pbkdf2() {
        let builder = config::Config::builder()
            .set_override("auth.methods", "")
            .unwrap()
            .set_override("database.connection", "dummy")
            .unwrap()
            .set_override("identity.password_hashing_algorithm", "Pbkdf2Sha512")
            .unwrap();
        let conf = Config::try_from(builder).expect("can build valid config");

        let python_pbkdf2_hash = "$pbkdf2-sha512$25000$bo2REsLY.z9HCCFESEmJkQ$qX0JhkudwUVXpDKfMkDrWRgiP2AcYLbocxVkQrOmX4i0SGANHAB8KQUd1vbwVYJEBpbi4RvyvP5QJWZfIhnWTQ";

        // Call the REAL production entry point function, not the helper function
        let result = verify_password(&conf, TEST_PASSWORD, python_pbkdf2_hash)
            .await
            .unwrap();

        assert!(
            result,
            "The production verify_password function failed to fallback and parse the legacy string!"
        );
    }

    #[tokio::test]
    async fn test_production_verify_password_integration_with_legacy_scrypt() {
        let builder = config::Config::builder()
            .set_override("auth.methods", "")
            .unwrap()
            .set_override("database.connection", "dummy")
            .unwrap()
            .set_override("identity.password_hashing_algorithm", "Bcrypt") // Intentional mismatch
            .unwrap();
        let conf = Config::try_from(builder).expect("can build valid config");

        // Raw Python Passlib Scrypt hash containing dots (un-normalized)
        let raw_python_scrypt = "$scrypt$ln=16,r=8,p=1$FoLwnnPuvVdKqbWWEuK8lw$zaI+PjacJwDMwu4NoXmY9spmyrB4qnc8kGAJ4I6oABo";

        // Call the REAL production entry point function
        let result = verify_password(&conf, TEST_PASSWORD, raw_python_scrypt)
            .await
            .unwrap();

        assert!(
            result,
            "Production verify_password failed to auto-detect and normalize the legacy Scrypt hash!"
        );
    }
}
