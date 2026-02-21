use super::hash::{hash_password, verify_password};

#[test]
fn hash_password_returns_valid_argon2_hash() {
    let password = "my_secure_password_123";
    let result = hash_password(password);

    assert!(result.is_ok());
    let hash = result.unwrap();
    assert!(hash.starts_with("$argon2"));
}

#[test]
fn hash_password_same_password_produces_different_hashes() {
    let password = "same_password_test";

    let hash1 = hash_password(password).expect("First hash should succeed");
    let hash2 = hash_password(password).expect("Second hash should succeed");

    assert_ne!(
        hash1, hash2,
        "Same password should produce different hashes due to salt"
    );
}

#[test]
fn hash_password_empty_string_works() {
    let password = "";
    let result = hash_password(password);

    assert!(result.is_ok());
    let hash = result.unwrap();
    assert!(hash.starts_with("$argon2"));
}

#[test]
fn verify_password_correct_password_returns_true() {
    let password = "correct_password_456";
    let hash = hash_password(password).expect("Hashing should succeed");

    let result = verify_password(password, &hash);

    assert!(result.is_ok());
    assert!(
        result.unwrap(),
        "Verification should return true for correct password"
    );
}

#[test]
fn verify_password_incorrect_password_returns_false() {
    let password = "correct_password_789";
    let wrong_password = "wrong_password_789";
    let hash = hash_password(password).expect("Hashing should succeed");

    let result = verify_password(wrong_password, &hash);

    assert!(result.is_ok());
    assert!(
        !result.unwrap(),
        "Verification should return false for incorrect password"
    );
}

#[test]
fn verify_password_invalid_hash_returns_error() {
    let password = "some_password";
    let invalid_hash = "not_a_valid_argon2_hash";

    let result = verify_password(password, invalid_hash);

    assert!(
        result.is_err(),
        "Verification should return error for invalid hash format"
    );
}
