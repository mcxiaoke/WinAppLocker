//! exelock-crypto 单元测试：算法/KDF round-trip、错误密钥、AAD 篡改、迭代次数校验。

use exelock_crypto::{
    algorithm_by_id, kdf_by_id, validate_iterations, CryptoAlgorithm, Kdf, KdfParams,
    MIN_ITERATIONS, MAX_ITERATIONS,
};

const PW: &[u8] = b"correct horse battery staple";
const PLAINTEXT: &[u8] = b"hello exelock payload plaintext data 0123456789";

fn derive_key(kdf_id: u16, iters: u32, salt: &[u8]) -> Vec<u8> {
    let kdf = kdf_by_id(kdf_id).expect("kdf");
    let key = kdf
        .derive(PW, salt, KdfParams::Pbkdf2 { iterations: iters })
        .expect("derive");
    key.to_vec()
}

#[test]
fn pbkdf2_derive_is_deterministic() {
    let salt = [1u8; 16];
    let a = derive_key(exelock_crypto::kdf::id::PBKDF2_SHA256, 100_000, &salt);
    let b = derive_key(exelock_crypto::kdf::id::PBKDF2_SHA256, 100_000, &salt);
    assert_eq!(a, b, "相同密码+salt+迭代次数应派生出相同密钥");
    assert_eq!(a.len(), 32);
}

#[test]
fn pbkdf2_different_salt_different_key() {
    let k1 = derive_key(exelock_crypto::kdf::id::PBKDF2_SHA256, 100_000, &[1; 16]);
    let k2 = derive_key(exelock_crypto::kdf::id::PBKDF2_SHA256, 100_000, &[2; 16]);
    assert_ne!(k1, k2, "不同 salt 应派生出不同密钥");
}

#[test]
fn aes256_gcm_round_trip() {
    let salt = [9u8; 16];
    let key = derive_key(exelock_crypto::kdf::id::PBKDF2_SHA256, 100_000, &salt);
    let algo = algorithm_by_id(exelock_crypto::algorithm::id::AES_256_GCM).unwrap();
    let nonce = exelock_crypto::random_bytes(algo.nonce_len());

    let ct = algo.encrypt(PLAINTEXT, &key, &nonce, None).expect("encrypt");
    assert_eq!(ct.len(), PLAINTEXT.len() + algo.tag_len());

    let pt = algo.decrypt(&ct, &key, &nonce, None).expect("decrypt");
    assert_eq!(pt, PLAINTEXT);
}

#[test]
fn chacha20_round_trip() {
    let salt = [9u8; 16];
    let key = derive_key(exelock_crypto::kdf::id::PBKDF2_SHA256, 100_000, &salt);
    let algo = algorithm_by_id(exelock_crypto::algorithm::id::CHACHA20_POLY1305).unwrap();
    let nonce = exelock_crypto::random_bytes(algo.nonce_len());

    let ct = algo.encrypt(PLAINTEXT, &key, &nonce, None).expect("encrypt");
    let pt = algo.decrypt(&ct, &key, &nonce, None).expect("decrypt");
    assert_eq!(pt, PLAINTEXT);
}

#[test]
fn wrong_password_fails_decryption() {
    let salt = [9u8; 16];
    let key_correct = derive_key(exelock_crypto::kdf::id::PBKDF2_SHA256, 100_000, &salt);
    let key_wrong = derive_key(exelock_crypto::kdf::id::PBKDF2_SHA256, 100_000, &[8; 16]);

    let algo = algorithm_by_id(exelock_crypto::algorithm::id::AES_256_GCM).unwrap();
    let nonce = exelock_crypto::random_bytes(algo.nonce_len());
    let ct = algo.encrypt(PLAINTEXT, &key_correct, &nonce, None).expect("encrypt");

    let err = algo.decrypt(&ct, &key_wrong, &nonce, None);
    assert!(err.is_err(), "错误密钥解密必须失败");
}

#[test]
fn ciphertext_tamper_fails() {
    let salt = [9u8; 16];
    let key = derive_key(exelock_crypto::kdf::id::PBKDF2_SHA256, 100_000, &salt);
    let algo = algorithm_by_id(exelock_crypto::algorithm::id::AES_256_GCM).unwrap();
    let nonce = exelock_crypto::random_bytes(algo.nonce_len());
    let mut ct = algo.encrypt(PLAINTEXT, &key, &nonce, None).expect("encrypt");
    // 翻转一个字节
    ct[0] ^= 0xff;
    assert!(algo.decrypt(&ct, &key, &nonce, None).is_err());
}

#[test]
fn aad_tamper_fails() {
    let salt = [9u8; 16];
    let key = derive_key(exelock_crypto::kdf::id::PBKDF2_SHA256, 100_000, &salt);
    let algo = algorithm_by_id(exelock_crypto::algorithm::id::AES_256_GCM).unwrap();
    let nonce = exelock_crypto::random_bytes(algo.nonce_len());
    let aad: &[u8] = b"header-binding";
    let ct = algo.encrypt(PLAINTEXT, &key, &nonce, Some(aad)).expect("encrypt");

    // 用不同 AAD 解密必须失败
    let bad_aad: &[u8] = b"header-bindinX";
    assert!(algo.decrypt(&ct, &key, &nonce, Some(bad_aad)).is_err());
    // 正确 AAD 解密成功
    assert!(algo.decrypt(&ct, &key, &nonce, Some(aad)).is_ok());
}

#[test]
fn wrong_key_length_rejected() {
    let algo = algorithm_by_id(exelock_crypto::algorithm::id::AES_256_GCM).unwrap();
    let nonce = exelock_crypto::random_bytes(algo.nonce_len());
    let short_key = [0u8; 16];
    assert!(algo.encrypt(PLAINTEXT, &short_key, &nonce, None).is_err());
}

#[test]
fn wrong_nonce_length_rejected() {
    let algo = algorithm_by_id(exelock_crypto::algorithm::id::AES_256_GCM).unwrap();
    let key = [0u8; 32];
    let bad_nonce = [0u8; 11];
    assert!(algo.encrypt(PLAINTEXT, &key, &bad_nonce, None).is_err());
}

#[test]
fn unknown_algorithm_returns_none() {
    assert!(algorithm_by_id(0xFFFF).is_none());
}

#[test]
fn unknown_kdf_returns_none() {
    assert!(kdf_by_id(0xFFFF).is_none());
}

#[test]
fn iterations_bounds_enforced() {
    assert!(validate_iterations(MIN_ITERATIONS).is_ok());
    assert!(validate_iterations(MAX_ITERATIONS).is_ok());
    assert!(validate_iterations(MIN_ITERATIONS - 1).is_err());
    assert!(validate_iterations(MAX_ITERATIONS + 1).is_err());
}

#[test]
fn kdf_rejects_out_of_range_iterations() {
    let kdf = kdf_by_id(exelock_crypto::kdf::id::PBKDF2_SHA256).unwrap();
    let salt = [0u8; 16];
    let r = kdf.derive(PW, &salt, KdfParams::Pbkdf2 { iterations: 10 });
    assert!(r.is_err(), "低于最小迭代次数应被拒绝");
}

#[test]
fn algorithm_id_is_self_reported_and_consistent() {
    let aes = algorithm_by_id(exelock_crypto::algorithm::id::AES_256_GCM).unwrap();
    let cc = algorithm_by_id(exelock_crypto::algorithm::id::CHACHA20_POLY1305).unwrap();
    assert_eq!(aes.id(), exelock_crypto::algorithm::id::AES_256_GCM);
    assert_eq!(cc.id(), exelock_crypto::algorithm::id::CHACHA20_POLY1305);
    assert_eq!(aes.nonce_len(), 12);
    assert_eq!(cc.nonce_len(), 12);
    assert_eq!(aes.tag_len(), 16);
    assert_eq!(cc.tag_len(), 16);
    assert_eq!(aes.key_len(), 32);
    assert_eq!(cc.key_len(), 32);
}
