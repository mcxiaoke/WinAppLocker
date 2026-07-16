//! exelock-payload 测试：writer→reader round-trip、footer 定位、扩展区、篡改检测。

use exelock_crypto::{algorithm_by_id, kdf_by_id, CryptoAlgorithm, Kdf, KdfParams};
use exelock_payload::{
    header::{EXT_ORIGINAL_NAME, FLAG_ERASE_PAYLOAD, FLAG_USE_AAD, FLAG_ORIGINAL_IS_GUI},
    writer::{crc32_of, default_aad},
    PayloadBuilder, PayloadError, FIXED_HEADER_LEN, FOOTER_LEN,
};

const PW: &[u8] = b"test-password-123";
const PLAINTEXT: &[u8] = b"fake exe content for payload round trip test 0123456789";

/// 构造一个完整的 stub+payload 字节流（stub 用假前缀）。
fn build_locked_file(
    stub_prefix: &[u8],
    use_aad: bool,
    algorithm_id: u16,
    kdf_id: u16,
    iters: u32,
) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let salt = exelock_crypto::random_bytes(16);
    let kdf = kdf_by_id(kdf_id).unwrap();
    let key = kdf
        .derive(PW, &salt, KdfParams::Pbkdf2 { iterations: iters })
        .unwrap();
    let algo = algorithm_by_id(algorithm_id).unwrap();
    let nonce = exelock_crypto::random_bytes(algo.nonce_len());

    // AAD 必须在加密前确定，且与 builder 最终写入 EXT_AAD 的内容一致。
    let aad_bytes = if use_aad {
        Some(default_aad(algorithm_id, kdf_id, iters, 2, 0x8664))
    } else {
        None
    };
    let ct = algo
        .encrypt(PLAINTEXT, &key, &nonce, aad_bytes.as_deref())
        .unwrap();

    let crc = crc32_of(PLAINTEXT);
    let mut builder = PayloadBuilder::new(algorithm_id, kdf_id, iters)
        .original_pe_info(2, 0x8664, Some("app.exe"))
        .plaintext_meta(PLAINTEXT.len() as u64, crc)
        .material(salt.clone(), nonce.clone(), ct.clone())
        .erase_payload(true);
    if use_aad {
        builder = builder.use_aad(None);
    }
    let payload = builder.build();

    let mut file = stub_prefix.to_vec();
    file.extend_from_slice(&payload);
    (file, salt, nonce, ct)
}

#[test]
fn round_trip_basic() {
    let (file, salt, _nonce, _ct) =
        build_locked_file(b"FAKE_STUB_PREFIX", false, 0x0001, 0x0001, 100_000);
    let payload = exelock_payload::Payload::from_file_tail(&file).expect("parse");
    assert_eq!(payload.salt, salt);
    assert_eq!(payload.ciphertext.len(), PLAINTEXT.len() + 16);
    assert_eq!(payload.header.plaintext_len, PLAINTEXT.len() as u64);
    assert_eq!(payload.header.original_subsystem, 2);
    assert_eq!(payload.header.original_machine, 0x8664);
    assert!(payload.header.flags & FLAG_ERASE_PAYLOAD != 0);
    assert!(payload.header.flags & FLAG_ORIGINAL_IS_GUI != 0);
    // 扩展区应含 EXT_ORIGINAL_NAME
    assert_eq!(payload.extensions.get(EXT_ORIGINAL_NAME), Some(b"app.exe".as_slice()));
}

#[test]
fn round_trip_with_aad() {
    let (file, _salt, _nonce, _ct) =
        build_locked_file(b"\x00\x01\x02STUB", true, 0x0001, 0x0001, 100_000);
    let payload = exelock_payload::Payload::from_file_tail(&file).expect("parse");
    assert!(payload.header.flags & FLAG_USE_AAD != 0);
    assert!(payload.aad().is_some());
}

#[test]
fn round_trip_chacha20() {
    let (file, _salt, _nonce, _ct) =
        build_locked_file(b"STUB", false, 0x0002, 0x0002, 100_000);
    let payload = exelock_payload::Payload::from_file_tail(&file).expect("parse");
    assert_eq!(payload.header.algorithm_id, 0x0002);
    assert_eq!(payload.header.kdf_id, 0x0002);
    assert_eq!(payload.header.nonce_len, 12);
}

#[test]
fn footer_magic_mismatch_rejected() {
    let mut file = b"STUB".to_vec();
    file.extend_from_slice(&[0u8; 24]); // 全零 footer
    let err = exelock_payload::Payload::from_file_tail(&file);
    assert!(matches!(err, Err(PayloadError::BadFooterMagic)));
}

#[test]
fn header_tamper_detected_by_crc() {
    let (mut file, _salt, _nonce, _ct) =
        build_locked_file(b"STUB", false, 0x0001, 0x0001, 100_000);
    // 计算 payload 起始并翻转 header 中一个非 CRC 字节
    let payload_len = u64::from_le_bytes(file[file.len()-16..file.len()-8].try_into().unwrap()) as usize;
    let payload_start = file.len() - payload_len;
    // 翻转 algorithm_id（偏移 20）
    file[payload_start + 20] ^= 0xff;
    let err = exelock_payload::Payload::from_file_tail(&file);
    assert!(matches!(err, Err(PayloadError::HeaderCrcMismatch { .. })));
}

#[test]
fn ciphertext_tamper_detected_by_gcm() {
    let (mut file, salt, nonce, _ct) =
        build_locked_file(b"STUB", false, 0x0001, 0x0001, 100_000);
    let payload_len = u64::from_le_bytes(file[file.len()-16..file.len()-8].try_into().unwrap()) as usize;
    let payload_start = file.len() - payload_len;
    // 翻转 ciphertext 第一个字节（header 后 + salt + nonce 后）
    let ct_offset = payload_start + FIXED_HEADER_LEN + 16 + 12;
    file[ct_offset] ^= 0xff;

    let payload = exelock_payload::Payload::from_file_tail(&file).unwrap();
    let kdf = kdf_by_id(payload.header.kdf_id).unwrap();
    let key = kdf.derive(PW, &payload.salt, KdfParams::Pbkdf2 { iterations: 100_000 }).unwrap();
    let algo = algorithm_by_id(payload.header.algorithm_id).unwrap();
    let r = algo.decrypt(&payload.ciphertext, &key, &payload.nonce, payload.aad());
    assert!(r.is_err(), "篡改 ciphertext 后 GCM 解密必须失败");
}

#[test]
fn too_short_file_rejected() {
    let short = vec![0u8; 10];
    let err = exelock_payload::Payload::from_file_tail(&short);
    assert!(matches!(err, Err(PayloadError::TooShort(_, _))));
}

#[test]
fn extension_unknown_tag_is_skipped() {
    // 自定义 tag 0x8000 应被 reader 跳过而不报错
    let salt = exelock_crypto::random_bytes(16);
    let kdf = kdf_by_id(0x0001).unwrap();
    let key = kdf.derive(PW, &salt, KdfParams::Pbkdf2 { iterations: 100_000 }).unwrap();
    let algo = algorithm_by_id(0x0001).unwrap();
    let nonce = exelock_crypto::random_bytes(algo.nonce_len());
    let ct = algo.encrypt(PLAINTEXT, &key, &nonce, None).unwrap();
    let crc = crc32_of(PLAINTEXT);

    let payload = PayloadBuilder::new(0x0001, 0x0001, 100_000)
        .original_pe_info(3, 0x8664, None)
        .plaintext_meta(PLAINTEXT.len() as u64, crc)
        .material(salt, nonce, ct)
        .extension(0x8000, b"private-data".to_vec())  // 用户自定义扩展
        .extension(0x0006, b"padding".to_vec())        // 官方扩展
        .build();

    let mut file = b"STUB".to_vec();
    file.extend_from_slice(&payload);
    let parsed = exelock_payload::Payload::from_file_tail(&file).expect("parse");
    assert_eq!(parsed.extensions.get(0x8000), Some(b"private-data".as_slice()));
    assert_eq!(parsed.extensions.get(0x0006), Some(b"padding".as_slice()));
}

#[test]
fn payload_len_in_footer_is_consistent() {
    let (file, _salt, _nonce, _ct) =
        build_locked_file(b"STUB", false, 0x0001, 0x0001, 100_000);
    let footer_start = file.len() - FOOTER_LEN;
    let payload_len = u64::from_le_bytes(file[footer_start+8..footer_start+16].try_into().unwrap()) as usize;
    // payload_len 应小于等于文件大小
    assert!(payload_len <= file.len());
    assert!(payload_len > FIXED_HEADER_LEN + FOOTER_LEN);
}
