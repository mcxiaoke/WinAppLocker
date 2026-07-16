//! packer 端到端测试：加密 4 个样本，验证生成的 locked 文件能被 payload reader 解析，
//! 且解密还原的字节与原 EXE 一致。

use std::path::PathBuf;

use exelock_crypto::{algorithm_by_id, kdf_by_id, CryptoAlgorithm, Kdf, KdfParams};
use exelock_packer::pack::{pack, PackOptions};
use exelock_packer::stub_selector::StubPreference;
use exelock_payload::Payload;

fn samples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../tests/samples")
}

fn sample(name: &str) -> PathBuf {
    samples_dir().join(name)
}

/// 加密样本，然后从 locked 文件解析 payload 并解密，校验还原字节 == 原 EXE。
fn round_trip_sample(sample_name: &str, use_aad: bool, algorithm_id: u16, kdf_id: u16, iters: u32) {
    let input = sample(sample_name);
    let output = samples_dir().join(format!("{}_locked.exe", sample_name.replace(".exe", "")));

    let opts = PackOptions {
        input_path: input.clone(),
        output_path: output.clone(),
        password: "test1234".to_string(),
        algorithm_id,
        kdf_id,
        kdf_iterations: iters,
        salt_len: 16,
        use_aad,
        erase_payload: true,
        stub_preference: StubPreference::Auto,
        custom_extensions: Vec::new(),
    };

    let report = pack(&opts, None).expect("pack 失败");
    assert!(report.output_size > report.original_size, "输出应大于原文件");

    // 读取 locked 文件
    let locked_bytes = std::fs::read(&output).expect("读取 locked 文件失败");
    let payload = Payload::from_file_tail(&locked_bytes).expect("payload 解析失败");

    // 校验 header 字段
    assert_eq!(payload.header.algorithm_id, algorithm_id);
    assert_eq!(payload.header.kdf_id, kdf_id);
    assert_eq!(payload.header.kdf_iterations, iters);
    assert_eq!(payload.header.plaintext_len, report.original_size as u64);

    // 解密还原
    let kdf = kdf_by_id(payload.header.kdf_id).unwrap();
    let key = kdf
        .derive(
            b"test1234",
            &payload.salt,
            KdfParams::Pbkdf2 {
                iterations: payload.header.kdf_iterations,
            },
        )
        .unwrap();
    let algo = algorithm_by_id(payload.header.algorithm_id).unwrap();
    let plaintext = algo
        .decrypt(&payload.ciphertext, &key, &payload.nonce, payload.aad())
        .expect("解密失败");

    // 校验还原字节 == 原 EXE
    let original = std::fs::read(&input).expect("读取原 EXE 失败");
    assert_eq!(plaintext, original, "解密还原的字节与原 EXE 不一致");

    // 清理测试产物
    let _ = std::fs::remove_file(&output);
}

#[test]
fn round_trip_notepad_balanced() {
    round_trip_sample("notepad.exe", true, 0x0001, 0x0001, 100_000);
}

#[test]
fn round_trip_dontsleep_balanced() {
    round_trip_sample("DontSleep.exe", true, 0x0001, 0x0001, 100_000);
}

#[test]
fn round_trip_ddccli_balanced() {
    round_trip_sample("ddccli.exe", true, 0x0001, 0x0001, 100_000);
}

#[test]
fn round_trip_sha512sum_balanced() {
    round_trip_sample("sha512sum.exe", true, 0x0001, 0x0001, 100_000);
}

#[test]
fn round_trip_notepad_chacha_secure() {
    round_trip_sample("notepad.exe", true, 0x0002, 0x0002, 100_000);
}

#[test]
fn round_trip_notepad_no_aad() {
    round_trip_sample("notepad.exe", false, 0x0001, 0x0001, 100_000);
}

#[test]
fn gui_exe_sets_subsystem_flag() {
    // notepad.exe 是 GUI 程序，加密后 original_subsystem 应为 2
    let input = sample("notepad.exe");
    let output = samples_dir().join("_test_gui_flag_locked.exe");

    let opts = PackOptions {
        input_path: input.clone(),
        output_path: output.clone(),
        password: "test1234".to_string(),
        algorithm_id: 0x0001,
        kdf_id: 0x0001,
        kdf_iterations: 100_000,
        salt_len: 16,
        use_aad: true,
        erase_payload: true,
        stub_preference: StubPreference::Auto,
        custom_extensions: Vec::new(),
    };
    let _ = pack(&opts, None).unwrap();

    let locked = std::fs::read(&output).unwrap();
    let payload = Payload::from_file_tail(&locked).unwrap();
    assert_eq!(payload.header.original_subsystem, 2, "GUI 程序 subsystem 应为 2");
    assert!(payload.header.flags & exelock_payload::header::FLAG_ORIGINAL_IS_GUI != 0);

    let _ = std::fs::remove_file(&output);
}

#[test]
fn console_exe_sets_subsystem_flag() {
    // ddccli.exe 是 Console 程序，加密后 original_subsystem 应为 3
    let input = sample("ddccli.exe");
    let output = samples_dir().join("_test_cli_flag_locked.exe");

    let opts = PackOptions {
        input_path: input.clone(),
        output_path: output.clone(),
        password: "test1234".to_string(),
        algorithm_id: 0x0001,
        kdf_id: 0x0001,
        kdf_iterations: 100_000,
        salt_len: 16,
        use_aad: true,
        erase_payload: true,
        stub_preference: StubPreference::Auto,
        custom_extensions: Vec::new(),
    };
    let _ = pack(&opts, None).unwrap();

    let locked = std::fs::read(&output).unwrap();
    let payload = Payload::from_file_tail(&locked).unwrap();
    assert_eq!(payload.header.original_subsystem, 3, "Console 程序 subsystem 应为 3");
    assert!(payload.header.flags & exelock_payload::header::FLAG_ORIGINAL_IS_GUI == 0);

    let _ = std::fs::remove_file(&output);
}

#[test]
fn original_name_extension_present() {
    let input = sample("notepad.exe");
    let output = samples_dir().join("_test_name_ext_locked.exe");

    let opts = PackOptions {
        input_path: input.clone(),
        output_path: output.clone(),
        password: "test1234".to_string(),
        algorithm_id: 0x0001,
        kdf_id: 0x0001,
        kdf_iterations: 100_000,
        salt_len: 16,
        use_aad: true,
        erase_payload: true,
        stub_preference: StubPreference::Auto,
        custom_extensions: Vec::new(),
    };
    let _ = pack(&opts, None).unwrap();

    let locked = std::fs::read(&output).unwrap();
    let payload = Payload::from_file_tail(&locked).unwrap();
    assert_eq!(
        payload.extensions.get(exelock_payload::header::EXT_ORIGINAL_NAME),
        Some(b"notepad.exe".as_slice()),
        "EXT_ORIGINAL_NAME 应包含原文件名"
    );

    let _ = std::fs::remove_file(&output);
}

#[test]
fn custom_extension_preserved() {
    let input = sample("notepad.exe");
    let output = samples_dir().join("_test_custom_ext_locked.exe");

    let opts = PackOptions {
        input_path: input.clone(),
        output_path: output.clone(),
        password: "test1234".to_string(),
        algorithm_id: 0x0001,
        kdf_id: 0x0001,
        kdf_iterations: 100_000,
        salt_len: 16,
        use_aad: false,
        erase_payload: false,
        stub_preference: StubPreference::Auto,
        custom_extensions: vec![(0x8000, b"my-license".to_vec())],
    };
    let _ = pack(&opts, None).unwrap();

    let locked = std::fs::read(&output).unwrap();
    let payload = Payload::from_file_tail(&locked).unwrap();
    assert_eq!(
        payload.extensions.get(0x8000),
        Some(b"my-license".as_slice()),
        "用户自定义扩展应被保留"
    );

    let _ = std::fs::remove_file(&output);
}
