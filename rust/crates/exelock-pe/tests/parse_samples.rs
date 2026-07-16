//! exelock-pe 测试：用 tests/samples 下的真实样本验证 PE 解析。
//!
//! 样本说明（用户补充）：
//! - notepad.exe   — GUI 程序（Notepad3 或类似）
//! - DontSleep.exe — GUI 程序
//! - ddccli.exe    — Console 程序
//! - sha512sum.exe — Console 程序

use exelock_pe::{Machine, PeInfo, Subsystem};
use std::path::PathBuf;

fn sample(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/samples")
        .join(name)
}

fn read_sample(name: &str) -> Vec<u8> {
    let path = sample(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("读取 {} 失败: {}", path.display(), e))
}

#[test]
fn parse_notepad_exe() {
    let data = read_sample("notepad.exe");
    let info = PeInfo::parse(&data).expect("notepad.exe 应能解析");
    assert_eq!(info.machine, Machine::X64);
    assert!(info.subsystem.is_gui(), "notepad 应是 GUI 子系统, 实际 {:?}", info.subsystem);
    assert_eq!(info.subsystem.raw(), 2);
    assert!(!info.is_dotnet, "notepad 不是 .NET 程序");
    assert!(info.image_size > 0);
}

#[test]
fn parse_dontsleep_exe() {
    let data = read_sample("DontSleep.exe");
    let info = PeInfo::parse(&data).expect("DontSleep.exe 应能解析");
    assert_eq!(info.machine, Machine::X64);
    assert!(info.subsystem.is_gui(), "DontSleep 应是 GUI 子系统, 实际 {:?}", info.subsystem);
    assert_eq!(info.subsystem.raw(), 2);
    assert!(!info.is_dotnet);
}

#[test]
fn parse_ddccli_exe() {
    let data = read_sample("ddccli.exe");
    let info = PeInfo::parse(&data).expect("ddccli.exe 应能解析");
    assert_eq!(info.machine, Machine::X64);
    assert_eq!(info.subsystem, Subsystem::Console, "ddccli 应是 Console 子系统");
    assert_eq!(info.subsystem.raw(), 3);
    assert!(!info.subsystem.is_gui());
    assert!(!info.is_dotnet);
}

#[test]
fn parse_sha512sum_exe() {
    let data = read_sample("sha512sum.exe");
    let info = PeInfo::parse(&data).expect("sha512sum.exe 应能解析");
    assert_eq!(info.machine, Machine::X64);
    assert_eq!(info.subsystem, Subsystem::Console, "sha512sum 应是 Console 子系统");
    assert_eq!(info.subsystem.raw(), 3);
    assert!(!info.is_dotnet);
}

#[test]
fn reject_non_pe_data() {
    let data = b"this is not a PE file at all, just plain text";
    let err = PeInfo::parse(data);
    assert!(err.is_err());
}

#[test]
fn subsystem_from_raw_roundtrip() {
    assert_eq!(Subsystem::from_raw(2), Subsystem::Gui);
    assert_eq!(Subsystem::from_raw(3), Subsystem::Console);
    assert_eq!(Subsystem::from_raw(9), Subsystem::Unknown(9));
    assert_eq!(Subsystem::Gui.raw(), 2);
    assert_eq!(Subsystem::Console.raw(), 3);
    assert_eq!(Subsystem::Unknown(9).raw(), 9);
    assert!(Subsystem::Gui.is_gui());
    assert!(!Subsystem::Console.is_gui());
    assert!(Subsystem::Unknown(9).is_gui());
}

#[test]
fn machine_from_raw_roundtrip() {
    assert_eq!(Machine::from_raw(0x8664), Machine::X64);
    assert_eq!(Machine::from_raw(0x14c), Machine::Other(0x14c));
    assert_eq!(Machine::X64.raw(), 0x8664);
}
