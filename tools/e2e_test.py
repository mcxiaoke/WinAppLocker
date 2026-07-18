#!/usr/bin/env python3
"""
winlock/tools/e2e_test.py - WinLock 综合端到端测试

用法:
    python tools/e2e_test.py

测试矩阵:
    1. stub_sha256_test.exe  - SHA-256 标准向量 + utf16le_to_utf8 + 端到端 hash
    2. hellocli (CLI, test mode)    - 加壳 -> 运行 -> 验证输出 "Hello World!"
    3. hellogui (GUI, 正常模式)     - 加壳 -> 弹密码框 -> 输入正确密码 -> 主窗口出现
    4. hellogui (GUI, 错误密码路径) - 错误密码 -> 弹错误框 -> 重试 -> 主窗口出现
    5. DontSleep (GUI, 正常模式)    - 真实第三方 GUI 程序
    6. Notepad4 (GUI, 正常模式)    - 真实第三方 GUI 程序
    7. hellomingw/helloucrt/sha256sum - 有 TLS callbacks，应被 builder 拒绝

所有测试通过返回 0，任一失败返回 1。
"""
import os
import sys
import subprocess
import time
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = os.path.join(os.path.dirname(ROOT), "samples")
TEST_DIR = os.path.join(ROOT, "test")
BUILDER = os.path.join(ROOT, "builder", "builder.exe")
SHA256_TEST = os.path.join(ROOT, "tests", "stub_sha256_test.exe")
GUI_TEST = os.path.join(ROOT, "tools", "gui_test.py")
PYTHON = os.path.join(ROOT, ".venv", "Scripts", "python.exe")

# w64devkit 工具链完整路径（避免 PATH 查找问题）
W64DEVKIT = r"C:\Home\Develop\w64devkit\bin"
MAKE = os.path.join(W64DEVKIT, "make.exe")
GCC = os.path.join(W64DEVKIT, "gcc.exe")

PASS = "\033[92mPASS\033[0m"
FAIL = "\033[91mFAIL\033[0m"
SKIP = "\033[93mSKIP\033[0m"

results = []

def run(cmd, cwd=ROOT, timeout=30, env=None):
    """运行命令，返回 (returncode, stdout+stderr)"""
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                           timeout=timeout, env=env, shell=isinstance(cmd, str))
        return p.returncode, (p.stdout + p.stderr)
    except subprocess.TimeoutExpired:
        return -1, "TIMEOUT"

def make():
    """运行 make 重建 stub.bin 和 builder.exe"""
    env = os.environ.copy()
    env["Path"] = W64DEVKIT + ";" + env.get("Path", "")
    rc, out = run([MAKE], env=env, timeout=60)
    return rc == 0, out

def build_sha256_test():
    """编译 stub_sha256_test.exe"""
    env = os.environ.copy()
    env["Path"] = W64DEVKIT + ";" + env.get("Path", "")
    rc, out = run([GCC, "tests/stub_sha256_test.c", "-O2",
                   "-o", "tests/stub_sha256_test.exe"], env=env)
    return rc == 0, out

def pack(input_exe, output_exe, password=None, test_mode=False):
    """用 builder 加壳（新式参数 -i/-o/-p/-t）"""
    cmd = [BUILDER, "-i", input_exe, "-o", output_exe]
    if test_mode:
        cmd.append("-t")
    elif password:
        cmd.extend(["-p", password])
    rc, out = run(cmd, timeout=30)
    return rc == 0, out

# ---------- 测试用例 ----------

def test_sha256_unit():
    """1. stub_sha256_test 单元测试"""
    name = "stub_sha256_unit"
    if not os.path.exists(SHA256_TEST):
        ok, _ = build_sha256_test()
        if not ok:
            results.append((name, FAIL, "编译失败"))
            return
    rc, out = run([SHA256_TEST], timeout=10)
    if rc == 0 and "ALL PASS" in out:
        # 提取通过数
        m = re.search(r"-> (\d+)/(\d+) passed", out)
        detail = m.group(0) if m else "ok"
        results.append((name, PASS, detail))
    else:
        results.append((name, FAIL, f"exit={rc}"))

def test_hellocli_test_mode():
    """2. hellocli CLI test mode（不弹密码框，硬编码 test123）"""
    name = "hellocli_test_mode"
    src = os.path.join(SAMPLES, "hellocli.exe")
    dst = os.path.join(TEST_DIR, "hellocli_test.exe")
    ok, out = pack(src, dst, test_mode=True)
    if not ok:
        results.append((name, FAIL, "builder 失败"))
        return
    rc, out = run([dst], timeout=5)
    if rc == 0 and "Hello World!" in out:
        results.append((name, PASS, f"输出: {out.strip()}"))
    else:
        results.append((name, FAIL, f"exit={rc}, out={out.strip()}"))

def test_hellogui_correct_pwd():
    """3. hellogui GUI 正常模式 + 正确密码"""
    name = "hellogui_correct_pwd"
    src = os.path.join(SAMPLES, "hellogui.exe")
    dst = os.path.join(TEST_DIR, "hellogui_locked.exe")
    ok, out = pack(src, dst, password="hello123")
    if not ok:
        results.append((name, FAIL, "builder 失败"))
        return
    rc, out = run([PYTHON, GUI_TEST, dst, "hello123",
                   "--main-title", "win32helloword", "--timeout", "10"],
                  timeout=30)
    if rc == 0:
        results.append((name, PASS, "主窗口出现"))
    else:
        # 提取最后一行非空输出
        lines = [l for l in out.splitlines() if l.strip()]
        last = lines[-1] if lines else ""
        results.append((name, FAIL, last[:80]))

def test_hellogui_wrong_pwd():
    """4. hellogui GUI 错误密码路径"""
    name = "hellogui_wrong_pwd"
    src = os.path.join(SAMPLES, "hellogui.exe")
    dst = os.path.join(TEST_DIR, "hellogui_locked.exe")
    # 复用已加壳的
    if not os.path.exists(dst):
        ok, out = pack(src, dst, password="hello123")
        if not ok:
            results.append((name, FAIL, "builder 失败"))
            return
    rc, out = run([PYTHON, GUI_TEST, dst, "hello123",
                   "--main-title", "win32helloword",
                   "--wrong-pwd", "wrongpwd", "--timeout", "10"],
                  timeout=30)
    if rc == 0:
        results.append((name, PASS, "错误密码弹框 + 重试成功"))
    else:
        lines = [l for l in out.splitlines() if l.strip()]
        last = lines[-1] if lines else ""
        results.append((name, FAIL, last[:80]))

def test_dontsleep():
    """5. DontSleep 真实第三方 GUI 程序"""
    name = "dontsleep_real"
    src = os.path.join(SAMPLES, "DontSleep.exe")
    dst = os.path.join(TEST_DIR, "DontSleep_locked.exe")
    ok, out = pack(src, dst, password="hello123")
    if not ok:
        results.append((name, FAIL, "builder 失败"))
        return
    rc, out = run([PYTHON, GUI_TEST, dst, "hello123",
                   "--main-title", "Don't Sleep", "--timeout", "15"],
                  timeout=40)
    if rc == 0:
        results.append((name, PASS, "主窗口出现"))
    else:
        lines = [l for l in out.splitlines() if l.strip()]
        last = lines[-1] if lines else ""
        results.append((name, FAIL, last[:80]))

def test_notepad4():
    """6. Notepad4 真实第三方 GUI 程序"""
    name = "notepad4_real"
    src = os.path.join(SAMPLES, "Notepad4.exe")
    dst = os.path.join(TEST_DIR, "Notepad4_locked.exe")
    ok, out = pack(src, dst, password="hello123")
    if not ok:
        results.append((name, FAIL, "builder 失败"))
        return
    rc, out = run([PYTHON, GUI_TEST, dst, "hello123",
                   "--main-class", "Notepad4", "--timeout", "15"],
                  timeout=40)
    if rc == 0:
        results.append((name, PASS, "主窗口出现"))
    else:
        lines = [l for l in out.splitlines() if l.strip()]
        last = lines[-1] if lines else ""
        results.append((name, FAIL, last[:80]))

def test_bandizip():
    """7. Bandizip 真实第三方 GUI 程序（带 ASLR + 大 .text 节，输出到源目录）"""
    name = "bandizip_real"
    src = r"C:\Home\Tools\Bandizip\Bandizip.x64.exe"
    dst = r"C:\Home\Tools\Bandizip\Bandizip.x64_locked.exe"
    if not os.path.exists(src):
        results.append((name, SKIP, f"找不到 {src}"))
        return
    ok, out = pack(src, dst, password="hello123")
    if not ok:
        results.append((name, FAIL, "builder 失败"))
        return
    rc, out = run([PYTHON, GUI_TEST, dst, "hello123",
                   "--main-title", "Bandizip", "--timeout", "20"],
                  timeout=45)
    if rc == 0:
        results.append((name, PASS, "主窗口出现"))
    else:
        lines = [l for l in out.splitlines() if l.strip()]
        last = lines[-1] if lines else ""
        results.append((name, FAIL, last[:80]))

def test_tls_rejected():
    """7. 有 TLS callbacks 的样本应被 builder 拒绝"""
    name = "tls_rejected"
    rejected = []
    not_rejected = []
    for s in ["hellomingw", "helloucrt", "sha256sum"]:
        src = os.path.join(SAMPLES, f"{s}.exe")
        dst = os.path.join(TEST_DIR, f"{s}_should_fail.exe")
        ok, out = pack(src, dst, password="hello123")
        if ok:
            # builder 没拒绝，是问题
            not_rejected.append(s)
        else:
            if "TLS callbacks" in out:
                rejected.append(s)
            else:
                not_rejected.append(f"{s}(其他原因)")
    if not_rejected:
        results.append((name, FAIL, f"未拒绝: {not_rejected}"))
    else:
        results.append((name, PASS, f"全部拒绝: {rejected}"))

# ---------- 主 ----------

def main():
    print("=" * 70)
    print("WinLock 综合端到端测试")
    print("=" * 70)
    print()

    # 0. 重建
    print("[0] 重建 stub.bin + builder.exe ...")
    ok, out = make()
    if not ok:
        print(f"  make 失败:\n{out}")
        return 1
    print("  make OK")

    # 1-8
    tests = [
        test_sha256_unit,
        test_hellocli_test_mode,
        test_hellogui_correct_pwd,
        test_hellogui_wrong_pwd,
        test_dontsleep,
        test_notepad4,
        test_bandizip,
        test_tls_rejected,
    ]
    for t in tests:
        print(f"\n[{t.__doc__.split('.')[0].strip()}] {t.__name__}")
        t()
        name, status, detail = results[-1]
        print(f"  -> {status} {detail}")

    # 汇总
    print()
    print("=" * 70)
    print("测试汇总")
    print("=" * 70)
    npass = sum(1 for _, s, _ in results if s == PASS)
    nfail = sum(1 for _, s, _ in results if s == FAIL)
    for name, status, detail in results:
        # 去除 ANSI 颜色用于显示宽度
        status_plain = status.replace("\033[92m", "").replace("\033[91m", "").replace("\033[0m", "")
        print(f"  [{status_plain}] {name:30s} {detail}")
    print()
    print(f"总计: {npass} PASS, {nfail} FAIL")
    return 0 if nfail == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
