"""
test_e2e_msvc.py - 端到端验证 MSVC x64 + x86 迁移

测试矩阵（8 个样本，每个样本测 inplace + reflective 两种模式）：
    1. Notepad4.exe       (GUI x64, 真实第三方程序)
    2. DontSleep.exe      (GUI x64, CFG 启用，曾导致 fallback_relocations 4-byte 扫描 bug)
    3. helloguix64.exe    (GUI x64)
    4. helloguix86.exe    (GUI x86)
    5. hellocli.exe       (CLI x64)
    6. hellomingw.exe     (CLI MinGW, 有 TLS callbacks)
    7. helloucrt.exe      (CLI UCRT)
    8. ddccli.exe         (CLI)

每个样本：
  - inplace 加壳 (-t 测试模式，跳过密码框)
  - reflective 加壳
  - 启动后等待 3 秒
  - 检查进程没立即 crash（exit code != 0 表示 crash）

用法:
    python tests/test_e2e_msvc.py
"""
import os
import sys
import time
import subprocess

# ---- 路径配置 ----
REPO_ROOT = r"C:\Home\Projects\applocker"
DIST_DIR = os.path.join(REPO_ROOT, "packer", "dist")
SAMPLES_DIR = os.path.join(REPO_ROOT, "temp", "samples")
OUT_DIR = os.path.join(REPO_ROOT, "temp", "e2e_msvc")

BUILDER_INPLACE = os.path.join(DIST_DIR, "builder_inplace.exe")
BUILDER_REFLECTIVE = os.path.join(DIST_DIR, "builder_reflective.exe")

# ---- 测试样本 ----
# (name, type, window_or_output_match)
#   type: "GUI" / "CUI"
#   match: GUI 用窗口标题关键字，CUI 用 stdout 关键字
SAMPLES = [
    ("Notepad4.exe",     "GUI", "Notepad4"),
    ("DontSleep.exe",    "GUI", "DontSleep"),
    ("helloguix64.exe",  "GUI", "Hello"),
    ("helloguix86.exe",  "GUI", "hello"),
    ("hellocli.exe",     "CUI", "Hello"),
    ("hellomingw.exe",   "CUI", "Hello"),
    ("helloucrt.exe",    "CUI", "Hello"),
    ("ddccli.exe",       "CUI", None),  # 无固定输出，只检查不 crash
]


# ---- 工具函数 ----

def run(cmd, timeout=30, cwd=None):
    """运行命令，返回 (returncode, stdout+stderr)"""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, cwd=cwd)
        return p.returncode, (p.stdout + p.stderr)
    except subprocess.TimeoutExpired:
        return -1, "TIMEOUT"


def pack_inplace(in_path, out_path):
    """inplace 加壳：用 -t 测试模式（硬编码密码 test1234，跳过密码框）
    builder_inplace.exe -i <in> -o <out> -t --stub-dir <dist>
    --stub-dir 让 builder 找到 stub_inplace_xXX.bin"""
    cmd = [BUILDER_INPLACE, "-i", in_path, "-o", out_path, "-t",
           "--stub-dir", DIST_DIR]
    return run(cmd, timeout=30)


def pack_reflective(in_path, out_path):
    """reflective 加壳：用 -t 测试模式
    builder_reflective.exe <in> <out> --stub <stub_reflective_xXX.exe> -t
    --stub 显式指定 stub 路径"""
    # 根据输入 PE 的架构选 stub（builder 内部会判断，但我们直接传 x64 stub，
    # 让 builder 自己根据 input PE 的 Machine 字段选；如果传错的 stub 会失败）
    # 简单起见，用 --stub-dir 不行（reflective 用 --stub），所以让 builder 自己选
    # builder_reflective.c 中：如果不传 --stub，按 input PE 架构自动选
    # 但默认路径是 stub_reflective_xXX.exe 在当前目录，所以工作目录设为 DIST_DIR
    cmd = [BUILDER_REFLECTIVE, in_path, out_path, "-t"]
    return run(cmd, timeout=30, cwd=DIST_DIR)


def launch_and_check(exe_path, exe_type, match_keyword, wait_sec=4):
    """启动加壳后的 exe，检查是否 crash
    GUI: 启动后等 wait_sec 秒，进程还活着或正常退出即 PASS
    CUI: 启动后等 wait_sec 秒，检查 stdout 包含 match_keyword（如果有）"""
    try:
        # CUI 程序用 capture_output 捕获 stdout
        # GUI 程序不需要捕获 stdout（通常没有）
        if exe_type == "CUI":
            p = subprocess.Popen([exe_path], stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, cwd=os.path.dirname(exe_path))
        else:
            p = subprocess.Popen([exe_path], cwd=os.path.dirname(exe_path))
    except OSError as e:
        return False, f"launch failed: {e}"

    # 等待一会
    time.sleep(wait_sec)

    # 检查进程状态
    if p.poll() is None:
        # 进程仍在运行（GUI 程序预期行为）
        p.terminate()
        try:
            p.wait(timeout=3)
        except subprocess.TimeoutExpired:
            p.kill()
        return True, "running ok (still alive)"
    else:
        # 进程已退出
        rc = p.returncode
        if exe_type == "CUI":
            try:
                out, err = p.communicate(timeout=1)
                stdout = (out or b"").decode("utf-8", errors="replace")
                stderr = (err or b"").decode("utf-8", errors="replace")
            except subprocess.TimeoutExpired:
                stdout = stderr = ""
            if match_keyword and match_keyword in stdout:
                return True, f"exited rc={rc}, stdout matched '{match_keyword}'"
            if rc == 0:
                return True, f"exited rc=0, stdout={stdout[:80]!r}"
            return False, f"exited rc={rc}, stdout={stdout[:80]!r}, stderr={stderr[:80]!r}"
        else:
            # GUI 程序快速退出 = crash（除非是测试模式立即返回）
            if rc == 0:
                return True, f"exited rc=0 (test mode immediate return)"
            return False, f"exited rc={rc} (likely crash)"


# ---- 主测试逻辑 ----

def main():
    # ---- 0. Clean build 确保使用最新的 stub 和 builder ----
    print("=" * 70)
    print("[BUILD] 清理并重建 packer（MSVC x64 + x86）...")
    print("=" * 70)
    build_ps1 = os.path.join(REPO_ROOT, "packer", "build.ps1")
    rc, out = run(["pwsh", "-File", build_ps1, "-Clean"], timeout=120)
    if rc != 0:
        print(f"[FATAL] build.ps1 failed (rc={rc})")
        print(out)
        return 1
    print("[BUILD] 构建完成")
    print()

    if not os.path.exists(BUILDER_INPLACE):
        print(f"[FATAL] builder_inplace.exe not found: {BUILDER_INPLACE}")
        print("       Run packer/build.ps1 first.")
        return 1
    if not os.path.exists(BUILDER_REFLECTIVE):
        print(f"[FATAL] builder_reflective.exe not found: {BUILDER_REFLECTIVE}")
        print("       Run packer/build.ps1 first.")
        return 1

    if not os.path.exists(OUT_DIR):
        os.makedirs(OUT_DIR)

    print(f"dist/: {DIST_DIR}")
    print(f"samples/: {SAMPLES_DIR}")
    print(f"out/: {OUT_DIR}")
    print()

    results = []  # [(sample, mode, status, msg), ...]

    for sample_name, exe_type, match_kw in SAMPLES:
        in_path = os.path.join(SAMPLES_DIR, sample_name)
        base = os.path.splitext(sample_name)[0]

        print("=" * 70)
        print(f"[{sample_name}] ({exe_type})")
        print("=" * 70)

        if not os.path.exists(in_path):
            print(f"  [SKIP] sample not found")
            results.append((sample_name, "-", "SKIP", "not found"))
            continue

        # ---- inplace 加壳 ----
        print("  [inplace] packing...")
        out_inplace = os.path.join(OUT_DIR, f"{base}_inplace.exe")
        rc, out = pack_inplace(in_path, out_inplace)
        if rc != 0 or not os.path.exists(out_inplace):
            print(f"  [inplace][FAIL] pack rc={rc}")
            for line in out.splitlines()[-3:]:
                print(f"    {line}")
            results.append((sample_name, "inplace", "PACK_FAIL", f"rc={rc}"))
        else:
            size_kb = os.path.getsize(out_inplace) // 1024
            print(f"  [inplace][OK] packed ({size_kb} KB), launching...")
            ok, msg = launch_and_check(out_inplace, exe_type, match_kw)
            status = "PASS" if ok else "RUN_FAIL"
            print(f"  [inplace][{status}] {msg}")
            results.append((sample_name, "inplace", status, msg))

        # ---- reflective 加壳 ----
        print("  [reflective] packing...")
        out_refl = os.path.join(OUT_DIR, f"{base}_reflective.exe")
        rc, out = pack_reflective(in_path, out_refl)
        if rc != 0 or not os.path.exists(out_refl):
            print(f"  [reflective][FAIL] pack rc={rc}")
            for line in out.splitlines()[-3:]:
                print(f"    {line}")
            results.append((sample_name, "reflective", "PACK_FAIL", f"rc={rc}"))
        else:
            size_kb = os.path.getsize(out_refl) // 1024
            print(f"  [reflective][OK] packed ({size_kb} KB), launching...")
            ok, msg = launch_and_check(out_refl, exe_type, match_kw)
            status = "PASS" if ok else "RUN_FAIL"
            print(f"  [reflective][{status}] {msg}")
            results.append((sample_name, "reflective", status, msg))

        print()

    # ---- 汇总 ----
    print("=" * 70)
    print("Summary")
    print("=" * 70)
    print(f"{'Sample':<22} {'Mode':<12} {'Status':<10} {'Message'}")
    print("-" * 70)
    n_pass = 0
    n_fail = 0
    for sample, mode, status, msg in results:
        print(f"{sample:<22} {mode:<12} {status:<10} {msg[:60]}")
        if status == "PASS":
            n_pass += 1
        else:
            n_fail += 1
    print("-" * 70)
    print(f"PASS: {n_pass}  FAIL/SKIP: {n_fail}  Total: {len(results)}")
    return 0 if n_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
