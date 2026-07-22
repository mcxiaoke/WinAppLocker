; ============================================================
; loader_asm_x64.asm - x64 jump_to_oep 实现（MSVC MASM 语法）
;
; 背景：
;   MSVC x64 不支持内联汇编（GCC 的 __asm__ volatile 无法使用），
;   必须用独立 .asm 文件 + ml64.exe 编译为 .obj，再与 loader.c 链接。
;
; 功能（与 loader.c 的 GCC 内联汇编版本等价）：
;   跳转到原 PE 的 OEP（Original Entry Point），用 push + jmp 模拟 call，
;   压入返回地址（oep_returned），这样原 PE 内的 C++ 异常 dispatch 能正确
;   unwind 到本 stub 帧，不会因找不到 caller 而 terminate
;   （修复 DontSleep/MFC42u 崩溃问题）。
;
;   - 16 字节对齐 RSP（Windows x64 ABI 要求）
;   - push rdx 压入返回地址（RSP -= 8，RSP % 16 == 8 ✓ 符合 ABI 入口约束）
;   - jmp rcx 跳到 OEP（不压返回地址，用 push 预先压入）
;   - 不返回（OEP return 后通过 push 的返回地址回到 oep_returned）
;
; 入口签名：void jump_to_oep_x64(void* oep /*RCX*/, void* ret_addr /*RDX*/);
;   x64 ABI: RCX = 第一个参数 = oep
;            RDX = 第二个参数 = ret_addr
;
; 节区：
;   loader 是普通 PE（不做节区提取），用默认 .text 段即可。
;   不需要像 stub 那样放进 .text2$text 节。
;
; 参考：MSVC_PORRINT_AND_PIC_SPEC.md 阶段 4 步骤 C
; ============================================================

; 用默认 .text 段（loader 不做节区提取，普通 PE 布局）
.code

; void jump_to_oep_x64(void* oep /*RCX*/, void* ret_addr /*RDX*/);
jump_to_oep_x64 PROC
    and  rsp, -16        ; 16 字节对齐（清除 RSP 低 4 位，RSP % 16 == 0）
    push rdx             ; 压入返回地址（RSP -= 8，RSP % 16 == 8 ✓ ABI 入口约束）
    jmp  rcx            ; 跳到 OEP（jmp 不再压返回地址，用 push 预先压入）
jump_to_oep_x64 ENDP

END
