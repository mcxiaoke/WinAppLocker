; ============================================================
; stub_asm_x64.asm - x64 jump_to_oep 实现（MSVC MASM 语法）
;
; 背景：
;   MSVC x64 不支持内联汇编（GCC 的 __asm__ volatile 无法使用），
;   必须用独立 .asm 文件 + ml64.exe 编译为 .obj，再与 stub.c 的 .obj 链接。
;
; 功能：
;   跳转到原 PE 的 OEP（Original Entry Point），不返回。
;   - 16 字节对齐 RSP（Windows x64 ABI 要求）
;   - 预留 32 字节 shadow space + 8 字节对齐 = 40 字节
;   - 用 jmp 而非 call，不压入返回地址（stub 永不返回）
;
; 入口签名：void jump_to_oep_x64(void* oep);
;   x64 ABI: RCX = 第一个参数 = oep
;
; 节区：
;   必须放进 .text2$text 节（与 stub.c 的 #pragma code_seg(".text2$text") 一致），
;   否则 link.exe 会把它放进默认 .text 节，extract_lock_section.py 不会提取，
;   导致 stub.bin 缺失此函数，stub 运行时跳到 .text2 节里的 padding 区域崩溃。
;
;   MASM 用 SEGMENT ALIAS 指定实际 COFF 节名（节名含 $ 等特殊字符时必须用 ALIAS）。
;   link.exe 按 COFF $ 分组规则把 .text2$text 自动合并到 .text2 节。
;
; 参考：MSVC_PORTING_PLAN.md 第 275-285 行
;       MSVC_PORRINT_AND_PIC_SPEC.md 阶段 3 批 3
; ============================================================

; 用 SEGMENT 关键字 + ALIAS 把函数放进 .text2$text 节
; ALIAS 指定实际 COFF 节名（可以含 $ 等特殊字符）
locktext SEGMENT READ EXECUTE ALIAS('.text2$text')

; void jump_to_oep_x64(void* oep /*RCX*/);
jump_to_oep_x64 PROC
    and  rsp, -16        ; 16 字节对齐（清除 RSP 低 4 位）
    sub  rsp, 40         ; 32B shadow space + 8 对齐 = RSP ≡ 8 mod 16
                        ; （OEP 用 call 进入时栈布局假设）
    jmp  rcx            ; 跳到 OEP（jmp 不压返回地址，stub 永不返回）
jump_to_oep_x64 ENDP

locktext ENDS

; ============================================================
; stub_tls_callback + g_stub_tls_cb_marker（MSVC 特有方案）
;
; 问题：MSVC link.exe 不合并不同 flag 的 $ 子节
;   - .text2$tlscbm 是 const data (flags 0x40000040, read-only)
;   - .text2$tlscb 是 code (flags 0x60000020, read+execute)
;   导致 marker 和 function 分到不同 .text2 输出节，
;   builder.c 的 find_stub_tls_cb_offset 假设 function = magic + 16 失效。
;
; 解决：用 .asm 把 marker 和 function 放进同一个 .text2$tlscb SEGMENT
;   (READ EXECUTE)，保证 marker + 16 = function 的布局。
;   MinGW 仍用 stub.c 中的 C 定义 + stub.ld 的 KEEP() 保证顺序。
;
; 注意：
;   - marker 必须在 8 字节对齐处（builder.c 按 8 字节对齐搜索 magic）
;   - stub_tls_callback 是空实现，所有工作推到 stub_entry 完成
;   - x64 调用约定统一，RET 不清栈
;   - stub_tls_callback 必须用 /INCLUDE:stub_tls_callback 强制保留
;     （未被 stub.c 引用，/OPT:REF 会移除）
; ============================================================
locktlscb SEGMENT READ EXECUTE ALIAS('.text2$tlscb')

; g_stub_tls_cb_marker: 8 字节 magic + 8 字节 zero pad = 16 字节
; STUB_TLS_CB_MAGIC = 0x424C4C4143534C54ULL ("TLSCALLB" 小端)
PUBLIC g_stub_tls_cb_marker
g_stub_tls_cb_marker DQ 0424C4C4143534C54h
                     DQ 0

; stub_tls_callback 函数入口（紧跟 marker+16）
; 空实现：直接返回（所有工作推到 stub_entry 完成）
PUBLIC stub_tls_callback
stub_tls_callback PROC
    ret
stub_tls_callback ENDP

locktlscb ENDS

END
