; ============================================================
; stub_asm_x86.asm - x86 jump_to_oep 实现（MSVC MASM 语法）
;
; 功能：
;   跳转到原 PE 的 OEP，不返回。
;   - 16 字节对齐 ESP（避免 SSE 指令对齐异常，CRT 启动代码可能要求）
;   - 用 jmp 而非 call，不压入返回地址
;
; 入口签名：void __cdecl jump_to_oep_x86(void* oep);
;   x86 __cdecl: [esp+4] = 第一个参数 = oep
;
; 节区：
;   必须放进 .lock$text 节（与 x64 同样的问题），
;   否则 MASM 默认 .code 段会被 link.exe 放进 .text 节，
;   extract_lock_section.py 不提取 .text，stub.bin 缺失此函数，
;   stub 运行时跳到 .lock padding 区域崩溃（AV 0xC0000005）。
;
;   MASM x86 SEGMENT ALIAS 用法与 x64 一致：指定实际 COFF 节名
;   （含 $ 等特殊字符时必须用 ALIAS），link.exe 按 $ 分组规则合并到 .lock。
;
; 注意：
;   x86 MASM 的符号名需前导下划线（_jump_to_oep_x86），
;   与 __cdecl 调用约定的 name decoration 一致。
; ============================================================

.586
.model flat

; 用 SEGMENT 关键字 + ALIAS 把函数放进 .lock$text 节
locktext SEGMENT READ EXECUTE ALIAS('.lock$text')

; void __cdecl jump_to_oep_x86(void* oep /*[esp+4]*/);
_jump_to_oep_x86 PROC
    mov  eax, [esp+4]   ; 取参数 oep
    and  esp, -16       ; 16 字节对齐（清除 ESP 低 4 位）
    jmp  eax            ; 跳到 OEP（不压返回地址）
_jump_to_oep_x86 ENDP

locktext ENDS

; ============================================================
; stub_tls_callback + g_stub_tls_cb_marker（MSVC 特有方案）
;
; 问题：MSVC link.exe 不合并不同 flag 的 $ 子节
;   - .lock$tlscbm 是 const data (flags 0x40000040, read-only)
;   - .lock$tlscb 是 code (flags 0x60000020, read+execute)
;   导致 marker 和 function 分到不同 .lock 输出节，
;   builder.c 的 find_stub_tls_cb_offset 假设 function = magic + 16 失效。
;
; 解决：用 .asm 把 marker 和 function 放进同一个 .lock$tlscb SEGMENT
;   (READ EXECUTE)，保证 marker + 16 = function 的布局。
;   MinGW 仍用 stub.c 中的 C 定义 + stub.ld 的 KEEP() 保证顺序。
;
; 注意：
;   - marker 必须在 8 字节对齐处（builder.c 按 8 字节对齐搜索 magic）
;   - stub_tls_callback 是空实现，所有工作推到 stub_entry 完成
;   - x86 WINAPI(stdcall) 3 个 DWORD 参数 = 12 字节，用 RET 12 清栈
;   - x86 stdcall decoration: _name@N，符号名为 _stub_tls_callback@12
;   - stub_tls_callback 必须用 /INCLUDE:_stub_tls_callback@12 强制保留
;     （未被 stub.c 引用，/OPT:REF 会移除）
; ============================================================
locktlscb SEGMENT READ EXECUTE ALIAS('.lock$tlscb')

; g_stub_tls_cb_marker: 8 字节 magic + 8 字节 zero pad = 16 字节
; STUB_TLS_CB_MAGIC = 0x424C4C4143534C54ULL ("TLSCALLB" 小端)
PUBLIC _g_stub_tls_cb_marker
_g_stub_tls_cb_marker DQ 0424C4C4143534C54h
                      DQ 0

; stub_tls_callback 函数入口（紧跟 marker+16）
; 空实现：直接返回（所有工作推到 stub_entry 完成）
; x86 WINAPI(stdcall): 3 个 DWORD 参数 = 12 字节，被调用方清栈用 RET 12
PUBLIC _stub_tls_callback@12
_stub_tls_callback@12 PROC
    ret 12
_stub_tls_callback@12 ENDP

locktlscb ENDS

END
