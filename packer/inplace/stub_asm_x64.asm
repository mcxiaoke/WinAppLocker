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
;   必须放进 .lock$text 节（与 stub.c 的 #pragma code_seg(".lock$text") 一致），
;   否则 link.exe 会把它放进默认 .text 节，extract_lock_section.py 不会提取，
;   导致 stub.bin 缺失此函数，stub 运行时跳到 .lock 节里的 padding 区域崩溃。
;
;   MASM 用 SEGMENT ALIAS 指定实际 COFF 节名（节名含 $ 等特殊字符时必须用 ALIAS）。
;   link.exe 按 COFF $ 分组规则把 .lock$text 自动合并到 .lock 节。
;
; 参考：MSVC_PORTING_PLAN.md 第 275-285 行
;       MSVC_PORRINT_AND_PIC_SPEC.md 阶段 3 批 3
; ============================================================

; 用 SEGMENT 关键字 + ALIAS 把函数放进 .lock$text 节
; ALIAS 指定实际 COFF 节名（可以含 $ 等特殊字符）
locktext SEGMENT READ EXECUTE ALIAS('.lock$text')

; void jump_to_oep_x64(void* oep /*RCX*/);
jump_to_oep_x64 PROC
    and  rsp, -16        ; 16 字节对齐（清除 RSP 低 4 位）
    sub  rsp, 40         ; 32B shadow space + 8 对齐 = RSP ≡ 8 mod 16
                        ; （OEP 用 call 进入时栈布局假设）
    jmp  rcx            ; 跳到 OEP（jmp 不压返回地址，stub 永不返回）
jump_to_oep_x64 ENDP

locktext ENDS

END
