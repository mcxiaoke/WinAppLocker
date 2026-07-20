; ============================================================
; loader_asm_x86.asm - x86 jump_to_oep 实现（MSVC MASM 语法）
;
; 功能（与 loader.c 的 GCC 内联汇编版本等价）：
;   跳转到原 PE 的 OEP，用 push + jmp 模拟 call，
;   压入返回地址（oep_returned），让原 PE 的 SEH 异常能 unwind 回本 stub。
;
;   - 16 字节对齐 ESP（避免 SSE 指令对齐异常）
;   - push ret_addr 压入返回地址
;   - jmp oep 跳到 OEP
;
; 入口签名：void __cdecl jump_to_oep_x86(void* oep, void* ret_addr);
;   x86 __cdecl: [esp+4] = oep, [esp+8] = ret_addr
;
; 节区：
;   loader 是普通 PE，用默认 .text 段即可。
;
; 注意：
;   x86 MASM 的符号名需前导下划线（_jump_to_oep_x86），
;   与 __cdecl 调用约定的 name decoration 一致。
;
; 参考：MSVC_PORRINT_AND_PIC_SPEC.md 阶段 4 步骤 C
; ============================================================

.586
.model flat

.code

; void __cdecl jump_to_oep_x86(void* oep /*[esp+4]*/, void* ret_addr /*[esp+8]*/);
_jump_to_oep_x86 PROC
    mov  eax, [esp+4]   ; 取参数 oep
    mov  ecx, [esp+8]   ; 取参数 ret_addr
    and  esp, -16       ; 16 字节对齐（清除 ESP 低 4 位）
    push ecx            ; 压入返回地址
    jmp  eax            ; 跳到 OEP
_jump_to_oep_x86 ENDP

END
