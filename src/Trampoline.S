.text
.globl  _Zeek_trampoline_func_start

// Val*
// _Zeek_trampoline(Stmt* stmt, Frame *frame, StmtFlowType *flow, exec_stmt_func_t* esf) {
//     return esf(stmt, frame, ft);
// }
//
// RDI: stmt
// RSI: frame
// RDX: flow
// RCX: esf
//
_Zeek_trampoline_func_start:
#ifdef __x86_64__
    pushq   %rbp
    movq    %rsp, %rbp
    call    *%rcx
    popq    %rbp
    ret
#endif
#if defined(__aarch64__) && defined(__AARCH64EL__) && !defined(__ILP32__)
    // ARM64 little endian, 64bit ABI
    // generated with aarch64-linux-gnu-gcc 12.3
    stp     x29, x30, [sp, -16]!
    mov     x29, sp
    ldp     x29, x30, [sp], 16
    ldr     x3, [x3]
    mov     x16, x3
    br      x16
#endif

.globl  _Zeek_trampoline_func_end
_Zeek_trampoline_func_end:
    nop
