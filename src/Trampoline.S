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
    sub    $8, %rsp
    call    *%rcx
    add    $8, %rsp
    ret
#endif
#if defined(__aarch64__) && defined(__AARCH64EL__) && !defined(__ILP32__)
#error "Unsupported, but this this should work just work, like for Python"
    // ARM64 little endian, 64bit ABI
    // generate with aarch64-linux-gnu-gcc 12.1
    stp     x29, x30, [sp, -16]!
    mov     x29, sp
    blr     x3
    ldp     x29, x30, [sp], 16
    ret
#endif

.globl  _Zeek_trampoline_func_end
_Zeek_trampoline_func_end:
    nop
