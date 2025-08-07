// See src/Trampoline.cc and the print-trampoline top-level Makefile target
// for where this assembly code is coming from.
.text
.globl  _Zeek_trampoline_func_start

// zeek::Val* _Zeek_trampoline(zeek::detail::Stmt* stmt, zeek::detail::Frame* frame, zeek::detail::StmtFlowType* flow,
//                             zeek::SuspendedException* exc, exec_stmt_func_t esf) {
//     return esf(stmt, frame, flow, exc);
// }
//
// RDI: stmt
// RSI: frame
// RDX: flow
// RCX: exc
// R8 : esf
//
_Zeek_trampoline_func_start:
#ifdef __x86_64__
    endbr64
    pushq   %rbp
    movq    %rsp, %rbp
    call    *%r8
    popq    %rbp
    ret
#endif
#if defined(__aarch64__) && defined(__AARCH64EL__) && !defined(__ILP32__)
    stp     x29, x30, [sp, -16]!
    mov     x29, sp
    blr     x4
    ldp     x29, x30, [sp], 16
    ret
#endif

.globl  _Zeek_trampoline_func_end
_Zeek_trampoline_func_end:
    nop
