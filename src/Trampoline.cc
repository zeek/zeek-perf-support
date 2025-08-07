namespace zeek {
class Val;
class SuspendedException* exc;
namespace detail {
class Stmt;
class Frame;
class StmtFlowType;
} // namespace detail
} // namespace zeek


typedef zeek::Val* (*exec_stmt_func_t)(zeek::detail::Stmt* stmt, zeek::detail::Frame* frame,
                                       zeek::detail::StmtFlowType* flow, zeek::SuspendedException* exc);


/*
 * This is what the trampoline is meant to do.
 */
zeek::Val* _Zeek_trampoline(zeek::detail::Stmt* stmt, zeek::detail::Frame* frame, zeek::detail::StmtFlowType* flow,
                            zeek::SuspendedException* exc, exec_stmt_func_t esf) {
    return esf(stmt, frame, flow, exc);
}
