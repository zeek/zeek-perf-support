// Inspiration from the Python version, but totally hacked together.
//
// https://github.com/python/cpython/pull/96123/files
#include "Plugin.h"

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/unistd.h>
#include <zeek/Func.h>
#include <zeek/ID.h>
#include <zeek/Stmt.h>
#include <zeek/StmtEnums.h>
#include <zeek/Traverse.h>
#include <zeek/TraverseTypes.h>
#include <zeek/util.h>
#include <cstdlib>
#include <memory>
#include <set>

#include "config.h"

namespace zeek::plugin::Zeek_PerfSupport {
Plugin plugin;
}

using namespace zeek::plugin::Zeek_PerfSupport;

#define debug(...) PLUGIN_DBG_LOG(plugin, __VA_ARGS__)


namespace {

extern "C" {

// Use raw pointers so that the x86-64 calling convention is simple.
typedef zeek::Val* (*exec_stmt_func_t)(zeek::detail::Stmt* stmt, zeek::detail::Frame* frame,
                                       zeek::detail::StmtFlowType* flow);
typedef zeek::Val* (*trampoline_func_t)(zeek::detail::Stmt* stmt, zeek::detail::Frame* frame,
                                        zeek::detail::StmtFlowType* flow, exec_stmt_func_t callback);

// This is the callback invoked by the trampoline. It'll show up in the callstack, but should be easy
// enough to filter out. Invoking the Exec() member function via assembly looks like insanity.
zeek::Val* _Zeek_PerfSupport_stmt_exec(zeek::detail::Stmt* stmt, zeek::detail::Frame* frame,
                                       zeek::detail::StmtFlowType* flow) {
    return stmt->Exec(frame, *flow).release();
}

// These are defined in Trampoline.S and a copy is created for each ScriptFunc body.
extern zeek::Val* _Zeek_trampoline_func_start(zeek::detail::Stmt* stmt, zeek::detail::Frame* frame,
                                              zeek::detail::StmtFlowType* flow, exec_stmt_func_t callback);
extern void _Zeek_trampoline_func_end();
}

/**
 * Traverse the AST and collect all Zeek script functions.
 */
class FuncCollector : public zeek::detail::TraversalCallback {
public:
    virtual zeek::detail::TraversalCode PostFunction(const zeek::Func* func) {
        if ( func->GetKind() != zeek::Func::SCRIPT_FUNC )
            return zeek::detail::TC_CONTINUE;

        funcs.insert(func);
        return zeek::detail::TC_CONTINUE;
    }

    // Avoid endless type recursion!
    virtual zeek::detail::TraversalCode PreType(const zeek::Type* t) {
        if ( types.count(t) > 0 )
            return zeek::detail::TC_ABORTSTMT;

        types.insert(t);
        return zeek::detail::TC_CONTINUE;
    }

    std::set<const zeek::Type*> types;
    std::set<const zeek::Func*> funcs;
};

namespace {

#if ZEEK_VERSION_NUMBER < 70000
zeek::detail::StmtTag stmt_tag = zeek::detail::STMT_ANY;
#else
zeek::detail::StmtTag stmt_tag = zeek::detail::STMT_EXTERN;
#endif
} // namespace

/**
 * Stmt subclass that diverts execution through the given trampoline function.
 */
class TrampolineStmt : public zeek::detail::Stmt {
public:
    TrampolineStmt(zeek::detail::StmtPtr orig_stmt, trampoline_func_t trampoline)
        : Stmt(stmt_tag), orig_stmt(orig_stmt), trampoline(trampoline) {}

    zeek::ValPtr Exec(zeek::detail::Frame* frame, zeek::detail::StmtFlowType& flow) override {
        // debug("Trampoline start orig_stmt=%p frame=%p flow=%p trampoline=%p callback=%p", orig_stmt.get(), frame,
        // &flow,
        //      trampoline, callback);
        return zeek::IntrusivePtr{zeek::AdoptRef{},
                                  trampoline(orig_stmt.get(), frame, &flow, _Zeek_PerfSupport_stmt_exec)};
    }

    zeek::detail::TraversalCode Traverse(zeek::detail::TraversalCallback* cb) const override {
        return orig_stmt->Traverse(cb);
    }

    // This is something ZAM related and probably borked this way.
    zeek::detail::StmtPtr Duplicate() override { return orig_stmt->Duplicate(); }

private:
    const zeek::detail::StmtPtr orig_stmt;
    trampoline_func_t trampoline;
};

// Allocate executable memory for the trampolines.
std::pair<void*, size_t> mmap_trampoline_memory(size_t nbodies, size_t trampoline_alloc_sz) {
    int page_sz = sysconf(_SC_PAGE_SIZE);
    size_t mmap_sz = ((nbodies * trampoline_alloc_sz) / page_sz + 1) * page_sz;

    void* addr = mmap(NULL, mmap_sz, PROT_EXEC | PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    return {addr, mmap_sz};
}

// Open a file named /tmp/perf-<pid>.map.
//
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/perf/Documentation/jit-interface.txt
FILE* open_map_file() {
    std::string fn = zeek::util::fmt("/tmp/perf-%d.map", getpid());
    FILE* f = fopen(fn.c_str(), "w");
    if ( ! f ) {
        return nullptr;
    }
    return f;
}

// Format the name for a function and top-level Stmt.
//
// <prefix><function_name>:<filename>:<first_line>
std::string format_map_entry(const std::string& prefix, const zeek::Func* f, const zeek::detail::StmtPtr& stmt) {
    const auto* loc = stmt->GetLocationInfo();
#if ZEEK_VERSION < 80000
    auto fn = zeek::util::detail::without_zeekpath_component(loc->filename);
    std::string loc_str = zeek::util::fmt("%s:%d", fn.c_str(), loc->first_line);
#else
    auto fn = zeek::util::detail::without_zeekpath_component(loc->FileName());
    std::string loc_str = zeek::util::fmt("%s:%d", fn.c_str(), loc->FirstLine());
#endif

#if ZEEK_VERSION_NUMBER < 70100
    const char* name = f->Name();
#else
    const char* name = f->GetName().c_str();
#endif

    return zeek::util::fmt("%s%s:%s", prefix.c_str(), name, loc_str.c_str());
}

} // namespace

zeek::plugin::Configuration Plugin::Configure() {
    zeek::plugin::Configuration config;
    config.name = "Zeek::PerfSupport";
    config.description = "Produce map files for perf's JIT interface";
    config.version.major = VERSION_MAJOR;
    config.version.minor = VERSION_MINOR;
    config.version.patch = VERSION_PATCH;
    return config;
}

void Plugin::InstallTrampolinesIfEnabled() {
    const auto& enable = zeek::id::find_val<zeek::BoolVal>("PerfSupport::enable");
    const auto* env = std::getenv("ZEEKPERFSUPPORT");

    if ( enable->AsBool() || (env && ! zeek::util::streq(env, "0")) )
        InstallTrampolines();
}

void Plugin::Done() {
    // umap
    if ( trampoline_space != MAP_FAILED ) {
        munmap(trampoline_space, trampoline_space_sz);
        trampoline_space = MAP_FAILED;
    }
}

void Plugin::InstallTrampolines() {
    FuncCollector func_collector;
    zeek::detail::traverse_all(&func_collector);

    const auto& prefix_val = zeek::id::find_val<zeek::StringVal>("PerfSupport::prefix");
    const auto prefix = prefix_val->ToStdString();

    struct FileCloser {
        void operator()(FILE* f) noexcept { fclose(f); };
    };

    std::unique_ptr<FILE, FileCloser> mapf{open_map_file()};
    if ( ! mapf ) {
        zeek::reporter->Warning("Failed to open perf map file");
        return;
    }

    size_t nbodies = 0;
    for ( const auto* f : func_collector.funcs )
        nbodies += f->GetBodies().size();

    size_t trampoline_sz =
        reinterpret_cast<char*>(_Zeek_trampoline_func_end) - reinterpret_cast<char*>(_Zeek_trampoline_func_start);
    size_t trampoline_alloc_sz = (trampoline_sz / 16 + 1) * 16;

    debug("Trampoline %p-%p sz=%zu alloc_sz=%zu", _Zeek_trampoline_func_start, _Zeek_trampoline_func_end, trampoline_sz,
          trampoline_alloc_sz);

    std::tie(trampoline_space, trampoline_space_sz) = mmap_trampoline_memory(nbodies, trampoline_alloc_sz);
    if ( trampoline_space == MAP_FAILED ) {
        zeek::reporter->Warning("No mmap space for trampolines %s", strerror(errno));
        return;
    }

    debug("Allocated %zu bytes of executable trampoline memory at %p", trampoline_space_sz, trampoline_space);

    void* trampoline_offset = trampoline_space;

    for ( const auto* f : func_collector.funcs ) {
        const auto* csf = static_cast<const zeek::detail::ScriptFunc*>(f);

        // Calling ReplaceBody() requires non-const version.
        auto* sf = const_cast<zeek::detail::ScriptFunc*>(csf);

        for ( const auto& b : f->GetBodies() ) {
            // Copy this statement's own trampoline function in place.
            memcpy(trampoline_offset, reinterpret_cast<void*>(_Zeek_trampoline_func_start), trampoline_sz);

            auto entry = format_map_entry(prefix, f, b.stmts);
            std::string map_entry = zeek::util::fmt("%p %zx %s\n", trampoline_offset, trampoline_sz, entry.c_str());
            size_t n = fwrite(map_entry.c_str(), 1, map_entry.size(), mapf.get());
            if ( n != map_entry.size() )
                zeek::reporter->Warning("failed to write map entry %zu vs %zu", n, map_entry.size());

            // Now replace the statement!
            auto* body_trampoline_func = reinterpret_cast<trampoline_func_t>(trampoline_offset);
            auto trampoline_stmt = zeek::make_intrusive<TrampolineStmt>(b.stmts, body_trampoline_func);
            sf->ReplaceBody(b.stmts, trampoline_stmt);

            trampoline_offset = static_cast<char*>(trampoline_offset) + trampoline_alloc_sz;
        }
    }
}
