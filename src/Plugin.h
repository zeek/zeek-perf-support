#pragma once
#include <sys/mman.h>
#include <zeek/plugin/Plugin.h>
#include <zeek/zeek-version.h>

namespace zeek::plugin {
namespace Zeek_PerfSupport {

class Plugin : public zeek::plugin::Plugin {
protected:
    zeek::plugin::Configuration Configure() override;

    // For 7.1 or later, there's a InitPreExecution() so that
    // it's possible to trampoline into ZAMBody statements.
#if ZEEK_VERSION_NUMBER >= 70100
    void InitPreExecution() override { InstallTrampolinesIfEnabled(); };
#else
    void InitPostScript() override { InstallTrampolinesIfEnabled(); };
#endif
    void Done() override;


private:
    void InstallTrampolinesIfEnabled();
    void InstallTrampolines();

    void* trampoline_space = MAP_FAILED;
    size_t trampoline_space_sz = 0;
};

extern Plugin plugin;

} // namespace Zeek_PerfSupport
} // namespace zeek::plugin
