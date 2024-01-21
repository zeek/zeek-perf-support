#pragma once
#include <sys/mman.h>
#include <zeek/plugin/Plugin.h>

namespace zeek::plugin {
namespace Zeek_PerfSupport {

class Plugin : public zeek::plugin::Plugin {
protected:
    zeek::plugin::Configuration Configure() override;
    void InitPostScript() override;
    void Done() override;

    void InstallTrampolines();

private:
    void* trampoline_space = MAP_FAILED;
    size_t trampoline_space_sz = 0;
};

extern Plugin plugin;

} // namespace Zeek_PerfSupport
} // namespace zeek::plugin
