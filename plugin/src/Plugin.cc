#include "config.h"
#include "Plugin.h"

namespace zeek::plugin::Zeek_PerfSupport { Plugin plugin; }

using namespace zeek::plugin::Zeek_PerfSupport;

zeek::plugin::Configuration Plugin::Configure()
	{
	zeek::plugin::Configuration config;
	config.name = "Zeek::PerfSupport";
	config.description = "TODO: Insert description";
	config.version.major = VERSION_MAJOR;
	config.version.minor = VERSION_MINOR;
	config.version.patch = VERSION_PATCH;
	return config;
	}
