Zeek PerfSupport
================

Replaces `ScriptFunc` top-level bodies Stmt's with a Stmt class that diverts execution
through a trampoline (minimal JITing) and produces `/tmp/perf-<pid>.map` files.

Not enabled by default. Run with:

    perf record -g zeek -r ./trace.pcap PerfSupport::enable=T

or

    ZEEKPERFSUPPORT=1 perf record -g zeek -r ./trace.pcap PerfSupport::enable=T

To prefix the functions in the map file "ZEEK:", can redef `PerfSupport::prefix="ZEEK:"`.

![Flamegraph](./example/flame.svg)
