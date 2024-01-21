# @TEST-EXEC: bash %INPUT
# @TEST-EXEC: btest-diff output

set -eux

ZEEKPERFSUPPORT=1 zeek -e 'event zeek_init() {}' &
PID=$!
wait $PID
MAP_FN="/tmp/perf-${PID}.map"

if [ -f "${MAP_FN}" ]; then
    echo "PASS: found map file" >>output
else
    echo "FAIL: no perf-${PID}.map file found" >&2
fi

if grep -q zeek_init "${MAP_FN}"; then
    echo "PASS: found zeek_init" >>output
else
    echo "FAIL: zeek_init not in map file" >&2
fi

