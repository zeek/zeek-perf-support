# @TEST-DOC: Use a fairly advanced when() construct to tickle ZAM into throwing a ZAMDelayedCallException and ensure it's caught and re-raised.
# @TEST-EXEC: bash %INPUT
# @TEST-EXEC: btest-diff output

set -eux

ZEEKPERFSUPPORT=1 zeek --parse-only ./test.zeek
ZEEKPERFSUPPORT=1 zeek -O ZAM ./test.zeek > output 2>&1 &
PID=$!
wait $PID
echo $?
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


@TEST-START-FILE test.zeek
redef exit_only_after_terminate = T;

global tbl: table[string] of string;

event insert() {
    tbl["x"] = "now";
}

event insert_trampoline() {
    print "trampoline";
    schedule 10msec { insert() };
}

event do_terminate() {
    terminate();
}

function f(): string {
    return when ( "x" in tbl ) {
        return tbl["x"];
    }
}

event zeek_init() {
    when ( local r = f() ) {
        print "gotcha", r, tbl;
        schedule 10msec { do_terminate() };
    }

    schedule 10msec { insert_trampoline() };

    schedule 5000msec { do_terminate() };
    }
@TEST-END-FILE
