# @TEST-EXEC: zeek -NN Zeek::PerfSupport |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
