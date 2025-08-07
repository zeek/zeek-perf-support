# @TEST-EXEC: bash %INPUT

set -x

ZEEKPERFSUPPORT=0 zeek -e 'event zeek_init() { print(1/0); }' &> output_disabled
result_disabled=$?

ZEEKPERFSUPPORT=1 zeek -e 'event zeek_init() { print(1/0); }' &> output_enabled
result_enabled=$?

# If the program aborts the return codes are not going to be the same.
[[ $result_disabled == $result_enabled ]] && cmp output_disabled output_enabled
