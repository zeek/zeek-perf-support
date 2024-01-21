module PerfSupport;

export {
	## Create trampolines for every Zeek function and create a
	## /tmp/perf-<pid>.map file. Setting ZEEKPERFSUPPORT to any
	## value other than "0" also works.
	global enable: bool = F &redef;

	## The prefix to put in front of the function name.
	global prefix: string = "" &redef;
}
