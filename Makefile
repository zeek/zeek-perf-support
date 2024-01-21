default:
	(test -d build || ./configure)
	(cd build && make)
