default:
	(test -d build || ./configure)
	(cd build && make)

CFLAGS ?= -O1

.PHONY: print-trampoline
print-trampoline:
	$(CC) $(CFLAGS) -S -o - -fno-optimize-sibling-calls -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer -c src/Trampoline.cc
