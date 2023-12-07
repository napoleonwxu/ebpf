APPS= xdp-proxy
INCLUDES := -Ilibbpf/usr/include -I../libbpf/include/uapi -I.

.PHONY: all
all: $(APPS)

$(APPS):
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu -I. -c $@.bpf.c -o $@.bpf.o
	bpftool gen skeleton $@.bpf.o > $@.skel.h
	clang -g -O2 -Wall $(INCLUDES) -c $@.c -o $@.o
	clang -Wall -O2 -g $@.o -static -lelf -lz -o $@

clean:
	rm -rf $(APPS) *.o