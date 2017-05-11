EXTRA_CFLAGS:=-I $(UBPF_PATH)/vm -I $(UBPF_PATH)/vm/inc
UBPF_STATIC_LIB_PATH:=$(UBPF_PATH)/vm/libubpf.a

all: bridge module

bridge:
	gcc -c ubpf_bridge.c $(EXTRA_CFLAGS)
	gcc -o ubpf_bridge ubpf_bridge.o $(UBPF_STATIC_LIB_PATH)

module:
	clang-3.7 -c module.c -target bpf

run:
	sudo taskset -c 0 ./ubpf_bridge -i netmap:ens4f0 -i netmap:ens4f1 -f module.o

clean:
	rm ubpf_bridge.o module.o ubpf_bridge
