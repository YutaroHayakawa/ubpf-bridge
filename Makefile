SUBMODULE_PATH:=./external

UBPF_PATH:=$(SUBMODULE_PATH)/ubpf
UBPF_LIB:=$(UBPF_PATH)/vm/libubpf.a

EXTRA_CFLAGS:=-I $(UBPF_PATH)/vm -I $(UBPF_PATH)/vm/inc

all: ubpf bridge module

ubpf:
	make -C $(UBPF_PATH)/vm

bridge:
	gcc -c ubpf_bridge.c $(EXTRA_CFLAGS)
	gcc -o ubpf_bridge ubpf_bridge.o $(UBPF_LIB)

module:
	clang-3.7 -c module.c -target bpf

run:
	sudo taskset -c 0 ./ubpf_bridge -i netmap:ens4f0 -i netmap:ens4f1 -f module.o

run_nomodule:
	sudo taskset -c 0 ./ubpf_bridge -i netmap:ens4f0 -i netmap:ens4f1

clean:
	rm ubpf_bridge.o module.o ubpf_bridge
