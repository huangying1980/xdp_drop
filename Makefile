CLANG := clang

MAP_ENTRY := -DMAX_STATIS_NUM=6
MAP_ENTRY += -DMAX_PORT_NUM=128
MAP_ENTRY += -DMAX_LAYER3_NUM=16
MAP_ENTRY += -DMAX_LAYER4_NUM=8
MAP_ENTRY += -DMAX_LPM_IPV4_NUM=128
MAP_ENTRY += -DMAX_LPM_IPV6_NUM=128

#PROG_DEBUG := -DKERN_DEBUG

CLANG_FLAGS := -D__BPF_TRACING__ -Wall -Werror -g -O2 #$(PROG_DEBUG) #$(MAP_ENTRY)

LLC := llc

CC := gcc
#DEBUG := -DXDROP_DEBUG
#-DXDROP_DEBUG
CFLAGS := -g -Wall -Werror -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -DCOMPAT_NEED_REALLOCARRAY
VERSION := -DXDROP_VERSION=\"1.0.0\" -DXDROP_KERN_VERSION=\"1.0.0\"
SRC := xdrop_cmdline.c xdrop.c xdrop_util.c xdrop_user.c
OBJ := $(SRC:%.c=%.o)

LIBBPF_LIB := -lbpf -lelf -L./libbpf/src  -static -lz
#LIBBPF_LIB := -lbpf -L./libbpf/src 
#LIBBPF_LIB := ./libbpf/src/libbpf.a
#LIBBPF_INCLUDE := -I./ -I./libbpf/src -I./libbpf/include/uapi -I./libbpf/include -I ./headers
LIBBPF_INCLUDE := -I./ -I./libbpf/src -I./libbpf/include/uapi -I ./headers 
#LIBBPF_INCLUDE := -I./ -I./libbpf/src -I./libbpf/include/uapi -I ./headers -I./libbpf/src/build/usr/include/bpf

TARGET := xdrop

KERN_SRC := xdrop_kern_obj.c
KERN_OBJ := $(KERN_SRC:%.c=%.ll)
KERN_TARGET := xdrop_kern.obj

all: xdrop kern

$(TARGET):$(OBJ)
	$(CC) -o $(TARGET) $(OBJ) $(LIBBPF_LIB)

$(OBJ): %.o:%.c
	$(CC) -c $< -o $@ $(CFLAGS) $(VERSION) $(DEBUG) $(LIBBPF_INCLUDE)

kern: $(KERN_TARGET)

$(KERN_TARGET):$(KERN_OBJ)
	    $(LLC) -march=bpf -filetype=obj -o $@ $<
		    @chmod a+x $@

$(KERN_OBJ): %.ll:%.c
	    $(CLANG) -S -target bpf $(CLANG_FLAGS) $(LIBBPF_INCLUDE)  -emit-llvm -c -o $@ $<

install:
	mkdir -p /usr/local/xdp_drop
	install -m 0755 xdrop /usr/local/xdp_drop/
	cp  xdrop_kern.obj /usr/local/xdp_drop/
clean:
	rm -rf $(OBJ) $(TARGET) $(KERN_TARGET) $(KERN_OBJ)

.PHONY: all clean xdrop kern install
