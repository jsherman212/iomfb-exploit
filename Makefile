SDK = $(shell xcrun --sdk iphoneos --show-sdk-path)
CC = $(shell xcrun --sdk $(SDK) --find clang)
CFLAGS = -g -arch arm64 -isysroot $(SDK)
# make clang shut up about mach_port_destroy
CFLAGS += -Wno-deprecated-declarations
LDFLAGS = -framework CoreFoundation -framework IOKit

ifeq ($(SAMPLING_MEMORY), 1)
	CFLAGS += -DSAMPLING_MEMORY
endif

all : exploit

array.o : array.c array.h
	$(CC) $(CFLAGS) array.c -c

kernel_hooks.o : kernel_hooks.c kernel_hooks.h
	$(CC) $(CFLAGS) kernel_hooks.c -c

exploit : array.o iokit.h kernel_hooks.o IOMobileFramebufferUserClient.c
	$(CC) $(CFLAGS) $(LDFLAGS) array.o kernel_hooks.o IOMobileFramebufferUserClient.c -o exploit
	ldid -Sent.xml ./exploit
	sshpass -p "iphone" rsync -sz -e 'ssh -p 2222' ./exploit ./ent.xml \
		root@localhost:/var/root
