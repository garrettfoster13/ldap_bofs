CC := x86_64-w64-mingw32-gcc
STRIP := x86_64-w64-mingw32-strip

CFLAGS := -Os -fno-asynchronous-unwind-tables -nostdlib -fno-ident \
          -fpack-struct=8 -falign-functions=1 -s \
          -falign-jumps=1 -w -Wall -shared -Wl,--no-seh \
          -Wl,--enable-stdcall-fixup -DBOF

all:
	$(CC) $(CFLAGS) rbcd.c -c -o rbcd.x64.o
	$(STRIP) --strip-unneeded rbcd.x64.o

clean:
	rm -rf rbcd.x64.o
