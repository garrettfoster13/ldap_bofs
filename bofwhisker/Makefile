CC := x86_64-w64-mingw32-gcc
STRIP := x86_64-w64-mingw32-strip

CFLAGS := -Os -fno-asynchronous-unwind-tables -nostdlib -fno-ident \
          -fpack-struct=8 -falign-functions=1 -s \
          -falign-jumps=1 -w -Wall -shared -Wl,--no-seh \
          -Wl,--enable-stdcall-fixup -DBOF

all:
	$(CC) $(CFLAGS) keycred.c -c -o keycred.x64.o
	$(STRIP) --strip-unneeded keycred.x64.o

clean:
	rm -rf keycred.x64.o
