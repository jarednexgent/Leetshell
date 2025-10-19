CC_64=x86_64-w64-mingw32-gcc
ASSEMBLER=nasm -f win64
LINKER=x86_64-w64-mingw32-ld

leetshell:
	$(ASSEMBLER) alignstack.asm -o alignstack.o
	$(CC_64) leetshell.c -m64 -Os -fno-unwind-tables -fno-asynchronous-unwind-tables -nostdlib -fno-ident -Os -c -o leetshell.o
	$(LINKER) -T linker.ld --no-seh -s alignstack.o leetshell.o -o leetshell.exe
