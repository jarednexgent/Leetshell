CC_64=x86_64-w64-mingw32-gcc
ASSEMBLER=nasm -f win64
LINKER=x86_64-w64-mingw32-ld

leetshell:
	$(ASSEMBLER) alignstack.asm -o alignstack.o
	$(CC_64) leetshell.c -Wall -m64 -ffunction-sections -fno-unwind-tables -fno-asynchronous-unwind-tables -nostdlib -fno-ident -fno-inline -Os -c -o leetshell.o -Wl,-Tlinker.ld,--no-seh
	$(LINKER) -s alignstack.o leetshell.o -o leetshell.exe
