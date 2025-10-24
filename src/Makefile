# binaries
CC_64=x86_64-w64-mingw32-gcc
ASSEMBLER=nasm -f win64
LINKER=x86_64-w64-mingw32-ld
OBJCOPY := $(shell \
   command -v x86_64-w64-mingw32-objcopy 2>/dev/null || \
   command -v objcopy 2>/dev/null || echo objcopy)
HEXDUMP=hexdump

# inputs
ALIGN_ASM = alignstack.asm
MAIN_C    = leetshell.c
LDSCRIPT  = linker.ld

# wrappers/templates that embed payload.inc
TEMPLATE_EXE = template_exe.c
TEMPLATE_DLL = template_dll.c

# outputs
OBJ_ALIGN = alignstack.o
OBJ_MAIN  = leetshell.o
EXE_CORE  = leetshell.exe
BIN_CORE  = leetshell.bin
PAYLOAD_INC = payload.inc

# default gap fill for objcopy when carving .text
GAPFILL ?= 0x00

# base build flags 
CFLAGS = -m64 -Os -fno-unwind-tables -fno-asynchronous-unwind-tables -nostdlib -fno-ident
LDFLAGS = -T $(LDSCRIPT) --no-seh -s

# wrapper build flags
WRAP_CFLAGS  = -nostdlib -m64 -Os -s -fno-ident -ffunction-sections -fdata-sections
WRAP_LDFLAGS = -Wl,--gc-sections \
               -Wl,--disable-runtime-pseudo-reloc,--disable-auto-import \
               -Wl,--no-undefined

EXE_LDFLAGS  = -Wl,--entry,_start \
               -Wl,--subsystem,console

DLL_LDFLAGS  = -Wl,--entry,DllMain

# Parent dir (repo root) for defaults when OUTPUT is empty
PARENT := $(abspath ..)

# core build 
leetshell: $(BIN_CORE)

$(OBJ_ALIGN): $(ALIGN_ASM)
	$(ASSEMBLER) $< -o $@

$(OBJ_MAIN): $(MAIN_C)
	$(CC_64) $(CFLAGS) -c $< -o $@

$(EXE_CORE): $(OBJ_ALIGN) $(OBJ_MAIN) $(LDSCRIPT)
	$(LINKER) $(LDFLAGS) $(OBJ_ALIGN) $(OBJ_MAIN) -o $@

$(BIN_CORE): $(EXE_CORE)
	$(OBJCOPY) -O binary --only-section=.text --gap-fill $(GAPFILL) $(EXE_CORE) $(BIN_CORE)

# payload.inc (comma-separated hex) 
$(PAYLOAD_INC): $(BIN_CORE)
	$(HEXDUMP) -v -e '16/1 "0x%02x, "' $(BIN_CORE) | sed 's/ $$//' | sed '$$s/, $$//' > $(PAYLOAD_INC)

# RAW binary blob
raw: $(BIN_CORE)
	@if [ -z "$(OUTPUT)" ]; then OUT="$(PARENT)/output.bin"; else OUT="$(OUTPUT)"; fi; \
	cp -f $(BIN_CORE) "$$OUT"; \
	echo "[+] Raw binary saved: $$OUT"

# EXE (template_exe.c + payload.inc; no CRT)
exe: $(PAYLOAD_INC) $(TEMPLATE_EXE)
	@if [ -z "$(OUTPUT)" ]; then OUT="$(PARENT)/output.exe"; else OUT="$(OUTPUT)"; fi; \
	$(CC_64) $(WRAP_CFLAGS) $(TEMPLATE_EXE) \
	         $(WRAP_LDFLAGS) $(EXE_LDFLAGS) \
	         -lkernel32 \
	         -o "$$OUT"; \
	$(OBJCOPY) --remove-section .comment "$$OUT" 2>/dev/null || true; \
	echo "[+] EXE saved: $$OUT"

# DLL (template_dll.c + payload.inc; no CRT; neutral internal name)
dll: $(PAYLOAD_INC) $(TEMPLATE_DLL)
	@if [ -z "$(OUTPUT)" ]; then OUT="$(PARENT)/output.dll"; else OUT="$(OUTPUT)"; fi; \
	INTNAME="msvcrt.dll"; \
	{ echo "LIBRARY $$INTNAME"; echo "EXPORTS"; echo "  pDllMain @1 NONAME"; } > tmp_name.def; \
	$(CC_64) $(WRAP_CFLAGS) -shared $(TEMPLATE_DLL) tmp_name.def \
	         $(WRAP_LDFLAGS) $(DLL_LDFLAGS) \
	         -lkernel32 \
	         -o "$$OUT"; \
	rm -f tmp_name.def; \
	$(OBJCOPY) --remove-section .comment "$$OUT" 2>/dev/null || true; \
	echo "[+] DLL saved: $$OUT"

# C array (stdout if OUTPUT empty) 
c: $(BIN_CORE)
	@if [ -z "$(OUTPUT)" ]; then \
	  echo 'unsigned char buf[] = {'; \
	  $(HEXDUMP) -v -e '16/1 "0x%02x, " "\n"' $(BIN_CORE) | sed '$$s/, $$//'; \
	  echo '};'; \
	else \
	  { echo 'unsigned char buf[] = {'; \
	    $(HEXDUMP) -v -e '16/1 "0x%02x, " "\n"' $(BIN_CORE) | sed '$$s/, $$//'; \
	    echo '};'; } > "$(OUTPUT)"; \
	  echo "[+] C array written: $(OUTPUT)"; \
	fi

# Post-build cleanup
clean:
	rm -f $(OBJ_ALIGN) $(OBJ_MAIN) $(EXE_CORE) $(BIN_CORE) $(PAYLOAD_INC)

.PHONY: leetshell raw exe dll c clean
