#include <windows.h>
#include <winternl.h>

#define MAX_PROTOCOL_CHAIN 7
#define WSAPROTOCOL_LEN 255

typedef struct _WSAPROTOCOLCHAIN {
	int   ChainLen;
	DWORD ChainEntries[MAX_PROTOCOL_CHAIN];
  } WSAPROTOCOLCHAIN, *LPWSAPROTOCOLCHAIN;
  
  typedef struct _WSAPROTOCOL_INFOA {
	DWORD            dwServiceFlags1;
	DWORD            dwServiceFlags2;
	DWORD            dwServiceFlags3;
	DWORD            dwServiceFlags4;
	DWORD            dwProviderFlags;
	GUID             ProviderId;
	DWORD            dwCatalogEntryId;
	WSAPROTOCOLCHAIN ProtocolChain;
	int              iVersion;
	int              iAddressFamily;
	int              iMaxSockAddr;
	int              iMinSockAddr;
	int              iSocketType;
	int              iProtocol;
	int              iProtocolMaxOffset;
	int              iNetworkByteOrder;
	int              iSecurityScheme;
	DWORD            dwMessageSize;
	DWORD            dwProviderReserved;
	CHAR             szProtocol[WSAPROTOCOL_LEN + 1];
  } WSAPROTOCOL_INFOA, *LPWSAPROTOCOL_INFOA;
  
  // http://undocumented.ntinternals.net/index.html?page=UserMode%2FStructures%2FPEB_LDR_DATA.html
typedef struct _PEB_LDR_DATA2 {
    ULONG Length;
	BOOL Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA2, * PPEB_LDR_DATA2;

// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_data_table_entry.htm
typedef struct _LDR_DATA_TABLE_ENTRY2 {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY2, *PLDR_DATA_TABLE_ENTRY2;