// procclone.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

using namespace std;

DWORD FindTargetProcess(_TCHAR*);

BOOL SetPrivilege(
	HANDLE hToken,          // access token handle
	LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
	BOOL bEnablePrivilege   // to enable or disable privilege
	);
BOOL GetLogonSID (HANDLE hToken, PSID *ppsid) ;
VOID FreeLogonSID (PSID *ppsid) ;

HANDLE GetProcessToken(HANDLE hProcess);

int _tmain(int argc, _TCHAR* argv[])
{
	LPTSTR szProgram = NULL;
	DWORD dwTargetProc = -1;
	HANDLE hTargetProcess = INVALID_HANDLE_VALUE;
	HANDLE hCurrentProcess = INVALID_HANDLE_VALUE;
	HANDLE hToken = INVALID_HANDLE_VALUE;
	HANDLE hProcToken = NULL;
	STARTUPINFO si = {0};
	PROCESS_INFORMATION pi = {0};
	if(argc < 3){
		cout << "usage: procclone <pid/pname> <program>" << endl;
		return 1;
	}
	dwTargetProc = _wtoi(argv[1]);
	if(dwTargetProc == 0){
		dwTargetProc = FindTargetProcess(argv[1]);
	}

	//if the process still could not be found
	if(dwTargetProc == 0){
		wcout << L"Process " << argv[1] << L" cloud not be found." << endl;
		return 1;
	}
	hCurrentProcess = GetCurrentProcess();
	if(! OpenProcessToken(hCurrentProcess, TOKEN_ADJUST_PRIVILEGES, &hToken)){
		cout << "failed to open current process token to adjust privileges" << endl;
		CloseHandle(hCurrentProcess);
		return 1;
	}
	if(!SetPrivilege(hToken, L"SeDebugPrivilege", TRUE)){
		cout << "cannot enable debug privilege for current user" << endl;
		CloseHandle(hCurrentProcess);
		CloseHandle(hToken);
		return 1;
	}
	if(!SetPrivilege(hToken, L"SeAssignPrimaryTokenPrivilege", TRUE)){
		cout << "cannot enable SeAssignPrimaryTokenPrivilege for current user" << endl;
		CloseHandle(hCurrentProcess);
		CloseHandle(hToken);
		return 1;
	}
	CloseHandle(hCurrentProcess);
	CloseHandle(hToken);
	hToken = NULL;
	hTargetProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwTargetProc);
	if(NULL == hTargetProcess){
		cout << "failed to open target process" << endl;
		return 1;
	}
	hToken = GetProcessToken(hTargetProcess);
	if(hToken == NULL){
		cout << "cannot get the process token of target process" << endl;
		CloseHandle(hTargetProcess);
		return 1;
	}
	CloseHandle(hTargetProcess);
	if(!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation , TokenPrimary, &hProcToken)){
		cout << "failed to change the token to primary token as " << GetLastError() << endl;
		CloseHandle(hToken);
		return 1;
	}
	CloseHandle(hToken);
	si.cb = sizeof(STARTUPINFO);
	if(!CreateProcessAsUser(hProcToken, NULL, argv[2], NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)){
		CloseHandle(hToken);
		cout << "failed to create process as " << GetLastError() << "." << endl;
		return 1;
	}
	CloseHandle(hToken);
	cout << "Process with PID " << pi.dwProcessId << " created." << endl;
	return 0;
}

DWORD FindTargetProcess(_TCHAR* szProcName){
	DWORD dwTargetProc = 0;
	HANDLE hProcessSnap = INVALID_HANDLE_VALUE;
	PROCESSENTRY32 procEntry;

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if(hProcessSnap == INVALID_HANDLE_VALUE){
		cout << "failed to snap processes" << endl;
		return dwTargetProc;
	}

	procEntry.dwSize = sizeof(PROCESSENTRY32);
	if(! Process32First(hProcessSnap, &procEntry)){
		cout << "failed to search in process list" << endl;
		CloseHandle(hProcessSnap);
		return dwTargetProc;
	}
	do{
		if(_wcsicmp(szProcName, procEntry.szExeFile) == 0){
			dwTargetProc = procEntry.th32ProcessID;
			break;
		}
	}while(Process32Next(hProcessSnap, &procEntry));

	CloseHandle(hProcessSnap);
	return dwTargetProc;
}

BOOL SetPrivilege(
	HANDLE hToken,          // access token handle
	LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
	BOOL bEnablePrivilege   // to enable or disable privilege
	) 
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if ( !LookupPrivilegeValue( 
		NULL,            // lookup privilege on local system
		lpszPrivilege,   // privilege to lookup 
		&luid ) )        // receives LUID of privilege
	{
		printf("LookupPrivilegeValue error: %u\n", GetLastError() ); 
		return FALSE; 
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.

	if ( !AdjustTokenPrivileges(
		hToken, 
		FALSE, 
		&tp, 
		sizeof(TOKEN_PRIVILEGES), 
		(PTOKEN_PRIVILEGES) NULL, 
		(PDWORD) NULL) )
	{ 
		printf("AdjustTokenPrivileges error: %u\n", GetLastError() ); 
		return FALSE; 
	} 

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

	{
		printf("The token does not have the specified privilege. \n");
		return FALSE;
	} 

	return TRUE;
}

BOOL AdjustSDForToken(HANDLE hToken){
	PSECURITY_DESCRIPTOR pSD = NULL, pSDNew = NULL;
	DWORD dwBytesNeeded = 0;
	DWORD dwSize = 0;
	PSID mySid = NULL;
	HANDLE hMyToken = NULL;
	if(!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hMyToken)){
		cout << "cannot get current token object." << endl;
		return FALSE;
	}
	if(! GetLogonSID(hMyToken, &mySid)){
		CloseHandle(hMyToken);
		cout << "failed to get current user's SID" << endl;
		return FALSE;
	}
	CloseHandle(hMyToken);
	GetKernelObjectSecurity(hToken, DACL_SECURITY_INFORMATION, pSD, dwSize, &dwBytesNeeded);

	if(ERROR_INSUFFICIENT_BUFFER == GetLastError()){
		ACCESS_ALLOWED_ACE* pace = NULL;
		ACL_SIZE_INFORMATION aclSizeInfo = {0};
		BOOL bDaclExist, bDaclPresent;
		DWORD dwNewAclSize = 0;
		PACL pAcl = NULL, pNewAcl = NULL;
		PVOID pTempAce = NULL;

		pSD = (PSECURITY_DESCRIPTOR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBytesNeeded);
		pSDNew = (PSECURITY_DESCRIPTOR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBytesNeeded);

		dwSize = dwBytesNeeded;

		if(pSD == NULL ||!GetKernelObjectSecurity(hToken, DACL_SECURITY_INFORMATION, pSD, dwSize, &dwBytesNeeded)){
			HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pSD);
			HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pSDNew);
			FreeLogonSID(&mySid);
			cout << "cannot get the security info from token as " << GetLastError() << endl;
			return FALSE;
		}

		if(! InitializeSecurityDescriptor(pSDNew, SECURITY_DESCRIPTOR_REVISION)){
			HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pSD);
			HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pSDNew);
			FreeLogonSID(&mySid);
			cout << "failed to initialize new SD" << endl;
			return FALSE;
		}

		if(!GetSecurityDescriptorDacl(pSD, &bDaclPresent, &pAcl, &bDaclExist)){
			HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pSD);
			HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pSDNew);
			FreeLogonSID(&mySid);
			cout << "failed to get DACL from SD" << endl;
			return FALSE;
		}

		aclSizeInfo.AclBytesInUse = sizeof(ACL);

		if(pAcl != NULL){

			if(!GetAclInformation(pAcl, &aclSizeInfo, sizeof(ACL_SIZE_INFORMATION), AclSizeInformation)){
				HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pSD);
				HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pSDNew);
				FreeLogonSID(&mySid);
				cout << "failed to get acl size info from ACL" << endl;
				return FALSE;
			}

		}else{
			HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pSD);
			HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pSDNew);
			FreeLogonSID(&mySid);
			cout << "no ACL info" << endl;
			return FALSE;
		}

		dwNewAclSize = aclSizeInfo.AclBytesInUse + 2 * sizeof(ACCESS_ALLOWED_ACE) + 2 * GetLengthSid(mySid) - 2 * sizeof(DWORD);
		pNewAcl = (PACL)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwNewAclSize);

		if(pNewAcl == NULL){
			HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pSD);
			HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pSDNew);
			FreeLogonSID(&mySid);
			cout << "no memory" << endl;
			return FALSE;
		}

		if(!InitializeAcl(pNewAcl, dwNewAclSize, ACL_REVISION)){
			HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pSD);
			HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pSDNew);
			HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pNewAcl);
			FreeLogonSID(&mySid);
			cout << "failed to initialize ACL" << endl;
			return FALSE;
		}

		if (bDaclPresent)
		{
			// Copy the ACEs to the new ACL.
			if (aclSizeInfo.AceCount)
			{
				for (UINT i=0; i < aclSizeInfo.AceCount; i++)
				{
					// Get an ACE.
					if (!GetAce(pAcl, i, &pTempAce)){
						HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pSD);
						HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pSDNew);
						HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pNewAcl);
						FreeLogonSID(&mySid);
						cout << "failed to get ACE from ACL" << endl;
						return FALSE;
					}

					// Add the ACE to the new ACL.
					if (!AddAce(
						pNewAcl,
						ACL_REVISION,
						MAXDWORD,
						pTempAce,
						((PACE_HEADER)pTempAce)->AceSize)
						)
					{
						HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pSD);
						HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pSDNew);
						HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pNewAcl);
						FreeLogonSID(&mySid);
						cout << "failed to add ACE to ACL" << endl;
						return FALSE;
					}
				}//end for
			}
		}

		pace = (ACCESS_ALLOWED_ACE *)HeapAlloc(
			GetProcessHeap(),
			HEAP_ZERO_MEMORY,
			sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(mySid) -
			sizeof(DWORD));

		if (pace == NULL)
		{
			HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pSD);
			HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pSDNew);
			HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pNewAcl);
			FreeLogonSID(&mySid);
			cout << "no memory for ace" << endl;
			return FALSE;
		}

		pace->Header.AceType  = ACCESS_ALLOWED_ACE_TYPE;
		pace->Header.AceFlags = CONTAINER_INHERIT_ACE |
			INHERIT_ONLY_ACE | OBJECT_INHERIT_ACE;
		pace->Header.AceSize  = (WORD)(sizeof(ACCESS_ALLOWED_ACE) +
			GetLengthSid(mySid) - sizeof(DWORD));
		pace->Mask            = TOKEN_DUPLICATE;

		if (!CopySid(GetLengthSid(mySid), &pace->SidStart, mySid))
		{
			HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pSD);
			HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pSDNew);
			HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pNewAcl);
			HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pace);
			FreeLogonSID(&mySid);
			cout << "failed to copy sid" << endl;
			return FALSE;
		}

		if (!AddAce(
			pNewAcl,
			ACL_REVISION,
			MAXDWORD,
			(LPVOID)pace,
			pace->Header.AceSize)
			)
		{
			HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pSD);
			HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pSDNew);
			HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pNewAcl);
			HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pace);
			FreeLogonSID(&mySid);
			cout << "failed to add ACE to ACL (first)" << endl;
			return FALSE;
		}

		pace->Header.AceFlags = NO_PROPAGATE_INHERIT_ACE;
		pace->Mask            = TOKEN_ASSIGN_PRIMARY;

		if (!AddAce(
			pNewAcl,
			ACL_REVISION,
			MAXDWORD,
			(LPVOID)pace,
			pace->Header.AceSize)
			)
		{
			HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pSD);
			HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pSDNew);
			HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pNewAcl);
			HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pace);
			FreeLogonSID(&mySid);
			cout << "failed to add ACE to ACL (second)" << endl;
			return FALSE;
		}

		// Set a new DACL for the security descriptor.

		if (!SetSecurityDescriptorDacl(
			pSDNew,
			TRUE,
			pNewAcl,
			FALSE)
			)
		{
			HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pSD);
			HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pSDNew);
			HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pNewAcl);
			HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pace);
			FreeLogonSID(&mySid);
			cout << "failed to set new acl to new SD" << endl;
			return FALSE;
		}
		if(!SetKernelObjectSecurity(hToken, DACL_SECURITY_INFORMATION, pSDNew)){
			HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pSD);
			HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pSDNew);
			HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pNewAcl);
			HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pace);
			FreeLogonSID(&mySid);
			cout << "failed to set new SD" << endl;
			return FALSE;
		}

		HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pSD);
		HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pSDNew);
		HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pNewAcl);
		HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pace);
		FreeLogonSID(&mySid);
		return TRUE;


	}else{
		FreeLogonSID(&mySid);
		cout << "failed to get security info from token as " << GetLastError() << endl;
		return FALSE;
	}
}

HANDLE GetProcessToken(HANDLE hProcess){
	HANDLE hToken = NULL;
	PSID pPrevOwner  = NULL;
	BOOL bDefaultOwner = FALSE;
	if(OpenProcessToken(hProcess, TOKEN_DUPLICATE|TOKEN_QUERY, &hToken)){
		return hToken;
	}
	//we suffer some issue, try to adjust the token 
	if(!OpenProcessToken(hProcess, TOKEN_QUERY|WRITE_OWNER, &hToken)){
		cout << "failed to get a writable token from process as " << GetLastError() << endl;
		return hToken;
	}
	//
	if(AdjustSDForToken(hToken)){
		CloseHandle(hToken);
		if(OpenProcessToken(hProcess, TOKEN_DUPLICATE|TOKEN_QUERY, &hToken)){
			return hToken;
		}
		cout << "still could  not open a usable token." << endl;
		return NULL;
	}
	cout << "failed to adjust SD for the process token" << endl;
	CloseHandle(hToken);
	return NULL;
}

BOOL GetLogonSID (HANDLE hToken, PSID *ppsid) 
{
   BOOL bSuccess = FALSE;
   DWORD dwIndex;
   DWORD dwLength = 0;
   PTOKEN_GROUPS ptg = NULL;

// Verify the parameter passed in is not NULL.
    if (NULL == ppsid)
        goto Cleanup;

// Get required buffer size and allocate the TOKEN_GROUPS buffer.

   if (!GetTokenInformation(
         hToken,         // handle to the access token
         TokenGroups,    // get information about the token's groups 
         (LPVOID) ptg,   // pointer to TOKEN_GROUPS buffer
         0,              // size of buffer
         &dwLength       // receives required buffer size
      )) 
   {
      if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) 
         goto Cleanup;

      ptg = (PTOKEN_GROUPS)HeapAlloc(GetProcessHeap(),
         HEAP_ZERO_MEMORY, dwLength);

      if (ptg == NULL)
         goto Cleanup;
   }

// Get the token group information from the access token.

   if (!GetTokenInformation(
         hToken,         // handle to the access token
         TokenGroups,    // get information about the token's groups 
         (LPVOID) ptg,   // pointer to TOKEN_GROUPS buffer
         dwLength,       // size of buffer
         &dwLength       // receives required buffer size
         )) 
   {
      goto Cleanup;
   }

// Loop through the groups to find the logon SID.

   for (dwIndex = 0; dwIndex < ptg->GroupCount; dwIndex++) 
      if ((ptg->Groups[dwIndex].Attributes & SE_GROUP_LOGON_ID)
             ==  SE_GROUP_LOGON_ID) 
      {
      // Found the logon SID; make a copy of it.

         dwLength = GetLengthSid(ptg->Groups[dwIndex].Sid);
         *ppsid = (PSID) HeapAlloc(GetProcessHeap(),
                     HEAP_ZERO_MEMORY, dwLength);
         if (*ppsid == NULL)
             goto Cleanup;
         if (!CopySid(dwLength, *ppsid, ptg->Groups[dwIndex].Sid)) 
         {
             HeapFree(GetProcessHeap(), 0, (LPVOID)*ppsid);
             goto Cleanup;
         }
         break;
      }

   bSuccess = TRUE;

Cleanup: 

// Free the buffer for the token groups.

   if (ptg != NULL)
      HeapFree(GetProcessHeap(), 0, (LPVOID)ptg);

   return bSuccess;
}


VOID FreeLogonSID (PSID *ppsid) 
{
    HeapFree(GetProcessHeap(), 0, (LPVOID)*ppsid);
}
