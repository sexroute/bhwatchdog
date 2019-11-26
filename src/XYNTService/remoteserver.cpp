
#include "RemoteServer.h"
#include <Dbghelp.h>
#include <Psapi.h>
#include <atlconv.h>
#include <process.h>
#include <time.h>
#include <Psapi.h>
#include <Wtsapi32.h>
#include <Userenv.h>
#include <vector>
#include <atlbase.h>
#include <ATLComTime.h>
#include <TlHelp32.h>

INT G_B_DebuggerStarted = FALSE;
CCriticalSection * g_pLock						= NULL;
BOOL g_bServerStarted = FALSE;
BOOL  CRemoteSesrver::IsPortAvailable(int anPort)
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
	serverAddr.sin_addr.s_addr = ::inet_addr(_T("0.0.0.0"));
	serverAddr.sin_port = htons(lusPortTest);

	if (0 > bind ((SOCKET)lSockTest, (struct sockaddr *)&serverAddr, sizeof(serverAddr)))
	{
		(void)closesocket((UINT)lSockTest);

		return FALSE;
	}
	shutdown(lSockTest,SD_BOTH);
	(void)closesocket((UINT)lSockTest);

	return TRUE;
}

BOOL CRemoteSesrver::DetectAvailablePort(int & anPort)
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

volatile LONG g_shouldStopAllProcess = 0;

 BOOL CRemoteSesrver::ShouldStopAllProcess()
{
	g_shouldStopAllProcess = InterlockedExchangeAdd((volatile LONG *)&g_shouldStopAllProcess,0);
	return g_shouldStopAllProcess;
}

typedef struct __CLIENT_INFO
{
	CString m_strData;
	SOCKET m_oClient;
	CRemoteSesrver * m_pThis;
	int m_nServerMode;
}CLIENT_INFO;

 UINT CRemoteSesrver::ClientProcForStats(LPVOID apData)
{
	if (NULL == apData )
	{
		return 0;
	}

	CLIENT_INFO loInfo;

	CLIENT_INFO * lpClient = (CLIENT_INFO *)apData;
	if (lpClient->m_pThis == NULL)
	{
		return 0;
	}
	g_pLock->Lock();
	loInfo = *lpClient;
	delete lpClient;
	g_pLock->Unlock();
	
	LONG lshouldStopAllProcess = InterlockedExchangeAdd((volatile LONG *)&g_shouldStopAllProcess,0);
	
	if(loInfo.m_nServerMode)
	{

		lshouldStopAllProcess =1;
	}else
	{

		lshouldStopAllProcess =0;
	}

	InterlockedExchange((volatile LONG *)&g_shouldStopAllProcess,lshouldStopAllProcess);


	closesocket(loInfo.m_oClient);

	return 0;
}

 UINT CRemoteSesrver::ServerProcForStartStats(LPVOID apData)
{
	if (NULL == apData)
	{
		return 0;
	}
	g_pLock->Lock();
	g_bServerStarted = TRUE;
	g_pLock->Unlock();

	WSADATA wsa;

	SOCKET s;
	SOCKADDR_IN sAddr;

	int port;


	STARTUPINFO si;
	CRemoteSesrver * lpThis = (CRemoteSesrver* )apData;
	port = lpThis->m_nServerStartPort;//Set listening port
	DetectAvailablePort(port);

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
		DWORD ldwError = GetLastError();

		return -1;
	}

	lnRet = listen( s, 5 );

	int lnServerMode = lpThis->m_nMode;

	SetEvent(lpThis->m_hServerStatusStartStarted);

	if (SOCKET_ERROR == lnRet)
	{
		return -1;
	}

	CString lstrDataWriteBack;



	while(TRUE)
	{
		SOCKADDR_IN loClientAddr ={0}; // 定义一个客户端得地址结构作为参数  

		int lnAddr_length=sizeof(loClientAddr);  

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



		CLIENT_INFO * lpInfo = new CLIENT_INFO();
		lpInfo->m_oClient = loClient;
		lpInfo->m_strData = lstrDataWriteBack;
		lpInfo->m_pThis = lpThis;
		lpInfo->m_nServerMode = 0;
		CWinThread * lpThread = AfxBeginThread(CRemoteSesrver::ClientProcForStats,lpInfo,THREAD_PRIORITY_NORMAL,0,CREATE_SUSPENDED,0);

		if (NULL!=lpThread)
		{
			lpThread->m_bAutoDelete = TRUE;
			lpThread->ResumeThread();
			//CloseHandle(lpThread->m_hThread);
		}
	}

	g_bServerStarted = FALSE;

	return 0;
}

UINT CRemoteSesrver::ServerProcForStopStats(LPVOID apData)
{
	if (NULL == apData)
	{
		return 0;
	}
	g_pLock->Lock();
	g_bServerStarted = TRUE;
	g_pLock->Unlock();

	WSADATA wsa;

	SOCKET s;
	SOCKADDR_IN sAddr;

	int port;


	STARTUPINFO si;
	CRemoteSesrver * lpThis = (CRemoteSesrver* )apData;
	port = lpThis->m_nServerStopPort;//Set listening port

	DetectAvailablePort(port);

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
		DWORD ldwError = GetLastError();

		return -1;
	}

	lnRet = listen( s, 5 );

	int lnServerMode = lpThis->m_nMode;

	SetEvent(lpThis->m_hServerStatusStartStarted);

	if (SOCKET_ERROR == lnRet)
	{
		return -1;
	}

	CString lstrDataWriteBack;



	while(TRUE)
	{
		SOCKADDR_IN loClientAddr ={0}; // 定义一个客户端得地址结构作为参数  

		int lnAddr_length=sizeof(loClientAddr);  

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



		CLIENT_INFO * lpInfo = new CLIENT_INFO();
		lpInfo->m_oClient = loClient;
		lpInfo->m_strData = lstrDataWriteBack;
		lpInfo->m_pThis = lpThis;
		lpInfo->m_nServerMode = 1;
		CWinThread * lpThread = AfxBeginThread(CRemoteSesrver::ClientProcForStats,lpInfo,THREAD_PRIORITY_NORMAL,0,CREATE_SUSPENDED,0);

		if (NULL!=lpThread)
		{
			lpThread->m_bAutoDelete = TRUE;
			lpThread->ResumeThread();
			//CloseHandle(lpThread->m_hThread);
		}
	}

	g_bServerStarted = FALSE;

	return 0;
}


 BOOL CRemoteSesrver::StartServerStatusProc()
{
	BOOL lbShouldStartServer = FALSE;
	g_pLock->Lock();
	if (!g_bServerStarted)
	{
		lbShouldStartServer = TRUE;
	}		
	g_pLock->Unlock();

	if (lbShouldStartServer)
	{
		this->m_nServerStartPort = 28001;
		this->m_nServerStopPort = 29001;
		this->m_nMode = 0;

		CWinThread* lpThread = AfxBeginThread(CRemoteSesrver::ServerProcForStartStats,this,THREAD_PRIORITY_NORMAL,0,CREATE_SUSPENDED);
		
		lpThread->m_bAutoDelete = TRUE;
		lpThread->ResumeThread();	

		
		this->m_nMode = 1;
		lpThread = AfxBeginThread(CRemoteSesrver::ServerProcForStopStats,this,THREAD_PRIORITY_NORMAL,0,CREATE_SUSPENDED);
		lpThread->m_bAutoDelete = TRUE;
		lpThread->ResumeThread();	

		return TRUE;
	}

	return TRUE;

}

BOOL CRemoteSesrver::StartDebugger()
{
	BEGIN_ERROR_HANDLE;

	if (!G_B_DebuggerStarted)
	{
		G_B_DebuggerStarted = InterlockedExchangeAdd((volatile LONG *)&G_B_DebuggerStarted,0);

		if(!G_B_DebuggerStarted)
		{

			if (NULL == g_pLock)
			{
				g_pLock = new CCriticalSection();
			}

			BOOL lbStarted = StartServerStatusProc();
			if(lbStarted)
			{
				InterlockedExchange((volatile LONG *)&G_B_DebuggerStarted,(LONG)lbStarted);
			}
		}
	}

	END_ERROR_HANDLE;

	return FALSE;

}


