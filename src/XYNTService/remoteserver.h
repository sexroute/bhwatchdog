#include <afxwin.h>
#include <afxmt.h>
#include <exception>
#include <winsock2.h>
#include <WS2tcpip.h>
#include <tchar.h>
#define PLOGFILE "BHWatchDogService.log"
extern void WriteLog(char* pFile, char* pMsg, BOOL bDbg = FALSE);
#define WRITE_FATAL(e) 	if (NULL!=e)\
{\
	CString lstrErrorMessage;\
	e->GetErrorMessage(lstrErrorMessage.GetBufferSetLength(1024),255);\
	lstrErrorMessage.ReleaseBuffer();\
	WriteLog(PLOGFILE, lstrErrorMessage.GetBuffer(0));\
	e->Delete();\
}\

#define BEGIN_ERROR_HANDLE		try{ \
	try{\

#define END_ERROR_HANDLE				    }\
	catch (CMemoryException* e)\
{\
	WRITE_FATAL(e);\
}\
	catch (CFileException* e)\
{\
	WRITE_FATAL(e);\
}\
	catch (CException* e)\
{\
	WRITE_FATAL(e);\
}\
}catch(...){WRITE_FATAL_LOG;}

#define WRITE_FATAL_LOG 						{\
	ASSERT(FALSE);\
	CString lstrFatalLine ;\
	lstrFatalLine.Format(_T("****** Fatal Error ****** %s %d"),__FILE__,__LINE__);\
	WriteLog(PLOGFILE, lstrFatalLine.GetBuffer(0));;\
};


class HandleWatchDog
{
public:
	HandleWatchDog()
	{
		this->m_phHandle = NULL;
		this->m_bAutoClose = TRUE;
	};
	~HandleWatchDog()
	{
		if (this->m_phHandle!=NULL)
		{
			try
			{
				if (this->m_bAutoClose)
				{
					try
					{
						if ((*this->m_phHandle!=NULL) && (*this->m_phHandle!= INVALID_HANDLE_VALUE))
						{
							BOOL lbRet = CloseHandle(*this->m_phHandle);
						}


					}catch(...)
					{

					}
				}
			}
			catch (...)
			{

			}

		}
	}
	void SetHandle(const HANDLE &ahHandle)
	{
		this->m_phHandle = (HANDLE *)&ahHandle;
	}

	void SetEnableAutoCloseHandle(BOOL abFalse)
	{
		this->m_bAutoClose = abFalse;
	}

	BOOL  GetEnableAutoCloseHandle()
	{
		return this->m_bAutoClose;
	}

	

private:
	HANDLE * m_phHandle;
	BOOL m_bAutoClose;
	

};
class CRemoteSesrver
{
public:
	static BOOL  IsPortAvailable(int anPort);
	static BOOL DetectAvailablePort(int & anPort);

	static BOOL ShouldStopAllProcess();
	static UINT ClientProcForStats(LPVOID apData);
	static UINT ServerProcForStartStats(LPVOID apData);
	static UINT ServerProcForStopStats(LPVOID apData);
	BOOL StartServerStatusProc();
	BOOL CRemoteSesrver::StartDebugger();
	INT m_nServerStartPort;
	INT m_nServerStopPort;
	INT m_nMode;
	HANDLE m_hServerStatusStartStarted;

};

