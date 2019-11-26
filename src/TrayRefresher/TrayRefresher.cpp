// TrayRefresher.cpp : 定义控制台应用程序的入口点。
//
#define WAIT_OBJECT_0 ((STATUS_WAIT_0) + 0)
#define WAIT_OBJECT_1 ((STATUS_WAIT_0) + 1)
#include "stdafx.h"
#include <windows.h>


void RefreshTrayWindowsXp()
{
	HWND hwnd = NULL ;


	hwnd = ::FindWindow("Shell_TrayWnd", NULL);
	hwnd = ::FindWindowEx(hwnd, 0, "TrayNotifyWnd", NULL);
	hwnd = ::FindWindowEx(hwnd, 0, "SysPager", NULL);
	hwnd = ::FindWindowEx(hwnd, 0, "ToolbarWindow32", NULL);

	RECT rTrayToolBar;
	::GetClientRect(hwnd, &rTrayToolBar);

	for(int x = 1; x < rTrayToolBar.right - 1; x++)
	{
		int y = rTrayToolBar.bottom / 2;
		::SendMessage(hwnd, WM_MOUSEMOVE, 0, MAKELPARAM(x, y));
	}
}

void RefreshTrayWindows7()
{
	HWND hwnd = NULL ;
	HWND lhParent = NULL;

	hwnd = ::FindWindow("NotifyIconOverflowWindow", NULL);
	
	if (::IsWindow(hwnd))
	{
		BOOL lbShouldHid = FALSE;
		if (!IsWindowVisible(hwnd))
		{
			lhParent =hwnd;
			lbShouldHid = true;
			::ShowWindow(hwnd,SW_SHOW);
		}

		hwnd = ::FindWindowEx(hwnd, 0, "ToolbarWindow32", NULL);

		if (::IsWindow(hwnd))
		{
			RECT rTrayToolBar ={0};
			::GetClientRect(hwnd, &rTrayToolBar);

			for(int x = 1; x < rTrayToolBar.right - 2; x=x+2)
			{
				for (int y=1;y<rTrayToolBar.bottom-2;y=y+2)
				{			
					::SendMessage(hwnd, WM_MOUSEMOVE, 0, MAKELPARAM(x, y));
				}
			}

			if (lbShouldHid)
			{
				::ShowWindow(lhParent,SW_HIDE);
			}
		}
	}

}

void RefreshTray()
{
	// 获得托盘（不含时间的区域）句柄
	RefreshTrayWindowsXp();
	RefreshTrayWindows7();
}

CString GetAppPath()
{
	CString m_strAppPath = _T("");

	::GetModuleFileName(NULL, m_strAppPath.GetBuffer(256), 256);

	m_strAppPath.ReleaseBuffer();

	int n = m_strAppPath.ReverseFind( _T('\\') );

	m_strAppPath = m_strAppPath.Left(n + 1);

	CString strTempPathName;

	::GetLongPathName(m_strAppPath,strTempPathName.GetBuffer(256), 256);

	strTempPathName.ReleaseBuffer();

	m_strAppPath = strTempPathName;

	return m_strAppPath;
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
								  LPPROCESS_INFORMATION lpProcessInformation)
{

	BOOL lbRet = CreateProcessWithLogonW
		(
		lpUsername,
		lpDomain,
		lpPassword,
		dwLogonFlags,
		lpApplicationName,
		lpCommandLine,
		dwCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation
		);

	if (!lbRet)
	{
		DWORD ldwRet = GetLastError();
	}

	return lbRet;
}

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

BOOL ReBootComputer()
{
	BOOL lbRet = GetShutDownPrivilege();

	DWORD ldwRet = 0;

	if (lbRet)
	{
		lbRet = ExitWindowsEx(EWX_FORCE  | EWX_REBOOT, SHTDN_REASON_MINOR_MAINTENANCE);  

		ldwRet = GetLastError();
	}

	if (lbRet<=0)
	{
		BOOL lbRet2= SystemShutdown(2);

		ldwRet = GetLastError();

		if (!lbRet2)
		{
			system("shutdown -s -f -t -r 0");
		}
	}



	return lbRet;
}

BOOL ReadAndStartProcess(CString lstrFileName,CString lstrSectionName)
{
	
	USES_CONVERSION;

	int lnBufferLength = 2048;
	const int c_nMaxSize = 2048;
	STARTUPINFOW startUpInfow = { sizeof(STARTUPINFOW),NULL,A2W(""),NULL,0,0,0,0,0,0,0,STARTF_USESHOWWINDOW,0,0,NULL,0,0,0}; 
	startUpInfow.wShowWindow = SW_SHOW;			
	startUpInfow.lpDesktop = NULL;
	DWORD ldwCreateFlag = NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE|CREATE_UNICODE_ENVIRONMENT;
	PROCESS_INFORMATION procInfo[2048] = {0};

	CString lstrUserName ;
	CString lstrPassWord ;
	CString lstrDomain;
	CString lstrCommand;
	CString lstrWorkingDir;
	char szTitle[c_nMaxSize] = "";

	::GetPrivateProfileString(  lstrSectionName, 
		"Username",
		"",lstrUserName.GetBufferSetLength(lnBufferLength),
		lnBufferLength, 
		lstrFileName);
	lstrUserName.ReleaseBuffer();

	::GetPrivateProfileString(  lstrSectionName, 
		"Password",
		"",lstrPassWord.GetBufferSetLength(lnBufferLength),
		lnBufferLength, 
		lstrFileName);
	lstrPassWord.ReleaseBuffer();

	::GetPrivateProfileString(  lstrSectionName, 
		"Domain",
		"",lstrDomain.GetBufferSetLength(lnBufferLength),
		lnBufferLength, 
		lstrFileName);
	lstrDomain.ReleaseBuffer();

	::GetPrivateProfileString(lstrSectionName, 
		"CommandLine", 
		"", lstrCommand.GetBufferSetLength(lnBufferLength),
		lnBufferLength, 
		lstrFileName);	
	lstrCommand.ReleaseBuffer();

	::GetPrivateProfileString(  lstrSectionName, 
		"WorkingDir",
		"",lstrWorkingDir.GetBufferSetLength(lnBufferLength),
		lnBufferLength, 
		lstrFileName);
	lstrWorkingDir.ReleaseBuffer();	


	int lbHide = 	::GetPrivateProfileInt(  lstrSectionName, 
											"Hide",
											1,
											lstrFileName);

	
	::GetPrivateProfileString(lstrSectionName, "Title", "", szTitle, c_nMaxSize, lstrFileName);

	if(strlen(szTitle)!=0)
	{
		startUpInfow.lpTitle = A2W(szTitle);
	}

	int lnShowMode = SW_SHOW;

	if (lbHide)
	{
		lnShowMode = SW_HIDE;
	}

	startUpInfow.wShowWindow = lnShowMode;		

	if (lstrWorkingDir.Trim().IsEmpty())
	{
		CString lstrWorkDir =lstrCommand;

		lstrWorkDir.Replace(_T('/'),_T('\\'));

		int lnIndex = lstrWorkDir.ReverseFind(_T('\\'));

		if (lnIndex >0)
		{
			lstrWorkDir = lstrWorkDir.Mid(0,lnIndex);

			lstrWorkingDir = lstrWorkDir;
		}
	}

	BOOL 	lbRet = CreateProcessWithLogonW(
											T2W(lstrUserName),
											T2W(lstrDomain),
											T2W(lstrPassWord),
											LOGON_WITH_PROFILE,
											NULL,
											A2W(lstrCommand),
											ldwCreateFlag,
											NULL,
											A2W(lstrWorkingDir),
											&startUpInfow,
											&(procInfo[0]));

	return lbRet;
}


int _tmain(int argc, _TCHAR* argv[])
{
	CString lstrFileName;
	CString lstrSectionName ;
	
	if (NULL!=argv)
	{
		if (argc>0 && argv!= NULL)
		{
			for (int i=0;i<argc;i++)
			{
				CString lstrTemp = argv[i];
				
				int lnIndex = lstrTemp.Find("/reboot");

				if (lnIndex>=0)
				{
					ReBootComputer();
				}
			    
				lnIndex = lstrTemp.Find("/f");
				if (lnIndex>=0)
				{
					lstrFileName = lstrTemp.Mid(lnIndex+2).Trim();
				}else 
				{
					lnIndex = lstrTemp.Find("/s");

					if (lnIndex>=0)
					{
						lstrSectionName =  lstrTemp.Mid(lnIndex+2).Trim();
					}
				}
			}
		}
	}

	BOOL lbRet = FALSE;

	if ((!lstrFileName.Trim().IsEmpty()) && (!lstrSectionName.Trim().IsEmpty()))
	{
		lbRet = ReadAndStartProcess(lstrFileName.Trim(),lstrSectionName.Trim());
	}

	RefreshTray();

	return 1;
}

