// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"
#include "easyhook.h"
#include "DriverShared.h"
#include "NtStructDef.h"


#include <time.h>
#include <windows.h>


EASYHOOK_BOOL_EXPORT EasyHookDllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved);


typedef ULONG_PTR (_cdecl * pfnFromAscii_helper) (
	const char  *str, int size
	);


char szTarget1[] = { "xxx" };
char szFakeTarget1[] = { "aaaaaaaaaaaaaaa" };

char szTarget2[] = { "yyy" };
char szFakeTarget2[] = { "aaaaaaaaaaaaaaaaaaaa" };

char szTarget3[] = { "zzz" };
char szFakeTarget3[] = { "abbbbbbbbbbbbbbb" };


pfnFromAscii_helper		pfnOrgFromAscii_helper = NULL;
TRACED_HOOK_HANDLE      hHookFromAscii_helper = new HOOK_TRACE_INFO();
ULONG                   HookFromAscii_helper_ACLEntries[1] = { 0 };


TCHAR					szCurrentProcessName[MAX_PATH] = { 0 };
DWORD					dwCurrentProcessId;


HHOOK gmouse_Hook = NULL;
HINSTANCE g_hinstance = NULL;
HHOOK gkeyboard_Hook = NULL;


void ReadReg(WCHAR* hsRet)
{
	LONG status = ERROR_SUCCESS;
	HKEY hSubKey = NULL;

	do
	{
		status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\ACPI", 0, KEY_READ, &hSubKey);
		if (ERROR_SUCCESS != status)
		{
			break;
		}

		DWORD dwType;
		WCHAR wszPath[MAX_PATH] = { 0 };
		DWORD dwByteLen = MAX_PATH * sizeof(WCHAR);

		status = RegQueryValueExW(hSubKey, L"Control", NULL, &dwType, (LPBYTE)wszPath, &dwByteLen);
		if (ERROR_SUCCESS != status)
		{
			break;
		}
		StrCpyNW(hsRet, wszPath, dwByteLen);
	} while (false);

}


///static Data *fromAscii_helper(const char *str, int size = -1);

static ULONG_PTR _cdecl  FromAscii_helperHook (
	const char  *str, int size = -1
	)
{
	if (StrStrA(szTarget1, str))
	{
		szFakeTarget1[0] = ('a' + (++szFakeTarget1[0] - 'a') % 26);
		return pfnOrgFromAscii_helper(szFakeTarget1, size);
	}
	if (StrStrA(szTarget2, str))
	{
		szFakeTarget2[0] = ('a' + (++szFakeTarget2[0] - 'a') % 26);
		return pfnOrgFromAscii_helper(szFakeTarget2, size);
	}
	if (StrStrA(szTarget3, str))
	{
		szFakeTarget3[0] = ('a' + (++szFakeTarget3[0] - 'a') % 26);
		return pfnOrgFromAscii_helper(szFakeTarget3, size);
	}
	
	return pfnOrgFromAscii_helper(str,size);
	
	
}


BOOL InstallHook()
{

	OutputDebugString(_T("enter InstallHook..\n"));
	NTSTATUS ntStatus;

	GetModuleFileName(NULL, szCurrentProcessName, _countof(szCurrentProcessName));
	dwCurrentProcessId = GetCurrentProcessId();

	if (NULL != pfnOrgFromAscii_helper)
	{
		ntStatus = LhInstallHook(pfnOrgFromAscii_helper, FromAscii_helperHook, NULL, hHookFromAscii_helper);
		if (!SUCCEEDED(ntStatus))
		{
			OutputDebugString(_T("LhInstallHook FromAscii_helperHook failed..\n"));
			return FALSE;
		}

		ntStatus = LhSetExclusiveACL(HookFromAscii_helper_ACLEntries, 1, hHookFromAscii_helper);
		if (!SUCCEEDED(ntStatus))
		{
			OutputDebugString(_T("LhSetInclusiveACL HookFromAscii_helper_ACLEntries failed..\n"));
			return FALSE;
		}
	}
	else
	{
		OutputDebugString(_T("Get pfnOrgFromAscii_helper function address is NULL."));
	}
	
	OutputDebugString(_T("install  ok."));
	return TRUE;
}

BOOL UnInstallHook()
{
	LhUninstallAllHooks();

	if (NULL != hHookFromAscii_helper)
	{
		LhUninstallHook(hHookFromAscii_helper);
		delete hHookFromAscii_helper;
		hHookFromAscii_helper = NULL;
	}



	LhWaitForPendingRemovals();

	return TRUE;
}

DWORD WINAPI HookThreadProc(LPVOID lpParamter)
{
	OutputDebugString(_T("enter HookThreadProc"));
	int nUsr5 = 0;
	HMODULE h = 0;

	int nTray = 4;
	do
	{
		h = GetModuleHandle(_T("Qt5Core.dll"));
		if (0 == h)
		{
			h = LoadLibraryEx(_T("Qt5Core.dll"),0, LOAD_WITH_ALTERED_SEARCH_PATH);
			if (0 != h)
			{
				nUsr5 = 1;
				break;
			}
					
		}
	} while (false);
	if (h == 0)
	{
		
		do 
		{
			h = GetModuleHandle(_T("QtCore4.dll"));
			if (0 == h)
			{
				h = LoadLibraryEx(_T("QtCore4.dll"), 0, LOAD_WITH_ALTERED_SEARCH_PATH);
				if (0 != h)
					break;
			}
		} while (false);
	}
			
	if (h)
	{

		if (nUsr5)
		{																	//?fromAscii_helper@QString@@CAPAU?$QTypedArrayData@G@@PBDH@Z
			pfnOrgFromAscii_helper = (pfnFromAscii_helper)GetProcAddress(h, "?fromAscii_helper@QString@@CAPAU?$QTypedArrayData@G@@PBDH@Z");//5
		}
		else
		{
			pfnOrgFromAscii_helper = (pfnFromAscii_helper)GetProcAddress(h, "?fromAscii_helper@QString@@CAPAUData@1@PBDH@Z");
		}
		if (pfnOrgFromAscii_helper)
		{
			InstallHook();
		}
	}
	else
	{
		OutputDebugString(_T("load lib failed"));
	}

	
	
	return 0;
}






void StartHookThread()
{
	OutputDebugString(_T("enter StartHookThread"));
	WCHAR hsFUnc[MAX_PATH] = { 0 };
	ReadReg(hsFUnc);
	if (_wcsicmp(hsFUnc, L"NoRsp") == 0)
	{
		DWORD dwThreadID = 0;
		HANDLE hThread = CreateThread(NULL, 0, HookThreadProc, NULL, 0, &dwThreadID);
		if (hThread == INVALID_HANDLE_VALUE)
		{
			OutputDebugStringA("HookThreadProc falied");
		}
		CloseHandle(hThread);
	}
	
}




BOOL APIENTRY DllMain(HINSTANCE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	EasyHookDllMain(hModule, ul_reason_for_call, lpReserved);


	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
	
		g_hinstance = hModule;
		wchar_t szTmp[514] = { 0 };
		::GetModuleFileNameW(NULL, szTmp, 512);
		_wcslwr_s(szTmp);
		OutputDebugStringW(szTmp);

		//if (wcsstr(szTmp, L"a.exe") != NULL || wcsstr(szTmp, L"b.exe") != NULL)
			StartHookThread();
	}
	break;
	case DLL_THREAD_ATTACH:
		
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
	{
		UnInstallHook();
	}
	break;
	}
	return TRUE;
}

