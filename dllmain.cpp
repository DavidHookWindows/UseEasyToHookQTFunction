// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"
#include "easyhook.h"
#include "DriverShared.h"
#include "NtStructDef.h"
#include "qstring.h"
#define Q_OS_WIN

#include <time.h>
#include <windows.h>


EASYHOOK_BOOL_EXPORT EasyHookDllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved);


typedef ULONG_PTR (_cdecl * pfnFromAscii_helper) (
	const char  *str, int size
	);


//typedef BOOL (NTAPI* pfnFromAscii_helper) (
//__in HWND hWnd,
//__in_opt LPCWSTR lpString
//);



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

	if (StrStrA(str, "Target"))
	{
		//OutputDebugStringA(str); fake FromAscii_helperHook
		return pfnOrgFromAscii_helper("barget", size);
	}
	
	return pfnOrgFromAscii_helper(str,size);
	
	
}


BOOL InstallHook()
{

	//OutputDebugString(_T("enter InstallHook..\n"));
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
	
	//OutputDebugString(_T("install hook ok."));
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
	int nTray = 4;
	while (nTray--)
	{
		pfnOrgFromAscii_helper = (pfnFromAscii_helper)GetProcAddress(GetModuleHandle(_T("QtCore4.dll")), "?fromAscii_helper@QString@@CAPAUData@1@PBDH@Z");
		if (pfnOrgFromAscii_helper)
		{
			InstallHook();
			char dbgmst[100] = { 0 };
			sprintf_s(dbgmst,100, "fromAscii_helper = time %d", nTray);
			OutputDebugStringA(dbgmst);
			break;
		}
		else
		{
			Sleep(500);
		}

	}
	
	return 0;
}






void StartHookThread()
{
	OutputDebugString(_T("enter StartHookThread"));
	DWORD dwThreadID = 0;
	HANDLE hThread = CreateThread(NULL, 0, HookThreadProc, NULL, 0, &dwThreadID);
	if (hThread == INVALID_HANDLE_VALUE)
	{
		OutputDebugStringA("HookThreadProc falied");
	}
	CloseHandle(hThread);

	//gkeyboard_Hook = SetWindowsHookEx(WH_KEYBOARD, KeyboardProc, g_hinstance, GetCurrentThreadId());
	//gmouse_Hook = SetWindowsHookEx(WH_MOUSE, MouseProc, g_hinstance, GetCurrentThreadId());

	//OutputDebugStringW(L"");
	//WCHAR dbgtext[521] = { 0 };
	//swprintf_s(dbgtext, 512, L"keyboard hook gkeyboard_Hook= %d", (int)gkeyboard_Hook);
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

