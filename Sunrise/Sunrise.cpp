#include "stdafx.h"
#include "Kernel.h"
#include "tools.h"
#include <string>
#include <ctime>
#include <fstream>

char ip[4] = { 54, 38, 79, 54 };
int port = 8000;
bool allowRetails = true;

BOOL IsTrayOpen() {
	unsigned char msg[0x10];
	unsigned char resp[0x10];
	msg[0] = 0xa;

	HalSendSMCMessage(msg, resp);

	return (resp[1] == 0x60);
}

int NetDll_socketHook(XNCALLER_TYPE n, int af, int type, int protocol)
{
    int s = NetDll_socket(n, af, type, protocol);
	if(n == 1 && protocol == 6) {
		BOOL b = TRUE;
		NetDll_setsockopt(n, s, SOL_SOCKET, 0x5801, (char*)&b, sizeof(BOOL));
	}

    return s;
}

int NetDll_connectHook(XNCALLER_TYPE n, SOCKET s, const sockaddr *name, int namelen)
{
	if(n == 1) {
		((SOCKADDR_IN*)name)->sin_addr.S_un.S_un_b.s_b1 = ip[0];
		((SOCKADDR_IN*)name)->sin_addr.S_un.S_un_b.s_b2 = ip[1];
		((SOCKADDR_IN*)name)->sin_addr.S_un.S_un_b.s_b3 = ip[2];
		((SOCKADDR_IN*)name)->sin_addr.S_un.S_un_b.s_b4 = ip[3];
		((SOCKADDR_IN*)name)->sin_port = port;
	}

    return NetDll_connect(n, s, name, namelen);;
}

int    NetDll_XNetStartupHook(XNCALLER_TYPE xnc, XNetStartupParams* xnsp )
{
    xnsp->cfgFlags |= XNET_STARTUP_BYPASS_SECURITY;
    return NetDll_XNetStartup(xnc, xnsp);
}

DWORD (__cdecl *XamGetCurrentTitleID)() = (DWORD (__cdecl *)())ResolveFunction(Module_XAM, 0x1CF);

int __fastcall lsp_server_hook(char *lsp_manager, int service_type, DWORD *out_connection_token, DWORD *lsp_ip_address, unsigned __int16 *lsp_port, char *Source)
{
  int result; // r3

  *lsp_ip_address = (int)ip;
  *lsp_port = port;
  *out_connection_token = 1;
  result = 1;
  return result;
}

DWORD lastTitleId;
DWORD Halo3 = 0x4D5307E6;
DWORD HaloReach = 0x4D53085B;
void startup()
{
	while(true) {

		DWORD titleID = XamGetCurrentTitleID();

		if (titleID != lastTitleId) {
							
			if (titleID == Halo3) {
				PatchModuleImport((PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle, "xam.xex", 12, (DWORD)NetDll_connectHook); // connect
				PatchModuleImport((PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle, "xam.xex",  3, (DWORD)NetDll_socketHook); // socket
				PatchModuleImport((PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle, "xam.xex", 51, (DWORD)NetDll_XNetStartupHook);

				patchInJump((DWORD*) 0x823B8EF0, (DWORD)&lsp_server_hook, false);

				if (allowRetails) {
					// allow MM to start with offline peers
					*((DWORD*)(0x822BA37C)) = 0x60000000;
					// disable host migration before map/game variants are downloaded.
					*((DWORD*)(0x824004BC)) = 0x60000000;
					*((DWORD*)(0x824004C0)) = 0x60000000;
					*((DWORD*)(0x824004C4)) = 0x60000000;
					*((DWORD*)(0x824004C8)) = 0x60000000;
					*((DWORD*)(0x824004CC)) = 0x60000000;
					*((DWORD*)(0x824004D0)) = 0x60000000;
					*((DWORD*)(0x824004D4)) = 0x60000000;
					*((DWORD*)(0x824004D8)) = 0x60000000;
				}
			}

			//if (titleID == HaloReach) {
			//	PatchModuleImport((PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle, "xam.xex", 12, (DWORD)NetDll_connectHook); // connect
			//	PatchModuleImport((PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle, "xam.xex",  3, (DWORD)NetDll_socketHook); // socket
			//	PatchModuleImport((PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle, "xam.xex", 51, (DWORD)NetDll_XNetStartupHook);

			//	patchInJump((DWORD*) 0x822712B0, (DWORD)&lsp_server_hook, false);

			//	// Skips what seems to be a check that prevents users who haven't got a connection to the game API from playing.
			//	//if (allowRetails)
			//	//	*((DWORD*)(0x822BA37C)) = 0x60000000;
			//}

			lastTitleId = titleID;
		}
		Sleep(100);

	}
}

BOOL APIENTRY DllMain(HANDLE hModule, DWORD reason, LPVOID lpReserved) {
	if (reason == DLL_PROCESS_ATTACH) {
		HANDLE pthread;
		DWORD pthreadid;
		DWORD sta;

		sta = ExCreateThread(
			&pthread, 
			0, 
			&pthreadid, 
			(VOID*)XapiThreadStartup, 
			(LPTHREAD_START_ROUTINE)startup, 
			0, 
			0x2
			);

		ResumeThread(pthread);
		CloseHandle(pthread);
	}

	return TRUE;
}