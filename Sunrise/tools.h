#include "stdafx.h"
#include "Kernel.h"

VOID Thread(LPTHREAD_START_ROUTINE th){
	HANDLE hThread; DWORD hThreadID;
	ExCreateThread(&hThread, 0, &hThreadID, (PVOID)XapiThreadStartup, (LPTHREAD_START_ROUTINE)th, NULL, 0x2);
	XSetThreadProcessor(hThread, 4);
	ResumeThread(hThread);
	CloseHandle(hThread);
}
FARPROC  ResolveFunction(PCHAR ModuleName, DWORD Ordinal) {
	HMODULE mHandle = GetModuleHandle(ModuleName);
	return (mHandle == NULL) ? NULL : GetProcAddress(mHandle, (LPCSTR)Ordinal);
}

void MessageBox(LPCWSTR Text, LPCWSTR Caption) {
	LPCWSTR* text;
	text = new LPCWSTR[1];
	text[0] = L"Ok";
	PXOVERLAPPED over = new XOVERLAPPED();
	memset(over, 0, sizeof(over));
	PMESSAGEBOX_RESULT result = new MESSAGEBOX_RESULT();
	memset(result, 0, sizeof(result));

	while(XShowMessageBoxUI(0, Caption, Text, 1, text, 0, XMB_NOICON, result, over) == ERROR_ACCESS_DENIED)
		Sleep(500);
	while(!XHasOverlappedIoCompleted(over))
		Sleep(500);
}

//HRESULT CreateSymbolicLink(char* szDrive, char* szDeviceName, BOOL System) {
//
//	// Setup our path
//	char szDestinationDrive[MAX_PATH];
//	sprintf_s(szDestinationDrive, MAX_PATH, System ? "\\System??\\%s" : "\\??\\%s", szDrive);
//
//	// Setup our strings
//	ANSI_STRING linkname, devicename;
//	RtlInitAnsiString(&linkname, szDestinationDrive);
//	RtlInitAnsiString(&devicename, szDeviceName);
//
//	//check if already mapped
//	if(FileExists(szDrive))
//		return S_OK;
//
//	// Create finally
//	NTSTATUS status = ObCreateSymbolicLink(&linkname, &devicename);
//	return (status >= 0) ? S_OK : S_FALSE;
//}
//VOID _PatchInJump(PDWORD Address, DWORD Destination, BOOL Linked) {
//		Address[0] = 0x3D600000 + ((Destination >> 16) & 0xFFFF);
//		if (Destination & 0x8000) Address[0] += 1;
//		Address[1] = 0x396B0000 + (Destination & 0xFFFF);
//		Address[2] = 0x7D6903A6;
//		Address[3] = Linked ? 0x4E800421 : 0x4E800420;
//}
		VOID patchInJump(DWORD* Address, DWORD Destination, bool Linked)
		{
			Address[0] = 0x3D600000 + ((Destination >> 16) & 0xFFFF);
			if (Destination & 0x8000)
				Address[0] += 1;
			Address[1] = 0x396B0000 + (Destination & 0xFFFF);
			Address[2] = 0x7D6903A6;
			Address[3] = Linked ? 0x4E800421 : 0x4E800420;

			do {
				__dcbst(0, Address);
				__emit(0x7c0004ac);
				__emit(0x4C00012C);
			} while (0);
		}
VOID __declspec(naked) GLPR(VOID) {
	__asm {
		std     r14, -0x98(sp)
		std     r15, -0x90(sp)
		std     r16, -0x88(sp)
		std     r17, -0x80(sp)
		std     r18, -0x78(sp)
		std     r19, -0x70(sp)
		std     r20, -0x68(sp)
		std     r21, -0x60(sp)
		std     r22, -0x58(sp)
		std     r23, -0x50(sp)
		std     r24, -0x48(sp)
		std     r25, -0x40(sp)
		std     r26, -0x38(sp)
		std     r27, -0x30(sp)
		std     r28, -0x28(sp)
		std     r29, -0x20(sp)
		std     r30, -0x18(sp)
		std     r31, -0x10(sp)
		stw     r12, -0x8(sp)
		blr
	}
}
DWORD RelinkGPLR(DWORD SFSOffset, PDWORD SaveStubAddress, PDWORD OriginalAddress) {
	DWORD Instruction = 0, Replacing;
	PDWORD Saver = (PDWORD)GLPR;
	if (SFSOffset & 0x2000000) SFSOffset = SFSOffset | 0xFC000000;
	Replacing = OriginalAddress[SFSOffset / 4];
	for (INT i = 0; i < 20; i++) {
		if (Replacing == Saver[i]) {
			DWORD NewOffset = (DWORD)&Saver[i] - (DWORD)SaveStubAddress;
			Instruction = 0x48000001 | (NewOffset & 0x3FFFFFC);
		}
	} return Instruction;
}
VOID HookFunctionStart(PDWORD Address, PDWORD SaveStub, DWORD Destination) {
	if ((SaveStub != NULL) && (Address != NULL)) {
		DWORD AddressRelocation = (DWORD)(&Address[4]);
		if (AddressRelocation & 0x8000) {
			SaveStub[0] = 0x3D600000 + (((AddressRelocation >> 16) & 0xFFFF) + 1);
		}
		else {
			SaveStub[0] = 0x3D600000 + ((AddressRelocation >> 16) & 0xFFFF);
		}
		SaveStub[1] = 0x396B0000 + (AddressRelocation & 0xFFFF);
		SaveStub[2] = 0x7D6903A6;

		for (INT i = 0; i < 4; i++) {
			if ((Address[i] & 0x48000003) == 0x48000001) {
				SaveStub[i + 3] = RelinkGPLR((Address[i] & ~0x48000003), &SaveStub[i + 3], &Address[i]);
			}
			else {
				SaveStub[i + 3] = Address[i];
			}
		}
		SaveStub[7] = 0x4E800420; // Branch unconditionally
		__dcbst(0, SaveStub); // Data Cache Block Store | Allows a program to copy the contents of a modified block to main memory.
		__sync(); // Synchronize | Ensure the dcbst instruction has completed.
		__isync(); // Instruction Synchronize | Refetches any instructions that might have been fetched prior to this instruction.
		patchInJump(Address, Destination, FALSE); // Redirect Function to ours
	}
}

HRESULT SetMemory(VOID* Destination, VOID* Source, DWORD Length) {

	//// Try to resolve our function
	//if(DevSetMemory == NULL)
	//	DevSetMemory = (pDmSetMemory)ResolveFunction("xbdm.xex", 40);
	//
	//// Now lets try to set our memory
	//if(DevSetMemory == NULL) {
		memcpy(Destination, Source, Length);
		return ERROR_SUCCESS;
	//} else {
	//	if(DevSetMemory(Destination, Length, Source, NULL) == MAKE_HRESULT(0, 0x2da, 0))
	//		return ERROR_SUCCESS;
	//}

	// We have a problem..
	return E_FAIL;
}

void Logger( PWCHAR logMsg ){
	MessageBox(logMsg, L"Recon Log");
	//XNotify(logMsg);
    //std::string filePath = "Hdd:\\recon.txt";
    //std::string now = getCurrentDateTime("now");
    //std::ofstream ofs(filePath.c_str(), std::ios_base::out | std::ios_base::app );
    //ofs << now << '\t' << logMsg << '\n';
    //ofs.close();
}

		HRESULT setMemory(VOID* Destination, VOID* Source, DWORD Length)
		{



				memcpy(Destination, Source, Length);
				return ERROR_SUCCESS;
		}

				FARPROC resolveFunction(CHAR* ModuleName, DWORD Ordinal)
		{
			HMODULE mHandle = GetModuleHandle(ModuleName);
			return (mHandle == NULL) ? NULL : GetProcAddress(mHandle, (LPCSTR)Ordinal);
		}

DWORD PatchModuleImport(PLDR_DATA_TABLE_ENTRY Module, PCHAR ImportedModuleName, DWORD Ordinal, DWORD PatchAddress) {
			DWORD address = (DWORD)resolveFunction(ImportedModuleName, Ordinal);
			if (address == NULL)
				return S_FALSE;

			VOID* headerBase = Module->XexHeaderBase;
			PXEX_IMPORT_DESCRIPTOR importDesc = (PXEX_IMPORT_DESCRIPTOR)RtlImageXexHeaderField(headerBase, 0x000103FF);
			if (importDesc == NULL)
				return S_FALSE;

			DWORD result = 2;

			CHAR* stringTable = (CHAR*)(importDesc + 1);

			XEX_IMPORT_TABLE_ORG* importTable = (XEX_IMPORT_TABLE_ORG*)(stringTable + importDesc->NameTableSize);

			for (DWORD x = 0; x < importDesc->ModuleCount; x++)
			{
				DWORD* importAdd = (DWORD*)(importTable + 1);
				for (DWORD y = 0; y < importTable->ImportTable.ImportCount; y++)
				{
					DWORD value = *((DWORD*)importAdd[y]);
					if (value == address)
					{
						setMemory((DWORD*)importAdd[y], &PatchAddress, 4);
						DWORD newCode[4];
						patchInJump(newCode, PatchAddress, FALSE);
						setMemory((DWORD*)importAdd[y + 1], newCode, 16);
						result = S_OK;
					}
				}
				importTable = (XEX_IMPORT_TABLE_ORG*)(((BYTE*)importTable) + importTable->TableSize);
			}
			return result;
}

DWORD PatchModuleImport(PCHAR Module, PCHAR ImportedModuleName, DWORD Ordinal, DWORD PatchAddress) {
	PLDR_DATA_TABLE_ENTRY ModuleHandle = (PLDR_DATA_TABLE_ENTRY)GetModuleHandle(Module);
	return PatchModuleImport(ModuleHandle, ImportedModuleName, Ordinal, PatchAddress);
}

DWORD BytesRead, BytesWritten;
BOOL FileExists(PCHAR Path) {
	if (GetFileAttributes(Path) == -1) {
		DWORD LastError = GetLastError();
		if (LastError == ERROR_FILE_NOT_FOUND || LastError == ERROR_PATH_NOT_FOUND) {
			return FALSE;
		}
	} return TRUE;
}
BOOL ReadFileAlt(PCHAR Path, LPVOID Buffer, DWORD dwBytesToRead) {
	HANDLE hFile = CreateFile(Path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		CloseHandle(hFile); return FALSE;
	}
	ReadFile(hFile, Buffer, dwBytesToRead, &BytesRead, NULL);
	CloseHandle(hFile);
	return TRUE;
}
BOOL WriteFileAlt(PCHAR Path, LPCVOID Buffer, DWORD dwBytesToWrite) {
	HANDLE hFile = CreateFile(Path, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		CloseHandle(hFile); return FALSE;
	}
	WriteFile(hFile, Buffer, dwBytesToWrite, &BytesRead, NULL);
	CloseHandle(hFile);
	return TRUE;
}

VOID(__cdecl *XNotifyQueueUI)(DWORD dwType, DWORD dwUserIndex, DWORD dwPriority, LPCWSTR pwszStringParam, ULONGLONG qwParam) = (VOID(__cdecl *)(DWORD, DWORD, DWORD, LPCWSTR, ULONGLONG))ResolveFunction("xam.xex", 0x290);
VOID XNotifyThread(PWCHAR NotifyText) {
	XNotifyQueueUI(XNOTIFYUI_TYPE_CONSOLEMESSAGE, XUSER_INDEX_ANY, 2, NotifyText, NULL);
}
VOID XNotify(PWCHAR pwszStringParam) {
	if (KeGetCurrentProcessType() == USER_PROC) {
		HANDLE th = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)XNotifyThread, (LPVOID)pwszStringParam, CREATE_SUSPENDED, NULL);
		if (th == NULL) return;
		ResumeThread(th);
	}
	else {
		XNotifyQueueUI(XNOTIFYUI_TYPE_CONSOLEMESSAGE, XUSER_INDEX_ANY, 2, pwszStringParam, NULL);
	}
}
BOOL IsEmpty(PBYTE Buffer, DWORD Size) {
	for (DWORD i = 0; i < Size; i++) {
		if (Buffer[i] != NULL) {
			return FALSE;
		}
	}return TRUE;
}

