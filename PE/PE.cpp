#include "PE.h"

DWORD WINAPI PE_GetExportFunctionAddress(LPVOID lpBuffer, LPCSTR szFunctionName) {
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpBuffer;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD)lpBuffer + pDos->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((DWORD)lpBuffer + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	DWORD dwNum = pExport->NumberOfFunctions;
	PDWORD pdwName = (PDWORD)(pExport->AddressOfNames + (DWORD)lpBuffer);
	PWORD pwOrder = (PWORD)(pExport->AddressOfNameOrdinals + (DWORD)lpBuffer);
	PDWORD pdwFuncAddr = (PDWORD)(pExport->AddressOfFunctions + (DWORD)lpBuffer);
	for (UINT i = 0; i < dwNum; i++) {
		LPCSTR lpFuncName = (LPCSTR)(pdwName[i] + (DWORD)lpBuffer);
		if (strcmp(lpFuncName, szFunctionName)) {
			WORD wOrd = pwOrder[i];
			return (DWORD)lpBuffer + pdwFuncAddr[wOrd];
		}
	}
	return 0;
}

DWORD WINAPI PE_GetFOAByRVA(LPVOID lpBuffer, DWORD dwTargetRVA) {
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpBuffer;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD)lpBuffer + pDos->e_lfanew);
	if (dwTargetRVA <= pNt->OptionalHeader.SizeOfHeaders) {
		return dwTargetRVA;
	}
	PIMAGE_SECTION_HEADER pFirstSec = IMAGE_FIRST_SECTION(pNt);
	for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
		if (dwTargetRVA >= pFirstSec[i].VirtualAddress && dwTargetRVA <= pFirstSec[i].VirtualAddress + pFirstSec[i].SizeOfRawData) {
			DWORD ret = (dwTargetRVA - pFirstSec[i].VirtualAddress) + pFirstSec[i].PointerToRawData;
			return ret;
		}
	}
	return 0;
}

PIMAGE_DOS_HEADER WINAPI PE_GetDosHeader(LPVOID lpBuffer) {
	return ((PIMAGE_DOS_HEADER)lpBuffer);
}

PIMAGE_NT_HEADERS WINAPI PE_GetNtHeader(LPVOID lpBuffer) {
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpBuffer;
	return ((PIMAGE_NT_HEADERS)((DWORD)lpBuffer + pDos->e_lfanew));
}

BOOL WINAPI PE_CheckPEFileVaild(LPVOID lpBuffer) {
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpBuffer;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD)lpBuffer + pDos->e_lfanew);
	return (pDos->e_magic == IMAGE_DOS_SIGNATURE && pNt->Signature == IMAGE_NT_SIGNATURE);
}


PIMAGE_SECTION_HEADER WINAPI PE_GetSectionHeaderByNameA(LPVOID lpBuffer, LPCSTR szSectionName) {
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpBuffer;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD)lpBuffer + pDos->e_lfanew);
	PIMAGE_SECTION_HEADER pFirstSection = IMAGE_FIRST_SECTION(pNt);
	for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
		if (strcmp((LPCSTR)pFirstSection[i].Name, szSectionName) == 0) {
			return &pFirstSection[i];
		}
	}
	return 0;
}

PIMAGE_SECTION_HEADER WINAPI PE_GetSectionHeaderByNameW(LPVOID lpBuffer, LPCWSTR wszSectionName) {
	//PE_GetSectionHeaderByNameA();
	return NULL;
}

BOOL WINAPI PE_RepairReloc(LPVOID lpBuffer, DWORD dwNewImageBase, _PE_REPAIRRELOC_DEFAULTHANDLER pfnRepairHandler) {
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpBuffer;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD)lpBuffer + pDos->e_lfanew);
	PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)((DWORD)lpBuffer + (pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress));
	if (pReloc->SizeOfBlock == 0 && pReloc->VirtualAddress == 0) {
		return FALSE;
	}
	if (pfnRepairHandler == NULL) {
		pfnRepairHandler = _PE_RepairReloc_DefaultHandler;
	}
	while (pReloc->VirtualAddress != 0) {
		struct TypeOffset {
			WORD offset : 12;
			WORD type : 4;
		};
		TypeOffset* pTypeOffs = (TypeOffset*)(pReloc + 1);
		DWORD dwCount = (pReloc->SizeOfBlock - 8) / 2;
		for (UINT i = 0; i < dwCount; i++) {
			if (pTypeOffs[i].type != 3) {
				continue;
			}
			PDWORD pdwRepairAddr = (PDWORD)((DWORD)lpBuffer + (pReloc->VirtualAddress + pTypeOffs[i].offset), lpBuffer);
			pfnRepairHandler(lpBuffer, dwNewImageBase, pdwRepairAddr);
			
		}
		pReloc = (PIMAGE_BASE_RELOCATION)((DWORD)pReloc + pReloc->SizeOfBlock);
	}
	return TRUE;
}

VOID WINAPI _PE_RepairReloc_DefaultHandler(LPVOID lpBuffer, DWORD dwNewImageBase, PDWORD pdwRepairAddr) {
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpBuffer;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD)lpBuffer + pDos->e_lfanew);
	*pdwRepairAddr -= pNt->OptionalHeader.ImageBase;
	*pdwRepairAddr += dwNewImageBase;
	return;
}

LPVOID WINAPI PE_GetSectionDataRVAByNameA(LPVOID lpBuffer,LPCSTR lpSectionName) {
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpBuffer;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD)lpBuffer + pDos->e_lfanew);
	PIMAGE_SECTION_HEADER pFirstSection = IMAGE_FIRST_SECTION(pNt);
	for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
		if (strcmp((LPCSTR)pFirstSection[i].Name, lpSectionName) == 0) {
			return (LPVOID)pFirstSection[i].VirtualAddress;
		}
	}
	return 0;
}

LPVOID WINAPI PE_GetSectionDataRVAByNameW(LPVOID lpBuffer, LPCWSTR wszSectionName) {
	//PE_GetSectionDataRVAByNameA
	return NULL;
}

DWORD WINAPI PE_AlignFile(LPVOID lpBuffer, DWORD dwValue) {
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpBuffer;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD)lpBuffer + pDos->e_lfanew);
	if (dwValue / pNt->OptionalHeader.FileAlignment * pNt->OptionalHeader.FileAlignment == dwValue) {
		return dwValue;
	}
	return ((dwValue / pNt->OptionalHeader.FileAlignment) + 1) * pNt->OptionalHeader.FileAlignment;
}

DWORD WINAPI PE_AlignSection(LPVOID lpBuffer, DWORD dwValue) {
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpBuffer;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD)lpBuffer + pDos->e_lfanew);
	if (dwValue / pNt->OptionalHeader.SectionAlignment * pNt->OptionalHeader.SectionAlignment == dwValue) {
		return dwValue;
	}
	return ((dwValue / pNt->OptionalHeader.SectionAlignment) + 1) * pNt->OptionalHeader.SectionAlignment;
}

BOOL WINAPI PE_RepairIAT(LPVOID lpBuffer, _PE_REPAIRIAT_DEFAULTHANDLER fnRepairHandler) {
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpBuffer;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD)lpBuffer + pDos->e_lfanew);
	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)lpBuffer + (pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));
	UINT count = (pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR)) - 2;
	if (count <= 0) {
		return FALSE;
	}
	if (fnRepairHandler == NULL) {
		fnRepairHandler = _PE_RepairIAT_DefaultHandler;
	}
	for (UINT i = 0; i < count; i++) {
		LPDWORD lpIATItem = (LPDWORD)((DWORD)lpBuffer + (pImport[i].FirstThunk, pNt));
		for (; *lpIATItem; lpIATItem++) {
			if (*lpIATItem & 0x80000000) {
				continue;
			}
			PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((DWORD)lpBuffer + (*lpIATItem));
			LPCSTR szDllName = (LPCSTR)((DWORD)lpBuffer + (pImport[i].Name));
			fnRepairHandler(lpIATItem, szDllName, pImportByName->Name);
			if (*lpIATItem == NULL) {
				return FALSE;
			}
		}
	}
	return TRUE;
}

VOID WINAPI _PE_RepairIAT_DefaultHandler(LPDWORD lpIATItem, LPCSTR szDllName, LPCSTR szFunctionName) {
	*lpIATItem = (DWORD)GetProcAddress(LoadLibraryA(szDllName), szFunctionName);
	return;
}

PIMAGE_FILE_HEADER WINAPI PE_GetFileHeader(LPVOID lpBuffer) {
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpBuffer;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD)lpBuffer + pDos->e_lfanew);
	return  &(pNt->FileHeader);
}

PIMAGE_OPTIONAL_HEADER WINAPI PE_GetOptionalFileHeader(LPVOID lpBuffer) {
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpBuffer;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD)lpBuffer + pDos->e_lfanew);
	return &(pNt->OptionalHeader);
}