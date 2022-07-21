/*
* -------------------------------------------------------------------------------------------
* | 提醒：此库中的所有函数都默认按区块对齐进行操作,若情况需要请考虑使用函数 PE_GetFOAByRVA 的合理性  |
* -------------------------------------------------------------------------------------------
*/
#ifndef _PE_
#define _PE_
#include <Windows.h>

//获取DOS头
PIMAGE_DOS_HEADER WINAPI PE_GetDosHeader(LPVOID lpBuffer);

//获取NT头
PIMAGE_NT_HEADERS WINAPI PE_GetNtHeader(LPVOID lpBuffer);

//获取NT文件头
PIMAGE_FILE_HEADER WINAPI PE_GetFileHeader(LPVOID lpBuffer);

//获取NT可选文件头
PIMAGE_OPTIONAL_HEADER WINAPI PE_GetOptionalFileHeader(LPVOID lpBuffer);

//检查PE文件合法性
BOOL WINAPI PE_CheckPEFileVaild(LPVOID lpBuffer);

//由字符串获取对应的区块头
PIMAGE_SECTION_HEADER WINAPI PE_GetSectionHeaderByNameA(LPVOID lpBuffer,LPCSTR szSectionName);

//由宽字节字符串获取对应的区块头
PIMAGE_SECTION_HEADER WINAPI PE_GetSectionHeaderByNameW(LPVOID lpBuffer, LPCWSTR wszSectionName);

//由RVA换算为FOA
DWORD WINAPI PE_GetFOAByRVA(LPVOID lpBuffer, DWORD dwTargetRVA);

//由获取导出函数
DWORD WINAPI PE_GetExportFunctionAddress(LPVOID lpBuffer, LPCSTR szFunctionName);

typedef VOID(WINAPI* _PE_REPAIRRELOC_DEFAULTHANDLER)(LPVOID, DWORD, PDWORD);

//修复重定位表(修复程序可自定义，默认 _PE_RepairReloc_DefaultHandler)
BOOL WINAPI PE_RepairReloc(LPVOID lpBuffer, DWORD dwNewImageBase, _PE_REPAIRRELOC_DEFAULTHANDLER fnRepairHandler = NULL);

//默认的重定位表修复程序
VOID WINAPI _PE_RepairReloc_DefaultHandler(LPVOID lpBuffer, DWORD dwNewImageBase, PDWORD pdwRepairAddr);

//由字符串获取对应的区块数据RVA
LPVOID WINAPI PE_GetSectionDataRVAByNameA(LPVOID lpBuffer, LPCSTR szSectionName);

//由宽字节字符串获取对应的区块数据RVA
LPVOID WINAPI PE_GetSectionDataRVAByNameW(LPVOID lpBuffer, LPCWSTR wszSectionName);

//根据PE文件的文件对齐值，返回所提供的数值对齐后的返回值
DWORD WINAPI PE_AlignFile(LPVOID lpBuffer, DWORD dwValue);

//根据PE文件的区块对齐值，返回所提供的数值对齐后的返回值
DWORD WINAPI PE_AlignSection(LPVOID lpBuffer, DWORD dwValue);
typedef VOID(WINAPI* _PE_REPAIRIAT_DEFAULTHANDLER)(LPDWORD,LPCSTR, LPCSTR);

//默认的IAT表修复程序
VOID WINAPI _PE_RepairIAT_DefaultHandler(LPDWORD lpIATItem, LPCSTR szDllName, LPCSTR szFunctionName);

//修复IAT表(修复程序可自定义，默认 _PE_RepairIAT_DefaultHandler)
BOOL WINAPI PE_RepairIAT(LPVOID lpBuffer, _PE_REPAIRIAT_DEFAULTHANDLER fnRepairHandler = NULL);

//修改文件创建时间戳
VOID WINAPI PE_SetTimeDateStamp(LPVOID lpBuffer,DWORD dwNewTimeDateStamp);

//枚举导出表。结果返回到回调函数
VOID WINAPI PE_EnumExportTableFunction(LPVOID lpBuffer,LPVOID CallBack);

//枚举导出表Dll。
VOID WINAPI PE_EnumImportTableDlls(LPVOID lpBuffer, LPVOID CallBack);

//枚举导出表Dll的对应导入函数。
VOID WINAPI PE_EnumImportTableDllFunctions(LPVOID lpBuffer, LPVOID CallBack);

//枚举区块头。
VOID WINAPI PE_EnumSectionHeader(LPVOID lpBuffer, LPVOID CallBack);


#endif