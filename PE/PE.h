/*
* -------------------------------------------------------------------------------------------
* | ���ѣ��˿��е����к�����Ĭ�ϰ����������в���,�������Ҫ�뿼��ʹ�ú��� PE_GetFOAByRVA �ĺ�����  |
* -------------------------------------------------------------------------------------------
*/
#ifndef _PE_
#define _PE_
#include <Windows.h>

//��ȡDOSͷ
PIMAGE_DOS_HEADER WINAPI PE_GetDosHeader(LPVOID lpBuffer);

//��ȡNTͷ
PIMAGE_NT_HEADERS WINAPI PE_GetNtHeader(LPVOID lpBuffer);

//��ȡNT�ļ�ͷ
PIMAGE_FILE_HEADER WINAPI PE_GetFileHeader(LPVOID lpBuffer);

//��ȡNT��ѡ�ļ�ͷ
PIMAGE_OPTIONAL_HEADER WINAPI PE_GetOptionalFileHeader(LPVOID lpBuffer);

//���PE�ļ��Ϸ���
BOOL WINAPI PE_CheckPEFileVaild(LPVOID lpBuffer);

//���ַ�����ȡ��Ӧ������ͷ
PIMAGE_SECTION_HEADER WINAPI PE_GetSectionHeaderByNameA(LPVOID lpBuffer,LPCSTR szSectionName);

//�ɿ��ֽ��ַ�����ȡ��Ӧ������ͷ
PIMAGE_SECTION_HEADER WINAPI PE_GetSectionHeaderByNameW(LPVOID lpBuffer, LPCWSTR wszSectionName);

//��RVA����ΪFOA
DWORD WINAPI PE_GetFOAByRVA(LPVOID lpBuffer, DWORD dwTargetRVA);

//�ɻ�ȡ��������
DWORD WINAPI PE_GetExportFunctionAddress(LPVOID lpBuffer, LPCSTR szFunctionName);

typedef VOID(WINAPI* _PE_REPAIRRELOC_DEFAULTHANDLER)(LPVOID, DWORD, PDWORD);

//�޸��ض�λ��(�޸�������Զ��壬Ĭ�� _PE_RepairReloc_DefaultHandler)
BOOL WINAPI PE_RepairReloc(LPVOID lpBuffer, DWORD dwNewImageBase, _PE_REPAIRRELOC_DEFAULTHANDLER fnRepairHandler = NULL);

//Ĭ�ϵ��ض�λ���޸�����
VOID WINAPI _PE_RepairReloc_DefaultHandler(LPVOID lpBuffer, DWORD dwNewImageBase, PDWORD pdwRepairAddr);

//���ַ�����ȡ��Ӧ����������RVA
LPVOID WINAPI PE_GetSectionDataRVAByNameA(LPVOID lpBuffer, LPCSTR szSectionName);

//�ɿ��ֽ��ַ�����ȡ��Ӧ����������RVA
LPVOID WINAPI PE_GetSectionDataRVAByNameW(LPVOID lpBuffer, LPCWSTR wszSectionName);

//����PE�ļ����ļ�����ֵ���������ṩ����ֵ�����ķ���ֵ
DWORD WINAPI PE_AlignFile(LPVOID lpBuffer, DWORD dwValue);

//����PE�ļ����������ֵ���������ṩ����ֵ�����ķ���ֵ
DWORD WINAPI PE_AlignSection(LPVOID lpBuffer, DWORD dwValue);
typedef VOID(WINAPI* _PE_REPAIRIAT_DEFAULTHANDLER)(LPDWORD,LPCSTR, LPCSTR);

//Ĭ�ϵ�IAT���޸�����
VOID WINAPI _PE_RepairIAT_DefaultHandler(LPDWORD lpIATItem, LPCSTR szDllName, LPCSTR szFunctionName);

//�޸�IAT��(�޸�������Զ��壬Ĭ�� _PE_RepairIAT_DefaultHandler)
BOOL WINAPI PE_RepairIAT(LPVOID lpBuffer, _PE_REPAIRIAT_DEFAULTHANDLER fnRepairHandler = NULL);

//�޸��ļ�����ʱ���
VOID WINAPI PE_SetTimeDateStamp(LPVOID lpBuffer,DWORD dwNewTimeDateStamp);

//ö�ٵ�����������ص��ص�����
VOID WINAPI PE_EnumExportTableFunction(LPVOID lpBuffer,LPVOID CallBack);

//ö�ٵ�����Dll��
VOID WINAPI PE_EnumImportTableDlls(LPVOID lpBuffer, LPVOID CallBack);

//ö�ٵ�����Dll�Ķ�Ӧ���뺯����
VOID WINAPI PE_EnumImportTableDllFunctions(LPVOID lpBuffer, LPVOID CallBack);

//ö������ͷ��
VOID WINAPI PE_EnumSectionHeader(LPVOID lpBuffer, LPVOID CallBack);


#endif