/****************************************************
 *	Author: JoongHan. Kim
 *	Date:	2015. 03. 15
 *	File:	Util_1.cpp
 *	Role:	
 *  Modify: 
 *  Encoding: UTF-8 인코딩
 ****************************************************/

#include "Util_1.h"
#include "ThreadUtil.h"
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <sstream>


static char g_szLogPath[500];
static CThdCritSec g_LogCritSec;


#if !defined(WIN32)
#include <stdarg.h>
#include <uuid/uuid.h>
#include <unistd.h>
#include <pwd.h>
char *readSymLink(const char *path);
#else
#include <conio.h>
#include <time.h>
#define snprintf _snprintf
#endif


void SetLogPath()
{
#if defined(WIN32)
	DWORD dwSize = GetModuleFileNameA(NULL, g_szLogPath, 500);
	g_szLogPath[dwSize - 4] = 0;
    strncat(g_szLogPath, ".log", 499);
    //DeleteFileA(g_szLogPath);
#else
//    char *pPath = readSymLink("/proc/self/exe");
//    char *pPath = "/home/user01/LinuxServerApp";
//    strncpy(g_szLogPath, pPath, 499);
//    strncat(g_szLogPath, ".log", 499);

    struct passwd *pw = getpwuid(getuid());
    const char *pPath = pw->pw_dir;
    strncpy(g_szLogPath, pPath, 499);
    strncat(g_szLogPath, "/App.log", 499);
    remove(g_szLogPath); 
#endif //
}


#if defined(WIN32) && defined(UNICODE)

class CPerformanceFQ
{
public:
    CPerformanceFQ()
    {
        QueryPerformanceFrequency(&m_Frequency);
    }
    LARGE_INTEGER m_Frequency;

} g_PerformanceFQ;
CThdCritSec g_PerformanceLock;


void LogWriteW(unsigned int Flag, const char *pFunction, int Line, const WCHAR *Format, ...)
{
	WCHAR szLog[2048] = { 0, };
    va_list ap; 
	va_start(ap, Format);
	_vsnwprintf_s(szLog, 2048, 2047, Format, ap);
    va_end(ap);

	WCHAR szWrite[2048] = { 0, };
	if(Flag & LOGPRINT_FUNC)
	{
		STR_USES_CONVERSION;
		swprintf_s(szWrite, 2048, L"[%s:%d] %s\n", STR_A2W(pFunction), Line, szLog);
	}
	else if(Flag & LOGPRINT_TIME)
	{
		SYSTEMTIME st = { 0, };
		GetLocalTime(&st);
		swprintf_s(szWrite, 2048, L"[%02d:%02d:%02d:%03d] %s\n", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, szLog);
	}
	else
	{
		swprintf_s(szWrite, 2048, L"%s\n", szLog);
	}

	CThdAutoLock Lock(g_LogCritSec);
    STR_USES_CONVERSION;
	FILE *fp = NULL;
	if(!_wfopen_s(&fp, STR_A2W(g_szLogPath), L"a"))
	{
		fwprintf(fp, szWrite);
		fclose(fp);
	}
}

void ConsoleWriteW(unsigned int Flag, const char *pFunction, int Line, const WCHAR *Format, ...)
{
	WCHAR szLog1[2048] = { 0, };
	WCHAR szLog2[2048] = { 0, };
    va_list ap;
	va_start(ap, Format);
	_vsnwprintf_s(szLog1, 2048, 2047, Format, ap);
    va_end(ap);

	WCHAR *pLog = szLog1;

	if(Flag & LOGPRINT_FUNC)
	{
        STR_USES_CONVERSION;
		swprintf_s(szLog2, 2048, L"[%s:%d] %s", STR_A2W(pFunction), Line, szLog1);
		pLog = szLog2;
	}

	if(Flag & LOGPRINT_TIME)
	{
		CThdAutoLock Lock(g_LogCritSec);
		SYSTEMTIME st = { 0, };
		GetLocalTime(&st);
		_cwprintf(L"[%02d:%02d:%02d:%03d] %s\n", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, pLog);
	}
	else
	{
		CThdAutoLock Lock(g_LogCritSec);
		_cwprintf(L"%s\n", pLog);
	}
}
#endif //defined(WIN32) && defined(UNICODE)

void LogWriteA(unsigned int Falg, const char *pFunction, int Line, const char *Format, ...)
{		
	char szLog[2048] = { 0, };
    va_list ap; 
	va_start(ap, Format);
	vsnprintf(szLog, 2047, Format, ap);
    va_end(ap);

	char szWrite[2048] = { 0, };
	if(Falg & LOGPRINT_FUNC)
	{
		snprintf(szWrite, 2047, "[%s:%d] %s\n", pFunction, Line, szLog);
	}	
	else if(Falg & LOGPRINT_TIME)
	{
		time_t long_time;
		time(&long_time);
		tm *pt = localtime(&long_time);
		snprintf(szWrite, 2047, "[%02d:%02d:%02d] %s\n", pt->tm_hour, pt->tm_min, pt->tm_sec, szLog);
	}
	else
	{
		snprintf(szWrite, 2047, "%s\n", szLog);
	}
	
	CThdAutoLock Lock(g_LogCritSec);
	FILE *fp = fopen(g_szLogPath, "a");
	if(fp)
	{
		fprintf(fp, szWrite);
		fclose(fp);
	}
}


void ConsoleWriteA(unsigned int Flag, const char *pFunction, int Line, const char *Format, ...)
{		
	char szLog1[2048] = { 0, };
	char szLog2[2048] = { 0, };
    va_list ap;
	va_start(ap, Format);
	vsnprintf(szLog1, 2047, Format, ap);
    va_end(ap);

	char *pLog = szLog1;
	
	if(Flag & LOGPRINT_FUNC)
	{
		snprintf(szLog2, 2047, "[%s_%d] %s", pFunction, Line, szLog1);
		pLog = szLog2;
	}

	if(Flag & LOGPRINT_TIME)
	{
		CThdAutoLock Lock(g_LogCritSec);
		time_t long_time;
		time(&long_time);
		tm *pt = localtime(&long_time);
#ifdef WIN32
		_cprintf("[%02d:%02d:%02d] %s\n", pt->tm_hour, pt->tm_min, pt->tm_sec, pLog);
#else
		fprintf(stderr, "[%02d:%02d:%02d] %s\n", pt->tm_hour, pt->tm_min, pt->tm_sec, pLog);
#endif

	}
	else
	{
		CThdAutoLock Lock(g_LogCritSec);
#ifdef WIN32
        _cprintf("%s\n", pLog); 
#else
		fprintf(stderr, "%s\n", pLog); 
#endif
	}
}

#ifdef WIN32
#include <MMSystem.h>
#include <Iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma warning(disable: 4996)


void GetMACaddress(TCHAR *szMac, int cbMac, TCHAR *szIp, int cbIp)
{
	if(!szMac || !szIp) return;

	DWORD dwBufLen = sizeof(IP_ADAPTER_INFO);
	IP_ADAPTER_INFO *pInfo = (IP_ADAPTER_INFO *)new BYTE[dwBufLen];
	if(!pInfo) return;


	if(ERROR_BUFFER_OVERFLOW == GetAdaptersInfo(pInfo,	&dwBufLen))
	{
		delete pInfo;

		pInfo = (IP_ADAPTER_INFO *)new BYTE[dwBufLen];
		if(ERROR_SUCCESS != GetAdaptersInfo(pInfo,	&dwBufLen))
			return;
	}

	_sntprintf_s(szMac, cbMac, cbMac - 1, _T("%02X:%02X:%02X:%02X:%02X:%02X"),
										pInfo[0].Address[0],
										pInfo[0].Address[1],
										pInfo[0].Address[2],
										pInfo[0].Address[3],
										pInfo[0].Address[4],
										pInfo[0].Address[5]);
#ifdef UNICODE
	STR_USES_CONVERSION;
	_tcsncpy_s(szIp, cbIp, STR_A2W(pInfo[0].IpAddressList.IpAddress.String), cbIp - 1);
#else
	_tcsncpy_s(szIp, cbIp, pInfo[0].IpAddressList.IpAddress.String, cbIp - 1);
#endif //UNICODE
}


void GetMACaddressA(char *szMac, int cbMac, char *szIp, int cbIp)
{
	if(!szMac || !szIp) return;

	DWORD dwBufLen = sizeof(IP_ADAPTER_INFO);
	IP_ADAPTER_INFO *pInfo = (IP_ADAPTER_INFO *)new BYTE[dwBufLen];
	if(!pInfo) return;
	

	if(ERROR_BUFFER_OVERFLOW == GetAdaptersInfo(pInfo,	&dwBufLen))
	{
		delete pInfo;
		
		pInfo = (IP_ADAPTER_INFO *)new BYTE[dwBufLen];
        if(!pInfo) return;

		if(ERROR_SUCCESS != GetAdaptersInfo(pInfo,	&dwBufLen))
        {
            delete [] pInfo;
			return;
        }
	}

	snprintf(szMac, cbMac - 1, "%02X:%02X:%02X:%02X:%02X:%02X",
										pInfo[0].Address[0],
										pInfo[0].Address[1],
										pInfo[0].Address[2],
										pInfo[0].Address[3],
										pInfo[0].Address[4],
										pInfo[0].Address[5]);
	strncpy(szIp, pInfo[0].IpAddressList.IpAddress.String, cbIp - 1);

    delete [] pInfo;
}


BOOL ExecuteExternalFile(TCHAR *szExeName, TCHAR *szArguments, char **ppBuf, DWORD *pBufLen)
{
    TCHAR szCommand[4096] = { 0, };
    _sntprintf_s(szCommand, 4096, 4095, _T("\"%s\" %s"), szExeName, szArguments);    

    SECURITY_ATTRIBUTES SecAttr = { 0, };
    SecAttr.nLength = sizeof(SecAttr);
    SecAttr.bInheritHandle = TRUE;

    HANDLE hRPipe = NULL;
    HANDLE hWPipe = NULL;
    CreatePipe(&hRPipe, &hWPipe, &SecAttr, 0);

    STARTUPINFO sInfo = { 0, };    
    sInfo.cb         = sizeof(sInfo);
    sInfo.dwFlags    = STARTF_USESTDHANDLES;
    sInfo.hStdInput  = NULL;
    sInfo.hStdOutput = hWPipe;
    sInfo.hStdError  = hWPipe;

    PROCESS_INFORMATION Info = { 0, };
    if(!CreateProcess(NULL, szCommand, NULL, NULL, TRUE, NORMAL_PRIORITY_CLASS | CREATE_NO_WINDOW, NULL, NULL, &sInfo, &Info))
    {
        DWORD Error = GetLastError();
        return FALSE;
    }
    CloseHandle(hWPipe);
        
    BOOL res;
    int ReadUnit = 10;
    int BufSize  = 10;
    int CumulReadSize = 0;
    char *pBuf = (char *)malloc(ReadUnit);

    do
    {
        DWORD ReadByte = 0;

        if(BufSize < CumulReadSize + ReadUnit)
        {
            BufSize += ReadUnit;
            pBuf = (char *)realloc(pBuf, BufSize);            
        }

        res = ::ReadFile(hRPipe, pBuf + CumulReadSize, ReadUnit, &ReadByte, 0);

        CumulReadSize += ReadByte;        

    } while(res);

    if(pBuf)
    {
        *ppBuf = new char [CumulReadSize + 1];    
        memcpy(*ppBuf, pBuf, CumulReadSize);
        (*ppBuf)[CumulReadSize] = 0;
        *pBufLen = CumulReadSize + 1;

        free(pBuf); 
    }

    if(Info.hProcess)
    {
        WaitForSingleObject(Info.hProcess, 10000);
    }    
    
    return TRUE;
}


UINT64 GetMicroSystemTime()
{
    CThdAutoLock Lock(g_PerformanceLock);
    for(int i = 0; i < 10; i++)
    {
        LARGE_INTEGER PerformanceCount;    
        if(QueryPerformanceCounter(&PerformanceCount))
        {
            double fCount = (double)PerformanceCount.QuadPart;
            double fFQ    = (double)(double)g_PerformanceFQ.m_Frequency.QuadPart;
            double Div = fCount / fFQ;
            long long Count = (UINT64)(Div * 1000000);
            if(Count > 0) return Count;
        }
        else return 0;
    }
    return 0;
}


char *GetApplicationPathUTF8()
{
    WCHAR Path[MAX_PATH] = { 0, };
    DWORD len = GetModuleFileName(NULL, Path, MAX_PATH);
    if(!len) return 0;

    WCHAR *pExe = wcsrchr(Path, L'\\');
    if(!pExe) return 0;

    if(pExe - Path < 2)
        return 0;
    pExe[1] = 0;   
        
    STR_USES_CONVERSION;
    char *pUTF8 = STR_W2UTF8(Path); 
    
    return strdup(pUTF8);
}

void GenerateGUID(unsigned char Guid[16])
{
    CoCreateGuid((GUID *)Guid);
}

#else

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>

VDOSP_UINT64 GetMicroSystemTime()
{
	struct timeval time;
	gettimeofday(&time, 0); // #This actually returns a struct that has microsecond precision.
	VDOSP_UINT64 microsec = ((unsigned long long)time.tv_sec * 1000000) + time.tv_usec;

	return microsec;
}


char *readSymLink(const char *path)
{
    char *retval = 0;
    ssize_t len = 64;
    ssize_t rc = -1;

    while (1)
    {
        char *ptr = (char *) realloc(retval, (size_t) len);
        if (ptr == NULL)
            break;

        retval = ptr;

        rc = readlink(path, retval, len);
        if (rc == -1) {
            break;
        } else if (rc < len) {
            retval[rc] = '\0';
            return retval;
        }

        len *= 2;
    }

    free(retval);
    return 0;
}

char *GetApplicationPathUTF8()
{
    char *retval = readSymLink("/proc/self/exe");  
    if(!retval) return 0;

    char *pExe = strrchr(retval, L'/');
    if(!pExe) return 0;

    if(pExe - retval < 2)
        return 0;
    pExe[1] = 0;   

    return retval;
}

void GenerateGUID(unsigned char Guid[16])
{    
    uuid_t uuid;
    uuid_generate(uuid);
    memcpy(Guid, uuid, 16);
}

char* removing_string( char* str, int start, int end )
{
	int i, len = strlen(str);

	for(i=0; i<len; i++)
	{
		str[start+i-1] = str[end+i];
	}
	return str;
}

int strupr(char *str)
{
	int i=0;
	int len=0;
	len=strlen(str);
	for(i=0;i<len;i++){
		*(str+i)=_toupper(*(str+i));
	}
	return i;
}

int find_string( const char* str, const char* find )
{
	int i, k;
	int len1 = strlen(str);
	int len2 = strlen(find);
	for( i=0; i<len1; i++ )
	{
		for( k=0; k<len2; k++ )
		{
			if( str[i+k] != find[k] )
				break;
		}

		if( find[k] == 0 )
			return (i+1);
	}

	return -1;
}

const char *getUserName()
{
	uid_t uid = geteuid();
	struct passwd *pw = getpwuid(uid);
	if (pw)
	{
		return pw->pw_name;
	}

	return "";
}

const char *getUpdateMountPath(char * szReturnPath)
{
	sprintf(szReturnPath, "/home/%s/Update", getUserName());

	fprintf(stderr, " %s:%d szReturnPath[%s]\n", __FILE__, __LINE__, szReturnPath);

	return szReturnPath;
}

const char *getTemplatesMountPath(char * szReturnPath)
{
	sprintf(szReturnPath, "/home/%s/Templates", getUserName());

	return szReturnPath;
}
#endif //WIN32


