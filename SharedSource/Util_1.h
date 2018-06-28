/****************************************************
 *	Author: JoongHan. Kim
 *	Date:	2015. 03. 15
 *	File:	Util_1.h
 *	Role:	
 *  Modify: 
 *  Encoding: UTF-8 인코딩
 ****************************************************/

#ifndef __UTIL1_H__
#define __UTIL1_H__


#include "CommonType.h"
#include <string>
#include <stdio.h>


//#define SHOWDBGLOG


#if defined(WIN32)
#include <tchar.h>
#include <Windows.h>
typedef TCHAR LOGCHAR;
#undef snprintf
#define snprintf _snprintf
#else
#define _T(x) x
typedef char LOGCHAR;
#endif 

using namespace std;

//20121030 jhkim
#define LOGPRINT_NONE 0
#define LOGPRINT_TIME 1
#define LOGPRINT_FUNC 2

VDOSP_UINT64 GetMicroSystemTime();
char *GetApplicationPathUTF8();
void GenerateGUID(unsigned char Guid[16]);

void SetLogPath();
void LogWrite(unsigned int Flag, const char *pFunction, int Line, const LOGCHAR *Format, ...);

class CUTILFunctionReturnLog
{
public:
    char *m_pFunction;
    CUTILFunctionReturnLog(char *pFuction) { m_pFunction = pFuction; fprintf(stderr, "%s [S]\n", pFuction); }
    ~CUTILFunctionReturnLog() { fprintf(stderr, "%s [E]\n", m_pFunction); }
};

#ifdef SHOWDBGLOG
    #if defined(WIN32) && defined(UNICODE)
        void LogWriteW(unsigned int Flag, const char *pFunction, int Line, const WCHAR *Format, ...);
        void ConsoleWriteW(unsigned int Flag, const char *pFunction, int Line, const WCHAR *Format, ...);
        void ConsoleWriteA(unsigned int Flag, const char *pFunction, int Line, const char *Format, ...);

        #define LOGOUT(Format, ...) LogWriteW(LOGPRINT_NONE, __FUNCTION__, __LINE__, Format, ##__VA_ARGS__)
        #define LOGOUTT(Format, ...) LogWriteW(LOGPRINT_TIME, __FUNCTION__, __LINE__, Format, ##__VA_ARGS__)
        #define LOGOUTF(Format, ...) LogWriteW(LOGPRINT_FUNC, __FUNCTION__, __LINE__, Format, ##__VA_ARGS__)
        #define LOGOUTTF(Format, ...) LogWriteW(LOGPRINT_TIME | LOGPRINT_FUNC, __FUNCTION__, __LINE__, Format, ##__VA_ARGS__)

        #define CONLOG(Format, ...) ConsoleWriteW(LOGPRINT_NONE, __FUNCTION__, __LINE__, Format, ##__VA_ARGS__)
        #define CONLOGT(Format, ...) ConsoleWriteW(LOGPRINT_TIME, __FUNCTION__, __LINE__, Format, ##__VA_ARGS__)
        #define CONLOGF(Format, ...) ConsoleWriteW(LOGPRINT_FUNC, __FUNCTION__, __LINE__, Format, ##__VA_ARGS__)
        #define CONLOGTF(Format, ...) ConsoleWriteW(LOGPRINT_TIME | LOGPRINT_FUNC, __FUNCTION__, __LINE__, Format, ##__VA_ARGS__)

        #define CONLOG_A(Format, ...) ConsoleWriteA(LOGPRINT_NONE, __FUNCTION__, __LINE__, Format, ##__VA_ARGS__)
        #define CONLOGT_A(Format, ...) ConsoleWriteA(LOGPRINT_TIME, __FUNCTION__, __LINE__, Format, ##__VA_ARGS__)
        #define CONLOGF_A(Format, ...) ConsoleWriteA(LOGPRINT_FUNC, __FUNCTION__, __LINE__, Format, ##__VA_ARGS__)
        #define CONLOGTF_A(Format, ...) ConsoleWriteA(LOGPRINT_TIME | LOGPRINT_FUNC, __FUNCTION__, __LINE__, Format, ##__VA_ARGS__)
    #else
        void LogWriteA(unsigned int Flag, const char *pFunction, int Line, const char *Format, ...);
        void ConsoleWriteA(unsigned int Flag, const char *pFunction, int Line, const char *Format, ...);

        #define LOGOUT(Format, ...) LogWriteA(LOGPRINT_NONE, __FUNCTION__, __LINE__, Format, ##__VA_ARGS__)
        #define LOGOUTF(Format, ...) LogWriteA(LOGPRINT_FUNC, __FUNCTION__, __LINE__, Format, ##__VA_ARGS__)
        #define LOGOUTTF(Format, ...) LogWriteA(LOGPRINT_TIME | LOGPRINT_FUNC, __FUNCTION__, __LINE__, Format, ##__VA_ARGS__)

        #define CONLOG(Format, ...) ConsoleWriteA(LOGPRINT_NONE, __FUNCTION__, __LINE__, Format, ##__VA_ARGS__)
        #define CONLOGT(Format, ...) ConsoleWriteA(LOGPRINT_TIME, __FUNCTION__, __LINE__, Format, ##__VA_ARGS__)
        #define CONLOGF(Format, ...) ConsoleWriteA(LOGPRINT_FUNC, __FUNCTION__, __LINE__, Format, ##__VA_ARGS__)
        #define CONLOGTF(Format, ...) ConsoleWriteA(LOGPRINT_TIME | LOGPRINT_FUNC, __FUNCTION__, __LINE__, Format, ##__VA_ARGS__)

        #define CONLOG_A(Format, ...) ConsoleWriteA(LOGPRINT_NONE, __FUNCTION__, __LINE__, Format, ##__VA_ARGS__)
        #define CONLOGT_A(Format, ...) ConsoleWriteA(LOGPRINT_TIME, __FUNCTION__, __LINE__, Format, ##__VA_ARGS__)
        #define CONLOGF_A(Format, ...) ConsoleWriteA(LOGPRINT_FUNC, __FUNCTION__, __LINE__, Format, ##__VA_ARGS__)
        #define CONLOGTF_A(Format, ...) ConsoleWriteA(LOGPRINT_TIME | LOGPRINT_FUNC, __FUNCTION__, __LINE__, Format, ##__VA_ARGS__)
    #endif //defined(WIN32) && defined(UNICODE)

    #define FUNCTIONRETURNLOG() CUTILFunctionReturnLog RetrunLog(__FUNCTION__);
#else
	#define LOGOUT
	#define LOGOUTT
	#define LOGOUTF
	#define LOGOUTTF

	#define CONLOG
	#define CONLOGT
	#define CONLOGF
	#define CONLOGTF

    #define CONLOG_A
    #define CONLOGT_A
    #define CONLOGF_A
    #define CONLOGTF_A

    #define FUNCTIONRETURNLOG
#endif //_DEBUG



#ifdef WIN32
//20120910 jhkim
#define STR_USES_CONVERSION const char *__pA = NULL; const WCHAR *__pW = NULL; int __ConvSize = 0;


inline WCHAR *STR_StrConvA2W(WCHAR *pW, const char *pA, int nChars)
{
	if(!pW) return NULL;
	if(!pA) return NULL;
	pW[0] = 0;
	MultiByteToWideChar(CP_ACP, 0, pA, -1, pW, nChars);
	return pW;
}


inline char *STR_StrConvW2A(char *pA, const WCHAR *pW, int nChars)
{
	if(!pW) return NULL; 
	if(!pA) return NULL;
	pA[0] = 0;
	WideCharToMultiByte(CP_ACP, 0, pW, -1, pA, nChars, NULL, NULL);
	return pA;
}


inline WCHAR *STR_StrConvUTF82W(WCHAR *pW, const char *pA, int nChars)
{
	if(!pW) return NULL;
	if(!pA) return NULL;
	pW[0] = 0;
	MultiByteToWideChar(CP_UTF8, 0, pA, -1, pW, nChars);
	return pW;
}


inline char *STR_StrConvW2UTF8(char *pA, const WCHAR *pW, int nChars)
{
	if(!pW) return NULL;
	if(!pA) return NULL;
	pA[0] = 0;
	WideCharToMultiByte(CP_UTF8, 0, pW, -1, pA, nChars, NULL, NULL);
	return pA;
}


#define STR_A2W(pA)																								   \
(																												   \
	((__pA = pA) == NULL) ? NULL :																				   \
	(__ConvSize = (lstrlenA(__pA) + 1), STR_StrConvA2W((WCHAR *)alloca(__ConvSize * 2), __pA, __ConvSize))	       \
)

#define STR_W2A(pW)																									\
(																													\
	((__pW = pW) == NULL) ? NULL :																					\
	(__ConvSize = (lstrlenW(__pW) + 1) * 2, STR_StrConvW2A((char *)alloca(__ConvSize), __pW, __ConvSize))			\
)

#define STR_UTF82W(pA)																								\
(																													\
	((__pA = pA) == NULL) ? NULL :																					\
	(__ConvSize = (lstrlenA(__pA) + 1), STR_StrConvUTF82W((WCHAR *)alloca(__ConvSize * 2), __pA, __ConvSize))	    \
)

#define STR_W2UTF8(pW)																								\
(																													\
	((__pW = pW) == NULL) ? NULL :																					\
	(__ConvSize = (lstrlenW(__pW) + 1) * 3, STR_StrConvW2UTF8((char *)alloca(__ConvSize), __pW, __ConvSize))	    \
)

void GetMACaddress(TCHAR *szMac, int cbMac, TCHAR *szIp, int cbIp);
void GetMACaddressA(char *szMac, int cbMac, char *szIp, int cbIp);
BOOL ExecuteExternalFile(TCHAR *szExeName, TCHAR *szArguments, char **ppBuf, DWORD *pBufLen);
#else
char* removing_string( char* str, int start, int end );
int strupr(char *str);
int find_string( const char* str, const char* find );
const char *getUserName();
const char *getUpdateMountPath(char * szReturnPath);
const char *getTemplatesMountPath(char * szReturnPath);
#endif //WIN32


#if !defined(WIN32)
#include <dlfcn.h>
#endif

class CSharedModule
{
public:
    CSharedModule(const char *pModuleName)
    {
        m_hModule = 0;
        Load(pModuleName);
    }

    CSharedModule()
    {
        m_hModule = 0;
    }

    ~CSharedModule()
    {
        Free();
    }

    bool Load(const char *pModuleName)
    {        
        if(!pModuleName)
            return false;

        CONLOGF(_T("pModuleName"));

        char szName[255] = { 0, }; 
#if defined(WIN32)
        if(strlen(pModuleName) > 1 && pModuleName[1] == ':')
        {
            m_hModule = LoadLibraryA(pModuleName);
        }
        else
        {
            snprintf(szName, 254, "%s.dll", pModuleName);
            m_hModule = LoadLibraryA(szName);
        }
#else
        if(pModuleName[0] == '/')
        {
            m_hModule = dlopen(pModuleName, RTLD_NOW);
        }
        else
        {
        	char *pAppPath = GetApplicationPathUTF8();
        	if(!pAppPath) return false;
            snprintf(szName, 254, "%slib%s.so", pAppPath, pModuleName);
            CONLOGF(_T("%s"), szName);
            m_hModule = dlopen(szName, RTLD_NOW);
            CONLOGF(_T("%08x=dlopen"), m_hModule);
        }
        CONLOGF(_T("dlsym [%s]"), dlerror());
#endif 
        if(m_hModule)
            return true;

        return false;
    }

    void *GetProcAddress(char *pProcName)
    {
        if(!m_hModule)
            return 0;

#if defined(WIN32)
        return ::GetProcAddress(m_hModule, pProcName);
#else
        return dlsym(m_hModule, pProcName);
#endif
    }

    void Free()
    {
        if(m_hModule)
        {
#if defined(WIN32)
            FreeLibrary(m_hModule);
#else
            dlclose(m_hModule);
#endif
            m_hModule = 0;
        }
    }

private:
#ifdef WIN32
    HMODULE m_hModule;
#else
    void   *m_hModule;
#endif
};


#endif //__UTIL1_H__
