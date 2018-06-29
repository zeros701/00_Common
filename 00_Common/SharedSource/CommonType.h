/****************************************************
 *	Author: JoongHan. Kim
 *	Date:	2015. 03. 15
 *	File:	CommonType.h
 *	Role:	
 *  Modify: 
 *  Encoding: UTF-8 인코딩
 ****************************************************/

#ifndef __COMMONTYPE_H__
#define __COMMONTYPE_H__

typedef char               VDOSP_INT8;
typedef short              VDOSP_INT16;
typedef unsigned char      VDOSP_UINT8;
typedef unsigned short     VDOSP_UINT16;
typedef unsigned int       VDOSP_UINT32;
typedef unsigned long long VDOSP_UINT64;

#ifdef WIN32
    #ifdef _DEBUG
        #ifndef DEBUG_NEW
            //#include <crtdbg.h>
            //#define DEBUG_NEW new(_NORMAL_BLOCK, __FILE__, __LINE__)
            //#define new DEBUG_NEW
        #endif //DEBUG_NEW
    #endif //
    #define snprintf _snprintf
#else
    #define strnicmp strncasecmp
#endif //WIN32


#endif //__COMMONTYPE_H__


