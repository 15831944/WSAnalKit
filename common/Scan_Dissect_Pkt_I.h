#if !defined(_SCAN_DISSECT_PKT_I_H)
#define _SCAN_DISSECT_PKT_I_H
/**
 * @brief       数据包解析接口
 * @use			wirshark数据包解析封装接口
 * @author      尹浙洪
 * @version     ver1.0
 * @date        2012/10/17
 * example
 * @code
 *
 *
 *
 * @endcode
 */
#include "Scan_Dissect_Pkt_Struct.h"

#ifdef OS_WINDOWS

#ifdef PKT_DISSECT_DLL
//根据数据包类型，解析数据包
extern "C"  __declspec( dllexport ) XJ_DISSECT_PKT*  xj_dissect_packet(const char* cdatabuffer,int nbufferlength);
//根据数据包类型，解析数据包_windows下离线试用
extern "C"  __declspec( dllexport ) XJ_DISSECT_PKT* xj_dissect_packet_offline_mms(const char* cdatabuffer,unsigned int nbufferlength,unsigned int nframenum,unsigned int nfile_off,unsigned int ncum_bytes,unsigned int nseconds,unsigned nuseconds);
//释放数据包
extern "C"  __declspec( dllexport )              int xj_cleanup_packet(XJ_DISSECT_PKT* xj_dissect_pkt);
//释放会话（比如单个抓包文件解析过程）
extern "C"  __declspec( dllexport )              void xj_cleanup_dissect();
#else 
//根据数据包类型，解析数据包
extern "C"  __declspec( dllimport ) XJ_DISSECT_PKT*  xj_dissect_packet(const char* cdatabuffer,int nbufferlength);
//释放数据包
extern "C"  __declspec( dllimport )             int  xj_cleanup_packet(XJ_DISSECT_PKT* xj_dissect_pkt);
#endif
#endif //OS_WINDOWS

#ifdef OS_LINUX
#ifdef __cplusplus
extern "C"
{
#endif
//根据数据包类型，解析数据包
	XJ_DISSECT_PKT*  xj_dissect_packet(const char* cdatabuffer,int nbufferlength);
//释放数据包
int  xj_cleanup_packet(XJ_DISSECT_PKT* xj_dissect_pkt);
//释放会话（比如单个抓包文件解析过程）
void xj_cleanup_dissect();
#ifdef __cplusplus
}
#endif
#endif//OS_LINUX

#endif//#define _SCAN_DISSECT_PKT_I_H