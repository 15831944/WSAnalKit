#pragma once
/********************************************************************
*	filename: 	CScanDissectPacketer
*	author:		yinzhehong
*	created:	2012/10/24
*	purpose:  	动态库操作类，用于使用对CScanDissectPacket封装的动态库        
*   version:    1.0
*********************************************************************/
#include "Scan_Dissect_Pkt_I.h"
#include "capanalyzerstruct.h"
#include "xjlib.h"

/************解析数据包*****/
 typedef XJ_DISSECT_PKT*  (*XJ_DISSECT_PACKET)(const char* cdatabuffer,int nbufferlength);
 /****离线解析数据包专用 add by yzh 20130401*********/
 typedef XJ_DISSECT_PKT*  (*XJ_DISSECT_PACKET_OFFLINE_MMS)(const char* cdatabuffer,unsigned int nbufferlength,unsigned int nframenum,unsigned int nfile_off,unsigned int cum_bytes,unsigned int nseconds,unsigned nuseconds);
 /*******释放数据包数据包*****/
 typedef int (*XJ_CLEANUP_PACKET)(XJ_DISSECT_PKT* xj_dissect_pkt);
 typedef void(*XJ_CLEANUP_DISSECT)();
class CScanDissectPacketer
{
public:
	CScanDissectPacketer(void);
	~CScanDissectPacketer(void);
public:
	/*初始化，加载动态库，导出库函数,cLibPathFullName为动态库相对路径+动态库名称*/
	int Initialize(const char *cLibPathName);
	/*卸载动态库*/
	int UnInitialize();
public:
	/************解析数据包*****/
	XJ_DISSECT_PKT*  I_XJ_DISSECT_PACKET(CAPMSGGININFO * pCapPackage,unsigned int nseq);
	/************解析MMS数据包*****/
	XJ_DISSECT_PKT* I_XJ_DISSECT_MMS_PACKET(CAPMSGGININFO * pCapPackage,unsigned int nseq);
	/************解析多帧数据包*****/
	XJ_DISSECT_PKT*  I_XJ_DISSECT_MUL_PACKET(CAPMSGGININFO * pCapPackage,unsigned int nseq);
	/*******释放数据包数据包*****/
	int I_XJ_CLEANUP_PACKET(XJ_DISSECT_PKT* xj_dissect_pkt);
	void I_XJ_CLEANUP_DISSECT();
private:
	/*加载动态库后返回的句柄*/
    XJHANDLE				  m_hDllInst;
private:
	XJ_DISSECT_PACKET m_pxj_Dissect_Packet;
	XJ_CLEANUP_PACKET m_pxj_Cleanup_Packet;
	XJ_DISSECT_PACKET_OFFLINE_MMS m_pxj_Dissect_Packet_OffLine_mms;
	XJ_CLEANUP_DISSECT m_pxj_Cleanup_Dissect;
private:
	int FillPkt2MsgBrief(XJ_DISSECT_PKT* xj_dissect_pkt,CAPMSGGININFO * pCapPackage);

};

