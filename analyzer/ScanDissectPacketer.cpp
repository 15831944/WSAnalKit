#pragma execution_character_set("UTF-8")
#include "ScanDissectPacketer.h"
#include "xjlib.h"
#include "const_scan.h"


CScanDissectPacketer::CScanDissectPacketer(void)
{
	m_hDllInst            = NULL;
	m_pxj_Dissect_Packet  = NULL;
	m_pxj_Cleanup_Packet  = NULL;
	m_pxj_Dissect_Packet_OffLine_mms = NULL;
}

CScanDissectPacketer::~CScanDissectPacketer(void)
{
}
/**
* @brief	Initialize         初始化，加载动态库，导出库函数,需被外部显性调用
* @param 	const char * cLibPathName  动态库所在路径,需相对路径+动态库名称
* @return	int 0表示成功
* @notes	无
* @sample	无
*/
int CScanDissectPacketer::Initialize(const char * cLibPathName)
{
	if(NULL == cLibPathName)
	{
		return -1;
	}
//	try
	{
		//加载库
        m_hDllInst = xj_load_library(cLibPathName);
		if(NULL == m_hDllInst)
		{
			return -1;
		}
		//导入库函数
        m_pxj_Dissect_Packet = (XJ_DISSECT_PACKET) xj_get_addr(m_hDllInst,"xj_dissect_packet");
        m_pxj_Cleanup_Packet = (XJ_CLEANUP_PACKET) xj_get_addr(m_hDllInst,"xj_cleanup_packet");
        m_pxj_Dissect_Packet_OffLine_mms = (XJ_DISSECT_PACKET_OFFLINE_MMS) xj_get_addr(m_hDllInst,"xj_dissect_packet_offline_mms");
        m_pxj_Cleanup_Dissect = (XJ_CLEANUP_DISSECT) xj_get_addr(m_hDllInst,"xj_cleanup_dissect");
		if(NULL == m_pxj_Dissect_Packet || NULL == m_pxj_Cleanup_Packet|| NULL == m_pxj_Dissect_Packet_OffLine_mms || NULL ==m_pxj_Cleanup_Dissect)//初始化失败
		{
			return -1;
		}
		return 0;
	}
//	catch (CException* e)
//	{
//		e->Delete();
//	}

	return -1;
}

/*
* @brief	UnInitialize         释放动态库
* @param 	
* @return	int 0表示成功
* @notes	无
* @sample	无
*/
int CScanDissectPacketer::UnInitialize()
{
	if(m_hDllInst != NULL)
	{
        xj_free_library(m_hDllInst);
		m_pxj_Dissect_Packet  = NULL;
		m_pxj_Cleanup_Packet  = NULL;
	}
	return 0;
}
/************解析数据包*****/
XJ_DISSECT_PKT*  CScanDissectPacketer::I_XJ_DISSECT_PACKET(CAPMSGGININFO * pCapPackage,unsigned int nseq)
{
	if(NULL == m_pxj_Dissect_Packet_OffLine_mms || NULL == pCapPackage )
		return NULL;
	//报文解析
	if(pCapPackage->csourceinfo == NULL|| pCapPackage->nsourceinfo_length < 56)
		return NULL;
	if(pCapPackage->pxj_dissect_pkt != NULL)//已经解析的不重新解析
		return pCapPackage->pxj_dissect_pkt;
	XJ_DISSECT_PKT*  pkt=NULL;
	if (pCapPackage->napptype!=ETHER_TYPE_DROP)
	{//初始化的时候，没有解析报文树，需要进一步解析
		pkt = m_pxj_Dissect_Packet(pCapPackage->csourceinfo+16,pCapPackage->nsourceinfo_length-16);
		//填充报文部分信息
		if(pkt != NULL)
		{
			FillPkt2MsgBrief(pkt,pCapPackage);
		}
	}
	return pkt;
}
/************解析MMS数据包*****/
XJ_DISSECT_PKT*  CScanDissectPacketer::I_XJ_DISSECT_MMS_PACKET(CAPMSGGININFO * pCapPackage,unsigned int nseq)
{
	if(NULL == m_pxj_Dissect_Packet || NULL == pCapPackage )
		return NULL;
	//报文解析
	if(pCapPackage->csourceinfo == NULL|| pCapPackage->nsourceinfo_length < 56)
		return NULL;
	XJ_DISSECT_PKT*  pkt = m_pxj_Dissect_Packet_OffLine_mms(pCapPackage->csourceinfo+16,pCapPackage->nsourceinfo_length-16,nseq,0,0,0,0);
	//填充报文部分信息
	if(pkt != NULL)
	{
		FillPkt2MsgBrief(pkt,pCapPackage);
	}
	return pkt;
}
/************解析数据包*****/
XJ_DISSECT_PKT*  CScanDissectPacketer::I_XJ_DISSECT_MUL_PACKET(CAPMSGGININFO * pCapPackage,unsigned int nseq)
{
	if(NULL == m_pxj_Dissect_Packet || NULL == pCapPackage)
		return NULL;
	if(pCapPackage->pxj_dissect_pkt != NULL)//已解析的，先清空
	{
		I_XJ_CLEANUP_PACKET(pCapPackage->pxj_dissect_pkt);
		pCapPackage->pxj_dissect_pkt = NULL;
	}
	XJ_DISSECT_PKT*  pkt;
	//调用解析接口
	if(pCapPackage->csourceinfo_cotp != NULL)
	{
		pkt = m_pxj_Dissect_Packet(pCapPackage->csourceinfo_cotp+16,pCapPackage->nsourceinfo_cotp_length-16);
	}
	//填充报文部分信息
	if(pkt != NULL)
	{
		FillPkt2MsgBrief(pkt,pCapPackage);
	}
	return pkt;
}
/*******释放数据包数据包*****/
int CScanDissectPacketer::I_XJ_CLEANUP_PACKET(XJ_DISSECT_PKT* xj_dissect_pkt)
{
	if(xj_dissect_pkt == NULL || m_pxj_Cleanup_Packet == NULL)
		return -1;
	//调用释放接口
	return m_pxj_Cleanup_Packet(xj_dissect_pkt);
}
void CScanDissectPacketer::I_XJ_CLEANUP_DISSECT()
{
	if (m_pxj_Cleanup_Dissect)
		m_pxj_Cleanup_Dissect();
}
int CScanDissectPacketer::FillPkt2MsgBrief(XJ_DISSECT_PKT* xj_dissect_pkt,CAPMSGGININFO * pCapPackage)
{
	//填充报文基本信息
	pCapPackage->pxj_dissect_pkt = xj_dissect_pkt;
//	strcpy(pCapPackage->csrc_ip,xj_dissect_pkt->ip_src);
//	strcpy(pCapPackage->cdst_ip,xj_dissect_pkt->ip_dst);
//	strcpy(pCapPackage->csrc_mac,xj_dissect_pkt->mac_src);
//	strcpy(pCapPackage->cdst_mac,xj_dissect_pkt->mac_dst);
	pCapPackage->nsrc_port  = xj_dissect_pkt->port_src;
	pCapPackage->ndst_port  = xj_dissect_pkt->port_dst;
	if (xj_dissect_pkt->ether_type != PKT_ETHER_TYPE_UNKOWN)
	{
		pCapPackage->napptype   = xj_dissect_pkt->ether_type;
	}

	return 0;
}
