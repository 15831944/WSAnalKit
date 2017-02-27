#pragma once
/********************************************************************
*	filename: 	WpcapLoader
*	author:		yinzhehong
*	created:	2011/11/30
*	purpose:  	pcap文件用wpcap文件加载，并调用packet2convert.dll库解析 
*   version:    1.0
*********************************************************************/
#include "capanalyzerstruct.h"
#include "Packet2Message.h"

class CPackageCovertWrapper
{
public:
	CPackageCovertWrapper(void);
	~CPackageCovertWrapper(void);

private:
	int PACKE2MSG_INIT();
	int my_itoa(int val, char* buf, int radix);
	int Hex2Binary(char *cHex);

public:
	//得到解析后的报文内容
	 int Make61850Struct_Pack2Msg(CAPMSGGININFO* pCapMsgGinInfo,PACKET_STRUCT* pPacket);

     /*根据解析标志位返回采样值报文处理结果*/
     string GetSVFormatErrorDesc(unsigned int u_result);

     /*根据解析标志位返回GOOSE报文处理结果*/
     string GetGOOSEFormatErrorDesc(unsigned int u_result);

	//释放解析后的报文
	int Release61850Struct_Pack2Msg(CAPMSGGININFO* pMsg);

	//解析MAC
	int ParseMac(char *p_packet_buf, char *p_mac);

	//解析IP
	int ParseIP(char *p_packet_buf, char *p_ip);

    //解析品质
	int ParseQuality(char *p_quality_buf,char *p_quality);

    //解析时间
	int ParseAvtm(char *p_packet_buf, char *c_avtm);

    //ETH2报文头分析
	int ETHER_TYPE_ETH2_Head_Aanalyze(CAPMSGGININFO*  pCapMsgGinInfo,PACKET_STRUCT* pPacketChar);

    //IP报文头分析
	int ETHER_TYPE_IP_Head_Aanalyze(CAPMSGGININFO*  pCapMsgGinInfo,PACKET_STRUCT* pPacket);

    //UDP报文解析
	int ETHER_TYPE_UDP_Head_Aanalyze(CAPMSGGININFO*  pCapMsgGinInfo,PACKET_STRUCT* pPacket);

    //TCP报文头分析
	int ETHER_TYPE_TCP_Head_Aanalyze(CAPMSGGININFO*  pCapMsgGinInfo,PACKET_STRUCT* pPacket);

    //ARP报文头分析
	int ETHER_TYPE_ARP_Head_Aanalyze(CAPMSGGININFO*  pCapMsgGinInfo,PACKET_STRUCT* pPacket);

	/******COTP连续报文分析****/
	int COTP_LIST_ANALYZE(CAPCONNECTINFO* pConnection);
	int Cotp_List_Aanlyze_Detail(MAP_CAPMSGINFO map_capmsginfo,CAPCONNECTINFO* pConnection,BOOL bdst2_src);
	bool Cotp_Packet_Fin(MAP_CAPMSGINFO& map_capmsginfo_cotplist,CAPMSGGININFO* pCapMsgGinInfo_first);
	int Cotp_Packet_Aanlyze(MAP_CAPMSGINFO map_capmsginfo_cotplist,CAPMSGGININFO* pCapMsgGinInfo_first);

    //获取tcp报文的应用报文长度以及开始位置指针
	char* Get_TcpSegments_Position(char* p_packet_src,unsigned int packet_src_length,unsigned int& ntcp_segment_length);

    //从TPKT报文中获取COPT报文的开始指针以及长度
    char* Get_CoptSegments_Postion_FromTpktPackage(char* p_tpkt_src,
                unsigned int& tpkt_src_length,unsigned int& ncoptsegement_length,bool& blastdataunit);

    /*得到IP层起始位置*/
	int GetIP_ST_POSITION(char* p_packet_src);
    void setLinkType(int nLinkType)
	{
         m_pkt2msg.packetconvert_set_linkType(nLinkType);
     }

private:

    PKTCONVERT_CFG_STRUCT m_CfgInfo;
    CPacketConvert m_pkt2msg;

};

