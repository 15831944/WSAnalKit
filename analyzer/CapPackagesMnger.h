#pragma once
#include "capanalyzerstruct.h"
//#include "CapTransformer.h"

/* pcap文件报文查询过滤 */
class CCapPackagesMnger
{
public:
	CCapPackagesMnger(void);
	~CCapPackagesMnger(void);
public:
	/******清空资源*******/
	void FreeSource(void);

	/************把报文放入对应队列*****************/
    int  AddPacket2MnGrList(CAPMSGGININFO * pCapPackage);

	/************根据报文类型获取总列表*****************/
    CAPCONNECTINFO* GetPcapconnetInfo(int npcapconnectType);

	/************根据报文源端或者目的获取总列表*****************/
	CAPCONNECTINFO* GetPcapconnetInfo_bySrc1_Src2(char* src1_addr,char* src2_addr);

	/************根据报文源端或者目的获取总列表*****************/
	CAPCONNECTINFO* GetPcapconnetInfo_byAppID(int appid);

	/************根据报文查询条件从队列中查询出对应报文****************/
    int GetNewFilterConnectionByCondition(MAP_CAPMSGINFO map_capmsginfo_src,
                 MAP_CAPMSGINFO* pmap_capmsginfo_dst,PACKETQUER_FILTER *pQuery_Filter);
public:
	CAPPARSERINFO      m_capparserninfo;		    //cap文件总结构
//	MAP_CAPMSGINFO     m_mapcapmsginfo;			    //消息map表
	MAP_CAPCONNECTINFO m_mapcapconnectionfo;        //连接map表
	CAPCONNECTINFO     m_pcapconnectinfoTotal;      //全部链接中的数据
	CAPCONNECTINFO     m_pcapconnetionfoTotal_MMS;  //全部MMS报文
	CAPCONNECTINFO     m_pcapconnetionfoTotal_SV;   //全部SV报文
	CAPCONNECTINFO     m_pcapconnetionfoTotal_GOOSE;//全部GOOSE报文
	CAPCONNECTINFO     m_pcapconnetionfoTotal_TCP;  //全部TCP报文
	CAPCONNECTINFO     m_pcapconnetionfoTotal_UDP;  //全部TCP报文
	CAPCONNECTINFO     m_pcapconnetionfoTotal_ARP;  //全部ARP报文
	CAPCONNECTINFO     m_pcapconnetionfoTotal_OTHER;//全部其它报文
	CAPCONNECTINFO     m_pcapconnetionfoTotal_PTP;  //全部PTP报文
};

