#pragma once
//#include "../wsconfig/WSSysconfig.h"
//#include "../wsconstant/wsconstant.h"
#include "capanalyzerstruct.h"
#include <map>
#include <string>
/**
 * @brief       class name: CCapPackageStatic
 * @use			pcap数据包链路分析和统计
					 1、全数据包解析模式：读取完所有数据包后，统一进行统计
					 2、可逐包统计模式：  读取一帧统计一帧
 * @author      尹浙洪
 * @version     ver1.0
 * @date        2010/8/23
 * example
 * @code
 *
 *
 *
 * @endcode
 */
typedef std::map <std::string, CAPCONNECTINFO*>	MAP_MAC_CAPCONNECTINFO;      //MAC地址链路map表
class CCapPackageStatic
{
public:
	CCapPackageStatic(void);
	~CCapPackageStatic(void);
public:
	
	/*****全数据统计链路信息*****/
	//int StaticAllPakcageLinks(CAPPARSERINFO*  pcapparserninfo, MAP_CAPMSGINFO*  pmapcapmsginfo,MAP_CAPCONNECTINFO* pmapcapconnectionfo);
	/*****单帧报文链路统计*****/
	CAPCONNECTINFO* StaticPackageLink(CAPPARSERINFO*  pcapparserninfo,CAPMSGGININFO * pCapMsgGinInfo,MAP_CAPCONNECTINFO* pmapcapconnectionfo);
	/*****统计报文类型个数，针对单帧报文*****/
    int StaticPakcageAppNum(CAPPARSERINFO*  pcapparserninfo, CAPMSGGININFO * pCapMsgGinInfo);

private:
	/*****当前链接是否存在*****/
	CAPCONNECTINFO* PackageLinkExist(CAPMSGGININFO * pCapMsgGinInfo);//const char* csource1,const char* csource2,int nappid,int nethertype);
	/*****创建新链接*****/
	CAPCONNECTINFO* CreatNewLink(int nIndex,CAPMSGGININFO* pCapMsgGinInfo);
	/*****当前链接是否存在******/
	int StaticExistPackage(CAPMSGGININFO* pCapMsgGinInfo,CAPCONNECTINFO * pCapconnectinfo);
private:
	CAPPARSERINFO*		m_pcapparserninfo;			//cap文件总结构
	MAP_CAPMSGINFO*		m_pmapcapmsginfo;			//所有消息map表指针
	MAP_CAPCONNECTINFO* m_pmapcapconnectionfo;		//所有链接map表指针
//	MAP_CAPCONNECTINFO  m_mapappid_capconnectionfo; //appid与链接的映射
	MAP_MAC_CAPCONNECTINFO m_mapappid_mac_capconnectionfo; //appid与链接的映射
	MAP_MAC_CAPCONNECTINFO m_map_mac_capconnectionfo; //appid与链接的映射
	MAP_MAC_CAPCONNECTINFO m_map_mac_reverse_capconnectionfo;//反向mac地址表

};

