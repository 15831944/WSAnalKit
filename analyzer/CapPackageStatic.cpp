#pragma execution_character_set("UTF-8")
#include "CapPackageStatic.h"
#include "define_scan.h"
#include "const_scan.h"
#include "wsconstant.h"
#include "xjlib.h"


//数据包统计，生成各种链路信息
CCapPackageStatic::CCapPackageStatic(void)
{
	m_pcapparserninfo     = NULL;			//cap文件总结构,需外部设置
	m_pcapparserninfo	  = NULL;			//所有消息
	m_pmapcapconnectionfo = NULL;			//连接
}

CCapPackageStatic::~CCapPackageStatic(void)
{
	//m_mapappid_capconnectionfo.clear();
	m_mapappid_mac_capconnectionfo.clear();
	std::map <std::string, CAPCONNECTINFO*>().swap(m_mapappid_mac_capconnectionfo);
	m_map_mac_capconnectionfo.clear(); //mac与链接的映射
	std::map <std::string, CAPCONNECTINFO*>().swap(m_map_mac_capconnectionfo);
	m_map_mac_reverse_capconnectionfo.clear();//反向mac地址表
	std::map <std::string, CAPCONNECTINFO*>().swap(m_map_mac_reverse_capconnectionfo);
}
/**
* @brief	StaticPackageLink                         统计单帧链路
* @param 	CAPPARSERINFO*  pcapparserninfo           文件的总信息
* @param 	 CAPMSGGININFO * pCapMsgGinInfo           数据包
* @param 	 MAP_CAPCONNECTINFO* pmapcapconnectionfo  链接队列
* @return	CAPCONNECTINFO *                          新链路，或者已有链路指针
* @notes	外部一次性加载好数据包后,调用本函数一次性进行统计
* @sample	无
*/
CAPCONNECTINFO*  CCapPackageStatic::StaticPackageLink(CAPPARSERINFO*  pcapparserninfo,CAPMSGGININFO * pCapMsgGinInfo,MAP_CAPCONNECTINFO* pmapcapconnectionfo)
{
	//参数检验
	if(pcapparserninfo == NULL || pCapMsgGinInfo == NULL || pmapcapconnectionfo == NULL)
	{
		return NULL;
	}
	BOOL bNewConnect = FALSE;
	CAPCONNECTINFO * pCapconnectinfo = NULL;
	m_pcapparserninfo     = pcapparserninfo;			//cap文件总结构,需外部设置
	m_pmapcapconnectionfo = pmapcapconnectionfo;		//连接
	if(pCapMsgGinInfo->napptype == ETHER_TYPE_ARP || pCapMsgGinInfo->napptype == ETHER_TYPE_UDP)//arp报文和UDP报文单独统计,放在一个统一链路中
	{
		std::map <int, CAPCONNECTINFO*>::iterator iter;
		iter = pmapcapconnectionfo->begin();
		pCapconnectinfo = iter->second;
	}
	else
	{
		pCapconnectinfo = PackageLinkExist(pCapMsgGinInfo);//->csrc_mac,pCapMsgGinInfo->cdst_mac,pCapMsgGinInfo->napp_id,pCapMsgGinInfo->napptype);//判断链路是否存在
	}
	if(pCapconnectinfo == NULL)//发现新链路
	{
		bNewConnect = TRUE;
		//创建新链路,将新链路加入链路队列中
		pCapconnectinfo = CreatNewLink(pmapcapconnectionfo->size() + 1,pCapMsgGinInfo);
		pcapparserninfo->nconnects += 1;                                   //链接个数+1
		//统计链路帧数
		StaticExistPackage(pCapMsgGinInfo,pCapconnectinfo);				   //统计
	}
	else//发现已有链路，直接统计
	{
		StaticExistPackage(pCapMsgGinInfo,pCapconnectinfo);
	}
	//应用报文类型统数量统计
	StaticPakcageAppNum(pcapparserninfo, pCapMsgGinInfo);
	//将错误报文增加到队列中
	if(pCapMsgGinInfo->nAppConetentGood == 0)
	{
		pCapconnectinfo->map_capmsginfo_error.insert(std::map <int, CAPMSGGININFO*> :: value_type(pCapconnectinfo->nerrpackages, pCapMsgGinInfo));
		pCapconnectinfo->nerrpackages ++;//错误报文增加
	}
	if(pCapMsgGinInfo->beventanalyzedgoose == true)//事件报文 add by yinzhehong 20130321
	{
		pCapconnectinfo->map_capmsginfo_event.insert(std::map <int, CAPMSGGININFO*> :: value_type(pCapconnectinfo->neventpackages, pCapMsgGinInfo));
		pCapconnectinfo->neventpackages ++;	//事件报文增加)
	}
	return pCapconnectinfo;
}
/**
* @brief	StaticPakcageAppNum   统计应用报文个数
* @param 	CAPPARSERINFO*  pcapparserninfo           文件的总信息
* @param 	 APMSGGININFO * pCapMsgGinInfo            单个数据包信息
* @return	int
* @notes	
* @sample	无
*/
int CCapPackageStatic::StaticPakcageAppNum(CAPPARSERINFO*  pcapparserninfo, CAPMSGGININFO * pCapMsgGinInfo)
{
	if(pcapparserninfo == NULL || pCapMsgGinInfo == NULL)
	{
		return -1;
	}
	//记录总包数累加
	pcapparserninfo->napppackages ++;
	//总字节数累加
	pcapparserninfo->lTotalCapLenth += pCapMsgGinInfo->ncap_len;//字节
	CAPCONNECTINFO* pCapconnectinfo = (CAPCONNECTINFO*) pCapMsgGinInfo->pcapconnect;
	//时间累加
	pcapparserninfo->ftime_lastpk_2_first = pCapconnectinfo->ftime_relative_last;
	//报文统计
	switch(pCapMsgGinInfo->napptype)
	{
	case PROTOAPPTYPE_SMV92:
		pcapparserninfo->napp92packages ++;
		break;
	case PROTOAPPTYPE_GOOSE:
		pcapparserninfo->nappgoosepackages ++;
		break;
	case PROTOAPPTYPE_MMS:
		pcapparserninfo->nappmmspackages ++;
		break;
	case  PROTOAPPTYPE_OTHER:
		pcapparserninfo->nappotherpackages ++;
		break;
	case PROTOAPPTYPE_TIME1588:
		pcapparserninfo->ntime1588packages ++;
		break;
	case PROTOAPPTYPE_ARP:
		pcapparserninfo->nappbroadcastpackages ++;
		break;
	case PROTOAPPTYPE_UDP:
		pcapparserninfo->nappudppackages ++;
		break;
	case  PROTOAPPTYPE_TCP:
		pcapparserninfo->napptcppackages ++;
		break;
	case  PROTOAPPTYPE_SMV91:
		pcapparserninfo->napp91packages ++;
		break;
	default:
		pcapparserninfo->nappotherpackages ++;
		break;
	}
	return 0;
}
/**
* @brief	PackageLinkExist            当前链接是否存在,如果appid存在，比较appid,否则根据报文类型来比较
* @param 	const char* csource1         
* @param 	const char* csource2         
* @param 	const char* cappid          应用数据编号，当数据包为采样或者goose时不为空
* @return	CAPCONNECTINFO*             已经存在的链接
* @notes	链接仅比较MAC地址
* @sample	无
*/
CAPCONNECTINFO* CCapPackageStatic::PackageLinkExist(CAPMSGGININFO * pCapMsgGinInfo)//const char* csource1,const char* csource2,int nappid,int nethertype)
{
	std::map <int, CAPCONNECTINFO*>::iterator iter;
	CAPCONNECTINFO * pCapconnectinfo = NULL;
	char itemkeywords[60],itemkeywords_revers[60];
	memset(itemkeywords,0,60);
	memset(itemkeywords_revers,0,60);
	int nappid = pCapMsgGinInfo->napp_id;
	if( nappid> 0)//smv-goose报文处理
	{
		sprintf(itemkeywords,"%x_%s",nappid,pCapMsgGinInfo->csrc_mac);    //名称合并
		std::string str(itemkeywords);
		std::map <std::string, CAPCONNECTINFO*>::iterator  iterconnectinfo = m_mapappid_mac_capconnectionfo.find(str);
		if(iterconnectinfo != m_mapappid_mac_capconnectionfo.end())
		{
			pCapconnectinfo = iterconnectinfo->second;
		}
	}
	else//其它类型的报文处理
	{
		if (pCapMsgGinInfo->napptype==ETHER_TYPE_DROP)
		{
			sprintf(itemkeywords,"%s","DropOrErr");  
		}
		else if (pCapMsgGinInfo->napptype==IEC61850_ETHER_TYPE_PTP_1588)
		{
			sprintf(itemkeywords,"%s","Ptp1588V2");
		}
		else if(strlen(pCapMsgGinInfo->csrc_ip))
		{
			sprintf(itemkeywords,"%s%s",pCapMsgGinInfo->csrc_ip,pCapMsgGinInfo->cdst_ip);          //名称合并
		}
		else if(strlen(pCapMsgGinInfo->csrc_mac))
		{
			sprintf(itemkeywords,"%s%s",pCapMsgGinInfo->csrc_mac,pCapMsgGinInfo->cdst_mac);           //名称合并
		}
		else
		{
			//
		}
		//src1->src2
		std::string str(itemkeywords);
		std::map <std::string, CAPCONNECTINFO*>::iterator iter = m_map_mac_capconnectionfo.find(str);
		if(iter != m_map_mac_capconnectionfo.end())
		{
			pCapconnectinfo = iter->second;
//			if(pCapconnectinfo != NULL)
//				pCapconnectinfo->map_capmsginfo_sr1_2_sr2.insert(std::map <int, CAPMSGGININFO*> :: value_type(pCapMsgGinInfo->nseq, pCapMsgGinInfo));
		}
		//src2->src1
		iter = m_map_mac_reverse_capconnectionfo.find(str);
		if(iter != m_map_mac_reverse_capconnectionfo.end())
		{
			pCapconnectinfo = iter->second;
//			if(pCapconnectinfo != NULL)
//				pCapconnectinfo->map_capmsginfo_sr2_2_sr1.insert(std::map <int, CAPMSGGININFO*> :: value_type(pCapMsgGinInfo->nseq, pCapMsgGinInfo));
		}
	}
	return pCapconnectinfo;
}
//创建一个新联接
/**
* @brief	CreatNewLink                 创建一个新链接
* @param 	int nIndex                   链接编号
* @param 	CAPMSGGININFO* pCapMsgGinInfo  
* @return	CAPCONNECTINFO*              新链接
* @notes	链接仅比较MAC地址
* @sample	无
*/
CAPCONNECTINFO * CCapPackageStatic::CreatNewLink(int nIndex,CAPMSGGININFO* pCapMsgGinInfo)
{
	//创建
	CAPCONNECTINFO * pCapconnectinfo = NULL;
    try
    {
		pCapconnectinfo = new CAPCONNECTINFO();								   //申请结构定义空间
		pCapconnectinfo->pcapparserinfo = m_pcapparserninfo;				   //联接对应的文件

		pCapconnectinfo->nconnectapptype = pCapMsgGinInfo->napptype;           //取报文的应用数据类型
		pCapconnectinfo->nseq            = nIndex;                             //顺序编号
		pCapconnectinfo->ncapp_id        = pCapMsgGinInfo->napp_id;            //应用数据编号

        time_to_string(pCapMsgGinInfo->nseconds_utc_tmstamp, pCapMsgGinInfo->nus_tmstamp, pCapconnectinfo->cstarttimestamp);
        pCapconnectinfo->ftime_relative_first = pCapMsgGinInfo->ftime_relative;
		pCapconnectinfo->ftime_relative_last  = pCapMsgGinInfo->ftime_relative;
		pCapMsgGinInfo->ftime_delta_capconnect = 0.0;
		pCapMsgGinInfo->ftime_relative_capconnect = 0.0;
		strcpy_s(pCapconnectinfo->csrc1_ip,pCapMsgGinInfo->csrc_ip);
		strcpy_s(pCapconnectinfo->csrc2_ip,pCapMsgGinInfo->cdst_ip);
		//mac地址
		strcpy_s(pCapconnectinfo->csrc1_mac,pCapMsgGinInfo->csrc_mac);
		strcpy_s(pCapconnectinfo->csrc2_mac,pCapMsgGinInfo->cdst_mac);
		//加入总map表
		m_pmapcapconnectionfo->insert(std::map <int, CAPCONNECTINFO*> :: value_type(nIndex, pCapconnectinfo));
		//创建MAC地址表
		char itemkeywords[60];
		memset(itemkeywords,0,60);

		if(pCapMsgGinInfo->napp_id > 0)//加入appid队列
		{
			sprintf(itemkeywords,"%x_%s",pCapMsgGinInfo->napp_id,pCapMsgGinInfo->csrc_mac);    //名称合并
			m_mapappid_mac_capconnectionfo.insert(std::map <std::string, CAPCONNECTINFO*> :: value_type(itemkeywords,pCapconnectinfo));
		}
		else
		{
			if (pCapMsgGinInfo->napptype==ETHER_TYPE_DROP)
			{
				sprintf(itemkeywords,"%s","DropOrErr");    //名称合并,可以考虑像udp-arp一样，放在前面
				m_map_mac_capconnectionfo.insert(std::map <std::string, CAPCONNECTINFO*>::value_type(itemkeywords,pCapconnectinfo));
				memset(itemkeywords,0,60);
				sprintf(itemkeywords,"%s","DropOrErr");    //名称合并
				m_map_mac_reverse_capconnectionfo.insert(std::map <std::string, CAPCONNECTINFO*>::value_type(itemkeywords,pCapconnectinfo));

			}
			else  if (pCapMsgGinInfo->napptype==IEC61850_ETHER_TYPE_PTP_1588)
			{
				sprintf(itemkeywords,"%s","Ptp1588V2");    //名称合并,可以考虑像udp-arp一样，放在前面
				m_map_mac_capconnectionfo.insert(std::map <std::string, CAPCONNECTINFO*>::value_type(itemkeywords,pCapconnectinfo));
				memset(itemkeywords,0,60);
				sprintf(itemkeywords,"%s","Ptp1588V2");    //名称合并
				m_map_mac_reverse_capconnectionfo.insert(std::map <std::string, CAPCONNECTINFO*>::value_type(itemkeywords,pCapconnectinfo));

			}
			else if(strlen(pCapMsgGinInfo->csrc_ip) > 0)//ip地址的MAP
			{
				//端口
				pCapconnectinfo->nsrc1_port = pCapMsgGinInfo->nsrc_port;
				pCapconnectinfo->nsrc2_port = pCapMsgGinInfo->ndst_port;

				sprintf(itemkeywords,"%s%s",pCapMsgGinInfo->csrc_ip,pCapMsgGinInfo->cdst_ip);    //名称合并
				m_map_mac_capconnectionfo.insert(std::map <std::string, CAPCONNECTINFO*>::value_type(itemkeywords,pCapconnectinfo));
				memset(itemkeywords,0,60);
				sprintf(itemkeywords,"%s%s",pCapMsgGinInfo->cdst_ip,pCapMsgGinInfo->csrc_ip);    //名称合并
				m_map_mac_reverse_capconnectionfo.insert(std::map <std::string, CAPCONNECTINFO*>::value_type(itemkeywords,pCapconnectinfo));
			}
			else if(strlen(pCapMsgGinInfo->csrc_mac) > 0)//ip地址的MAP//mac地址的MAP
			{
				sprintf(itemkeywords,"%s%s",pCapMsgGinInfo->csrc_mac,pCapMsgGinInfo->cdst_mac);    //名称合并
				m_map_mac_capconnectionfo.insert(std::map <std::string, CAPCONNECTINFO*>::value_type(itemkeywords,pCapconnectinfo));
				memset(itemkeywords,0,60);
				sprintf(itemkeywords,"%s%s",pCapMsgGinInfo->cdst_mac,pCapMsgGinInfo->csrc_mac);    //名称合并
				m_map_mac_reverse_capconnectionfo.insert(std::map <std::string, CAPCONNECTINFO*>::value_type(itemkeywords,pCapconnectinfo));
			}
			else
			{
			}
			//加入源端的统计
	//		pCapconnectinfo->map_capmsginfo_sr1_2_sr2.insert(std::map <int, CAPMSGGININFO*> :: value_type(pCapMsgGinInfo->nseq, pCapMsgGinInfo));
		}
		return pCapconnectinfo;
    }
    catch (...)
    {
        //do something
    }

    return NULL;
}
/**
* @brief	StaticExistPackage               将数据包的统计数据加入数据链路，如果数据链路第一次创建，填充数据链路内容
* @param 	CAPMSGGININFO*   pCapMsgGinInfo  数据包
* @param    CAPCONNECTINFO * pCapconnectinfo 数据链路
* @return	int                                
* @notes	
* @sample	无
*/
int CCapPackageStatic::StaticExistPackage(CAPMSGGININFO* pCapMsgGinInfo,CAPCONNECTINFO * pCapconnectinfo)
{
	//报文所属链路
	pCapMsgGinInfo->pcapconnect = (void*) pCapconnectinfo;
	int nsize = pCapconnectinfo->map_capmsginfo.size();
	if(nsize > 0)
	{
		pCapMsgGinInfo->pPreCapMsg = pCapconnectinfo->map_capmsginfo[nsize-1];//记忆上一帧
	}
	pCapconnectinfo->map_capmsginfo.insert(std::map <int, CAPMSGGININFO*> :: value_type(nsize, pCapMsgGinInfo));
	//记录长度
	pCapconnectinfo->lTotalCapLenth += pCapMsgGinInfo->ncap_len;//报文记录长度
	if(pCapconnectinfo->ncapp_id > 0)//有app_id的统计
	{
		pCapconnectinfo->nsrc1packages ++;//加1
	}
	else//其它类型的报文
	{
		if(strcmp(pCapconnectinfo->csrc1_mac,pCapMsgGinInfo->csrc_mac) == 0)//比较类型
		{
			pCapconnectinfo->nsrc1packages ++;//加1
			//补充统计
			if(strlen(pCapconnectinfo->csrc1_ip) == 0 )
			{
				strcpy_s(pCapconnectinfo->csrc1_ip,pCapMsgGinInfo->csrc_ip);
			}
			if(strlen(pCapconnectinfo->csrc2_ip) == 0)
			{
				strcpy_s(pCapconnectinfo->csrc2_ip,pCapMsgGinInfo->cdst_ip);
			}
			pCapconnectinfo->nsrc1_port = pCapMsgGinInfo->nsrc_port;
			pCapconnectinfo->nsrc2_port = pCapMsgGinInfo->ndst_port;
		}
		else if(strcmp(pCapconnectinfo->csrc1_mac,pCapMsgGinInfo->cdst_mac) == 0)
		{
			pCapconnectinfo->nsrc2packages ++;//对端发送
			//补充统计
			if(strlen(pCapconnectinfo->csrc1_ip) == 0 )
			{
				strcpy_s(pCapconnectinfo->csrc1_ip,pCapMsgGinInfo->cdst_ip);
			}
			if(strlen(pCapconnectinfo->csrc2_ip) == 0)
			{
				strcpy_s(pCapconnectinfo->csrc2_ip,pCapMsgGinInfo->csrc_ip);
			}
			pCapconnectinfo->nsrc1_port = pCapMsgGinInfo->ndst_port;
			pCapconnectinfo->nsrc2_port = pCapMsgGinInfo->nsrc_port;
		}
		else
		{
			pCapconnectinfo->nsrc1packages ++;//加1
			//补充统计
			if (!pCapconnectinfo->csrc1_mac[0])
			{
				strcpy_s(pCapconnectinfo->csrc1_ip,pCapMsgGinInfo->csrc_ip);  
				strcpy_s(pCapconnectinfo->csrc2_ip,pCapMsgGinInfo->cdst_ip); 
				strcpy_s(pCapconnectinfo->csrc1_mac,pCapMsgGinInfo->csrc_mac);  
				strcpy_s(pCapconnectinfo->csrc2_mac,pCapMsgGinInfo->cdst_mac); 
			}
		}
	}
	//链路结束时间
    time_to_string(pCapMsgGinInfo->nseconds_utc_tmstamp, pCapMsgGinInfo->nus_tmstamp, pCapconnectinfo->cendtimestamp);
	pCapMsgGinInfo->ftime_delta_capconnect    =   pCapMsgGinInfo->ftime_relative - pCapconnectinfo->ftime_relative_last;     //计算本链路与上一帧的时间差
	pCapMsgGinInfo->ftime_relative_capconnect =    pCapMsgGinInfo->ftime_relative - pCapconnectinfo->ftime_relative_first;    //计算本链路与第一帧的时间差

	pCapconnectinfo->ftime_relative_last  = pCapMsgGinInfo->ftime_relative;

	if(nsize == 0)//第一帧，不进行时间均匀分析
	{
		pCapconnectinfo->m_tRelastStatic.n0us ++;
		return 0;
	}
	//链路类型
/*	if(pCapconnectinfo->nconnectapptype == PROTOAPPTYPE_UNKOWN)
	{
		pCapconnectinfo->nconnectapptype = pCapMsgGinInfo->napptype;
	}*/
	//////////////////////add by ljm MMS报文类型
	if (pCapMsgGinInfo->napptype == PROTOAPPTYPE_MMS || pCapMsgGinInfo->napptype == ETHER_TYPE_COTP ||
		(pCapMsgGinInfo->napptype == ETHER_TYPE_TCP && (pCapMsgGinInfo->ndst_port==102 || pCapMsgGinInfo->nsrc_port==102)))
	{
		pCapconnectinfo->nconnectapptype = PROTOAPPTYPE_MMS;
	}
	/////////////////////
	//进行时间均匀度分析  ftime_delta_capconnect  本链路中与上一帧的时间差 1970年以后的秒 含毫秒
	double fInterval,fTemp;
//	double fStand = 0.00025;
	fInterval = pCapMsgGinInfo->ftime_delta_capconnect - 0.00025;

	fTemp = fInterval*1000000;
	if(fTemp < 0.0)
		fTemp = -fTemp;
	int nInterval = (int)fTemp;
	if(fTemp - nInterval > 0.5)
		nInterval++;
	if(fInterval < 0)
		nInterval = -nInterval;

	if(nInterval < 0.1 && nInterval >= 0)
	{
		pCapconnectinfo->m_tRelastStatic.n0us ++;
	}
	else if(nInterval < -10)
	{
		pCapconnectinfo->m_tRelastStatic.neg_nup11us ++;
	}
	else if(nInterval > 10)
	{
		pCapconnectinfo->m_tRelastStatic.nup11us ++;
	}
	else
	{
		switch(nInterval)
		{
		case 1:
			pCapconnectinfo->m_tRelastStatic.n1us ++;
			break;
		case 2:
			pCapconnectinfo->m_tRelastStatic.n2us ++;
			break;
		case 3:
			pCapconnectinfo->m_tRelastStatic.n3us ++;
			break;
		case 4:
			pCapconnectinfo->m_tRelastStatic.n4us ++;
			break;
		case 5:
			pCapconnectinfo->m_tRelastStatic.n5us ++;
			break;
		case 6:
			pCapconnectinfo->m_tRelastStatic.n6us ++;
			break;
		case 7:
			pCapconnectinfo->m_tRelastStatic.n7us ++;
			break;
		case 8:
			pCapconnectinfo->m_tRelastStatic.n8us ++;
			break;
		case 9:
			pCapconnectinfo->m_tRelastStatic.n9us ++;
			break;
		case 10:
			pCapconnectinfo->m_tRelastStatic.n10us ++;
			break;
		case -1:
			pCapconnectinfo->m_tRelastStatic.neg_n1us ++;
			break;
		case -2:
			pCapconnectinfo->m_tRelastStatic.neg_n2us ++;
			break;
		case -3:
			pCapconnectinfo->m_tRelastStatic.neg_n3us ++;
			break;
		case -4:
			pCapconnectinfo->m_tRelastStatic.neg_n4us ++;
			break;
		case -5:
			pCapconnectinfo->m_tRelastStatic.neg_n5us ++;
			break;
		case -6:
			pCapconnectinfo->m_tRelastStatic.neg_n6us ++;
			break;
		case -7:
			pCapconnectinfo->m_tRelastStatic.neg_n7us ++;
			break;
		case -8:
			pCapconnectinfo->m_tRelastStatic.neg_n8us ++;
			break;
		case -9:
			pCapconnectinfo->m_tRelastStatic.neg_n9us ++;
			break;
		case -10:
			pCapconnectinfo->m_tRelastStatic.neg_n10us ++;
			break;
		default:
			break;
		}
	}
	return 0;
}
