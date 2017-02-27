#pragma execution_character_set("UTF-8")
#include "PackageCovertWrapper.h"
#include "CapTransformer.h"
#include "ScanDissectPacketer.h"

extern CCapTransformer * g_capTransformer;  //cap文件生成的txt文件解析器
//CZipcWrapper              m_zicpWrapper;              //解压缩动态库封装
extern CScanDissectPacketer      *g_ScanDissectPacketer;      //用于数据包的解析

CPackageCovertWrapper::~CPackageCovertWrapper(void)
{
//	UnInitialize();
}
CPackageCovertWrapper::CPackageCovertWrapper(void)
{

}

//原始报文转换动态库初始化函数
int CPackageCovertWrapper::PACKE2MSG_INIT()
{
	m_CfgInfo.bParseGooseDA = true;
	m_CfgInfo.bParseSmvDA   = true;
	m_CfgInfo.logInfo.nLogLevel = 3;
	m_CfgInfo.logInfo.nLogMaxLen = 10240;
    strcpy_s(m_CfgInfo.logInfo.cLogPath,"../log/pack2msg");

    return m_pkt2msg.packetconvert_init(m_CfgInfo);
}

//得到解析后的报文内容
int  CPackageCovertWrapper::Make61850Struct_Pack2Msg(CAPMSGGININFO*  pCapMsgGinInfo, PACKET_STRUCT* pPacket)
{
    if(pPacket == NULL || pCapMsgGinInfo == NULL)
		return -1;
    string strTempContent;
    int nEtherType = m_pkt2msg.packetconvert_get_ether_type((char*)pPacket->pPacket);//获取报文类型
	pCapMsgGinInfo->napptype = nEtherType;//报文类型
	switch(nEtherType)
	{
		case IEC61850_ETHER_TYPE_SMV:
		{
			SMV_INFO_STRUCT* pSmvInfo = new SMV_INFO_STRUCT;
            m_pkt2msg.packetconvert_2smv_ex(pPacket,1,pSmvInfo);//解析报文
			if((pSmvInfo->u_result & DISSECT_SMV_RESULT_OK)!=DISSECT_SMV_RESULT_OK) //报文结果异常
			{
				pCapMsgGinInfo->nAppConetentGood = 0;//异常报文
				//此处填写报文格式异常
//                snprintf(pCapMsgGinInfo->ccontent,127,"%s",GetSVFormatErrorDesc(pSmvInfo->u_result).c_str());
                strncpy(pCapMsgGinInfo->ccontent,GetSVFormatErrorDesc(pSmvInfo->u_result).c_str(), 127 );
			}
			//解析后的内容
			pCapMsgGinInfo->pparserdstruct = (void *) pSmvInfo;
			//appid号
			pCapMsgGinInfo->napp_id = pSmvInfo->n_app_id;
			//发送端MAC地址
			ParseMac(pSmvInfo->c_src_mac, pCapMsgGinInfo->csrc_mac);
			//接收端MAC地址
			ParseMac(pSmvInfo->c_dest_mac, pCapMsgGinInfo->cdst_mac);
			if(pCapMsgGinInfo->nAppConetentGood)//正确报文
			{
                sprintf(pCapMsgGinInfo->ccontent,"序号:%d",pSmvInfo->p_asdu_info_struct[0].n_smpCnt);
			}
			break;
		}
	    case  IEC61850_ETHER_TYPE_GOOSE:
		{
			GOOSE_INFO_STRUCT* pGooseInfo = new GOOSE_INFO_STRUCT;
            m_pkt2msg.packetconvert_2goose_ex(pPacket,1,pGooseInfo);
			if((pGooseInfo->u_result &DISSECT_GOOSE_RESULT_OK)!=DISSECT_GOOSE_RESULT_OK)//报文解析异常
			{
				pCapMsgGinInfo->nAppConetentGood = 0;//异常报文
//                snprintf(pCapMsgGinInfo->ccontent,127,"%s",GetGOOSEFormatErrorDesc(pGooseInfo->u_result).c_str());//
                strncpy(pCapMsgGinInfo->ccontent, GetGOOSEFormatErrorDesc(pGooseInfo->u_result).c_str(), 127);
			}
			//解析后的内容
			pCapMsgGinInfo->pparserdstruct = (void *) pGooseInfo;
			//appid号
			pCapMsgGinInfo->napp_id  = pGooseInfo->n_app_id;
			//发送端MAC地址
			ParseMac(pGooseInfo->c_src_mac, pCapMsgGinInfo->csrc_mac);
			//接收端MAC地址
			ParseMac(pGooseInfo->c_dest_mac, pCapMsgGinInfo->cdst_mac);
			//概要描述
			if(pCapMsgGinInfo->nAppConetentGood)
			{
				sprintf_s(pCapMsgGinInfo->ccontent,"状态计数:%u   序号:%u",pGooseInfo->n_stNum,pGooseInfo->n_sqNum);
			}
			break;
		}
		case IEC61850_ETHER_TYPE_PTP_1588:
		{
            //PTP_INFO_STRUCT* pTpInfo = NULL;
            //CWSAnalyzerApp* pApp = (CWSAnalyzerApp*) AfxGetApp();
            //pApp->m_piec61850Analyzer->m_ptpv2Analyzer->parse(pPacket,1,(void**)&pTpInfo);
            PTP_INFO_STRUCT* pTpInfo = new PTP_INFO_STRUCT;
            m_pkt2msg.packetconvert_2ptp_ex(pPacket,1,pTpInfo);
			if (pTpInfo->u_result & ((1<<(PTP_PKTERR_LEN-1)) + (1<<(PTP_PKTERR_VAL-1))))
			{
				pCapMsgGinInfo->nAppConetentGood = 0;
			}
			//解析后的内容
			pCapMsgGinInfo->pparserdstruct = (void *) pTpInfo;
			//发送端MAC地址
			ParseMac(pTpInfo->c_src_mac, pCapMsgGinInfo->csrc_mac);
			//接收端MAC地址
			ParseMac(pTpInfo->c_dest_mac, pCapMsgGinInfo->cdst_mac);

            //概要描述 由于编译问题临时屏蔽  djf
			//CWSAnalyzerApp* pApp = (CWSAnalyzerApp*) AfxGetApp();
            //strTempContent.Format("SqID:%d %10s",pTpInfo->ptp_header.n_sq_id,
            //	pApp->m_KeyWords61850tranformer.GET_PTP1588_EVENT_ChineseDesc(pTpInfo->ptp_header.enum_ptp_msg_type));

            if (!pCapMsgGinInfo->nAppConetentGood)
			{
				strTempContent+="|格式错误";
			}
            strcpy_s(pCapMsgGinInfo->ccontent,strTempContent.c_str());
			break;
		}
		case ETHER_TYPE_TCP:
		{
			//eth2
			ETHER_TYPE_ETH2_Head_Aanalyze(pCapMsgGinInfo,pPacket);
			//IP
			ETHER_TYPE_IP_Head_Aanalyze(pCapMsgGinInfo,pPacket);
			//TCP
			ETHER_TYPE_TCP_Head_Aanalyze(pCapMsgGinInfo,pPacket);
			break;
		}	
		case  ETHER_TYPE_UDP:
		{
			//ETH2
			ETHER_TYPE_ETH2_Head_Aanalyze(pCapMsgGinInfo,pPacket);
			//IP
			ETHER_TYPE_IP_Head_Aanalyze(pCapMsgGinInfo,pPacket);
			//UPD
			ETHER_TYPE_UDP_Head_Aanalyze(pCapMsgGinInfo,pPacket);
			break;
		}
		case ETHER_TYPE_ARP:
		{
			//ETH2
			ETHER_TYPE_ETH2_Head_Aanalyze(pCapMsgGinInfo,pPacket);
			//ARP
			ETHER_TYPE_ARP_Head_Aanalyze(pCapMsgGinInfo,pPacket);
			break;
		}
		case  ETHER_TYPE_DROP:
		{
			{
				char chErr=((char*)(pPacket->pPacket))[pPacket->nLen-8];
				pCapMsgGinInfo->nAppConetentGood = 0;//异常报文
				//_snprintf_s(pCapMsgGinInfo->ccontent,127,"链路层丢帧,CRC校验错:%s|短帧:%s|长帧:%s",(chErr& 0x80)?"是":"否"
				//	,(chErr & 0x60)==0x20?"是":"否",(chErr& 0x60)==0x60?"是":"否");
                _snprintf_s(pCapMsgGinInfo->ccontent,127,"链路层丢帧：%s",(chErr& 0x80)?"CRC校验错":(chErr & 0x60)==0x20?"短帧":(chErr& 0x60)==0x60?"长帧":"");
                //用strcpy strcat 代替_snprintf_s  djf
//                strcpy(pCapMsgGinInfo->ccontent, "链路层丢帧：");
//                if(chErr & 0x80)
//                    strcat(pCapMsgGinInfo->ccontent, "CRC校验错");
//                else if (chErr & 0x60 == 0x20)
//                    strcat(pCapMsgGinInfo->ccontent, "短帧");
//                else if(chErr & 0x60 == 0x60)
//                    strcat(pCapMsgGinInfo->ccontent,"长帧");
			}
            //解析后的内容
			pCapMsgGinInfo->pparserdstruct = (void *) NULL;
			//appid号
			pCapMsgGinInfo->napp_id = 0;
			//发送端MAC地址
			pCapMsgGinInfo->csrc_mac[0]=0;
			//接收端MAC地址
			pCapMsgGinInfo->cdst_mac[0]=0;
			break;
		}
		default:
		{
			ETHER_TYPE_ETH2_Head_Aanalyze(pCapMsgGinInfo,pPacket);
			break;
		}	
	}
	return 0;
}
/****************根据解析标志位返回采样值报文处理结果*******************/
//Bit31:packet_len<76字节 Bit30:表示msg_len异常 Bit29:表示ASDU个数为0
//Bit15:nofasdu Bit14:sv_id Bit13:smpCunt Bit12:confRev Bit11:SmpSynch Bit10:DataSet Bit9:RefrTm Bit8:SmpRate Bit7:SEQUENCEOFDATA)，其它Bit位预留
//unsigned int u_result;//解析结果 add on 2013/03/28 ljm 默认0x00000000，高字节第4个字节表示解析异常结果，第3个字节预留，第1、2个字节表示解析结果标识
/**********************************add on 2013/03/28 报文解析结果**************************/
//Bit31:pakcet_len异常=0, Bit30:msg_len异常=0 , Bit15:nofasdu Bit14:sv_id Bit13:smpCnt Bit12:confRev Bit11:SmpSynch Bit7:SEQUENCEOFD 都为1
/*#define DISSECT_SMV_RESULT_OK				0x0000F800	

#define DISSECT_SMV_PKTLEN_ERROR			0x80000000
#define DISSECT_SMV_MSGLEN_ERROR			0x40000000
#define DISSECT_SMV_ASDU_NUM_ZERO			0x20000000

#define DISSECT_SMV_NOFASDU_OK				0x00008000
#define DISSECT_SMV_SVID_OK					0x00004000
#define DISSECT_SMV_SMPCNT_OK				0x00002000
#define DISSECT_SMV_CONFREV_OK				0x00001000
#define DISSECT_SMV_SMPSYNCH_OK				0x00000800

#define DISSECT_SMV_DATASET_OK				0x00000400
#define DISSECT_SMV_REFRTM_OK				0x00000200
#define DISSECT_SMV_SMPRATE_OK				0x00000100
#define DISSECT_SMV_SEQUENCEOFDATA_OK		0x00000080*/
string CPackageCovertWrapper::GetSVFormatErrorDesc(unsigned int u_result)
{
    string strResult("报文格式错误:");
	BOOL bFormatErr=((u_result & DISSECT_SMV_PKTLEN_ERROR) ==  DISSECT_SMV_PKTLEN_ERROR)
		||((u_result & DISSECT_SMV_MSGLEN_ERROR) ==  DISSECT_SMV_MSGLEN_ERROR);
	if(bFormatErr)
	{
		strResult +="报文长度描述与实际长度不一致|";
	}
	else
	{

		if((u_result & DISSECT_SMV_ASDU_NUM_ZERO) ==  DISSECT_SMV_ASDU_NUM_ZERO)
		{
			strResult +="ASDU个数为零|";
		}
		if((u_result & DISSECT_SMV_NOFASDU_OK) !=  DISSECT_SMV_NOFASDU_OK)
		{
			strResult +="缺ASDU个数|";
		}
		if((u_result & DISSECT_SMV_SVID_OK) !=  DISSECT_SMV_SVID_OK)
		{
			strResult +="缺SVID|";
		}
		if((u_result & DISSECT_SMV_CONFREV_OK) !=  DISSECT_SMV_CONFREV_OK)
		{
			strResult +="缺版本号|";
		}
		if((u_result & DISSECT_SMV_SMPCNT_OK) !=  DISSECT_SMV_SMPCNT_OK)
		{
			strResult +="缺采样计数|";
		}
		if((u_result & DISSECT_SMV_SMPSYNCH_OK) !=  DISSECT_SMV_SMPSYNCH_OK)
		{
			strResult +="缺同步标识|";
		}
		if((u_result & DISSECT_SMV_SMPRATE_OK) !=  DISSECT_SMV_SMPRATE_OK)
		{
			strResult +="缺采样频率|";
		}
		if((u_result & DISSECT_SMV_SEQUENCEOFDATA_OK) !=  DISSECT_SMV_SEQUENCEOFDATA_OK)
		{
			strResult +="缺数据个数|";
		}
	}



	return strResult;
}
/****************根据解析标志位返回GOOSE报文处理结果********************/
//Bit31:packet_len异常=0，Bit30:msg_len异常=0
//Bit23:PDU头的tag正确=1，Bit22:gocbRef, Bit21:timeAllowed Bit20:dataSet Bit19:T Bit18:stNum Bit17:sqNum Bit16:test Bit15:confRev Bit14:ndsCom Bit13:numDataSetEntries都为1
/*#define DISSECT_GOOSE_RESULT_OK		    0x00FFE000

#define DISSECT_GOOSE_PKTLEN_ERROR			0x80000000
#define DISSECT_GOOSE_MSGLEN_ERROR			0x40000000

#define DISSECT_GOOSE_PDU_TAG_OK			0x00800000
#define DISSECT_GOOSE_GOCB_OK				0x00400000
#define DISSECT_GOOSE_TAL_OK				0x00200000
#define DISSECT_GOOSE_DATASET_OK			0x00100000
#define DISSECT_GOOSE_T_OK					0x00080000
#define DISSECT_GOOSE_STNUM_OK				0x00040000
#define DISSECT_GOOSE_SQNUM_OK				0x00020000
#define DISSECT_GOOSE_TEST_OK				0x00010000
#define DISSECT_GOOSE_CONFREV_OK			0x00008000
#define DISSECT_GOOSE_NDSCOM_OK				0x00004000
#define DISSECT_GOOSE_NUMDATASETENTRIES_OK	0x00002000

#define DISSECT_GOOSE_ALL_DATA_TAG_OK		0x00001000
#define DISSECT_GOOSE_GOID_OK				0x00000800*/
string CPackageCovertWrapper::GetGOOSEFormatErrorDesc(unsigned int u_result)
{
    string strResult("报文格式错误:");
	if((u_result & DISSECT_GOOSE_PKTLEN_ERROR) ==  DISSECT_GOOSE_PKTLEN_ERROR)
	{
		strResult +="报文长度异常|";
	}
	if((u_result & DISSECT_GOOSE_MSGLEN_ERROR) ==  DISSECT_GOOSE_MSGLEN_ERROR)
	{
		strResult +="报文长度描述与实际长度不一致|";
	}
	else
	{
		if((u_result & DISSECT_GOOSE_PDU_TAG_OK) !=  DISSECT_GOOSE_PDU_TAG_OK)
		{
			strResult +="缺PDU|";
		}
		if((u_result & DISSECT_GOOSE_GOCB_OK) !=  DISSECT_GOOSE_GOCB_OK)
		{
			strResult +="缺GOCB|";
		}
		if((u_result & DISSECT_GOOSE_TAL_OK) !=  DISSECT_GOOSE_TAL_OK)
		{
			strResult +="缺TAL|";
		}
		if((u_result & DISSECT_GOOSE_DATASET_OK) !=  DISSECT_GOOSE_DATASET_OK)
		{
			strResult +="缺数据集|";
		}
		if((u_result & DISSECT_GOOSE_STNUM_OK) !=  DISSECT_GOOSE_STNUM_OK)
		{
			strResult +="缺STNUM|";
		}
		if((u_result & DISSECT_GOOSE_SQNUM_OK) !=  DISSECT_GOOSE_SQNUM_OK)
		{
			strResult +="缺SQNUM|";
		}
		if((u_result & DISSECT_GOOSE_TEST_OK) !=  DISSECT_GOOSE_TEST_OK)
		{
			strResult +="缺检修标志|";
		}
		if((u_result & DISSECT_GOOSE_CONFREV_OK) !=  DISSECT_GOOSE_CONFREV_OK)
		{
			strResult +="缺版本标识|";
		}
		if((u_result & DISSECT_GOOSE_NUMDATASETENTRIES_OK) !=  DISSECT_GOOSE_NUMDATASETENTRIES_OK)
		{
			strResult +="缺数据个数|";
		}
		if((u_result & DISSECT_GOOSE_NDSCOM_OK) !=  DISSECT_GOOSE_NDSCOM_OK)
		{
			strResult +="缺ndsCom|";
		}
		if((u_result & DISSECT_GOOSE_T_OK) !=  DISSECT_GOOSE_T_OK)
		{
			strResult +="缺发送时间|";
		}
	}
	return strResult;
}
int CPackageCovertWrapper::Release61850Struct_Pack2Msg(CAPMSGGININFO* pMsg)
{
	if(pMsg == NULL)
		return -1;
	if(pMsg->napptype == IEC61850_ETHER_TYPE_GOOSE)
	{
		GOOSE_INFO_STRUCT* pGooseInfo =(GOOSE_INFO_STRUCT*) pMsg->pparserdstruct;
        m_pkt2msg.packetconvert_release_goose_mms_data(pGooseInfo,1);
		delete pGooseInfo;
	}
	else if(pMsg->napptype == IEC61850_ETHER_TYPE_SMV)
	{
		SMV_INFO_STRUCT* pSmvInfo = (SMV_INFO_STRUCT*) pMsg->pparserdstruct;
        m_pkt2msg.packetconvert_release_smv_asdu(pSmvInfo,1);
		delete pSmvInfo;
	}
	else if(pMsg->napptype == IEC61850_ETHER_TYPE_PTP_1588)
	{
        //CWSAnalyzerApp* pApp = (CWSAnalyzerApp*) AfxGetApp();
        //pApp->m_piec61850Analyzer->m_ptpv2Analyzer->release_info(pMsg->pparserdstruct);
        //djf
        delete (PTP_INFO_STRUCT*)pMsg->pparserdstruct;
	}
	else
	{
		;
	}
	pMsg->pparserdstruct = NULL;
	return 0;
}
//int CPackageCovertWrapper::GetPTP_MSG_TIME(PTP_INFO_STRUCT* p_ptp_info_struct,__int64 &time_s, UINT &time_ns)
//{
//	int nRet = 0;
//	if(p_ptp_info_struct->ptp_header.enum_ptp_msg_type == PTP_SYNC_MESSAGE)//同步
//	{
//		m_pPacketConvert_I->get_timestamp_s_ns(p_ptp_info_struct->u.msg_sync.time_stamp_origin,time_s,time_ns);
//	}
//	else if(p_ptp_info_struct->ptp_header.enum_ptp_msg_type == PTP_ANNOUNCE_GENERAL)
//	{
//		m_pPacketConvert_I->get_timestamp_s_ns(p_ptp_info_struct->u.msg_announce.time_stamp_origin,time_s,time_ns);
//	}
//	else if(p_ptp_info_struct->ptp_header.enum_ptp_msg_type == PTP_FOLLOWUP_GENERAL)
//	{
//		m_pPacketConvert_I->get_timestamp_s_ns(p_ptp_info_struct->u.msg_follow_up.time_stamp_origin,time_s,time_ns);
//	}
//	else if(p_ptp_info_struct->ptp_header.enum_ptp_msg_type == PTP_DELAY_REQ_MESSAGE)
//	{
//		m_pPacketConvert_I->get_timestamp_s_ns(p_ptp_info_struct->u.msg_delay_req.time_stamp_origin,time_s,time_ns);
//	}
//	else if(p_ptp_info_struct->ptp_header.enum_ptp_msg_type == PTP_PDELAY_REQ_MESSAGE)
//	{
//		m_pPacketConvert_I->get_timestamp_s_ns(p_ptp_info_struct->u.msg_pdelay_req.time_stamp_origin,time_s,time_ns);
//	}
//	else if(p_ptp_info_struct->ptp_header.enum_ptp_msg_type == PTP_PDELAY_RESP_MESSAGE)
//	{
//		m_pPacketConvert_I->get_timestamp_s_ns(p_ptp_info_struct->u.msg_pdelay_resp.time_stamp_origin,time_s,time_ns);
//	}
//	else if(p_ptp_info_struct->ptp_header.enum_ptp_msg_type == PTP_DELAY_RESP_GENERAL)
//	{
//		m_pPacketConvert_I->get_timestamp_s_ns(p_ptp_info_struct->u.msg_delay_resp.time_stamp_origin,time_s,time_ns);
//	}
//	else if(p_ptp_info_struct->ptp_header.enum_ptp_msg_type == PTP_PDELAY_RESP_FOLLOW_UP_GENERAL)
//	{
//		m_pPacketConvert_I->get_timestamp_s_ns(p_ptp_info_struct->u.msg_pdelay_followup.time_stamp_origin,time_s,time_ns);
//	}
//	else
//	{
//		nRet = -1;
//	}
//	return nRet;
//}
//double CPackageCovertWrapper::GetPTP_MSG_TIME_CORRECTION(PTP_INFO_STRUCT* p_ptp_info_struct)
//{
//	double fValue = 0.0;
//	m_pPacketConvert_I->get_correction_val(p_ptp_info_struct->ptp_header.correction_field,fValue);
//	return fValue;
//}
//解析MAC
int CPackageCovertWrapper::ParseMac(char *p_packet_buf, char *p_mac)
{
	int i=0;
	int nLen = 0;
    if (m_pkt2msg.packetconvert_get_linkType()==101)
	{
		strcpy(p_mac,"00-00-00-00-00-00");
	}
	else
	sprintf(p_mac,"%02x-%02x-%02x-%02x-%02x-%02x",
		(unsigned char)p_packet_buf[0], (unsigned char)p_packet_buf[1], \
		(unsigned char)p_packet_buf[2], (unsigned char)p_packet_buf[3], \
		(unsigned char)p_packet_buf[4], (unsigned char)p_packet_buf[5]);
	nLen = 6;
	return nLen;
}
/********解析IP*****************/
int CPackageCovertWrapper::ParseIP(char *p_packet_buf, char *p_ip)
{
	int i=0;
	int nLen = 0;

	sprintf(p_ip,"%d.%d.%d.%d",
		(unsigned char)p_packet_buf[0], (unsigned char)p_packet_buf[1], \
		(unsigned char)p_packet_buf[2], (unsigned char)p_packet_buf[3]);

	nLen = 4;
	return nLen;
}
//解析品质
int CPackageCovertWrapper::ParseQuality(char *p_quality_buf,char *p_quality)
{
	char p_buf_emp[5];
	char c_data[65];
	memset(p_buf_emp,0,5);
	memset(c_data,0,65);
	memcpy(p_buf_emp,p_quality_buf,4);
	sprintf(p_quality,"%02x%02x%02x%02x",(unsigned char)p_buf_emp[0],(unsigned char)p_buf_emp[1], 
		(unsigned char)p_buf_emp[2],(unsigned char)p_buf_emp[3]);
	return 0;
}
//解析时间
int CPackageCovertWrapper::ParseAvtm(char *p_packet_buf, char *c_avtm)
{
	unsigned int n_secs = 0;
	unsigned int n_usecs = 0;
	int nLen = 0;
	if (NULL==p_packet_buf || NULL==c_avtm)
	{
		return 0;
	}
	memcpy((char*)&n_secs,p_packet_buf,4);
	memcpy((char*)&n_usecs,p_packet_buf+4,4);
	sprintf(c_avtm, "%d.%06d", n_secs, n_usecs);
	nLen = 8;
	return nLen;
}
int CPackageCovertWrapper::my_itoa(int val, char* buf, int radix)
{

	//   const int radix = 10;

	char* p;
	int a;        //every digit
	int len;
	char* b;    //start of the digit char
	char temp;

	p = buf;

	if (val < 0)
	{
		*p++ = '-';
		val = 0 - val;
	}

	b = p;

	do
	{
		a = val % radix;
		val /= radix;

		*p++ = a + '0';

	} while (val > 0);

	len = (int)(p - buf);

	*p-- = 0;

	//swap
	do
	{
		temp = *p;
		*p = *b;
		*b = temp;
		--p;
		++b;

	} while (b < p);

	return len;
}

int CPackageCovertWrapper::Hex2Binary(char *cHex)
{
	int n_strlen = 0;
	char cTemp[MAX_MMS_INFO_DATA_LEN];
	long l_Temp;

	n_strlen = strlen(cHex);
	if (NULL == cHex)
	{
		return -1;
	}
	memset(cTemp,0,MAX_MMS_INFO_DATA_LEN);

	l_Temp=strtoul(cHex,NULL,16);
	//	itoa(l_Temp, cHex, 2); 
	my_itoa(l_Temp, cHex, 2); 

	//前面补齐0
	while (strlen(cHex) < 4*n_strlen)
	{
		strcpy(cTemp, "0");
		strcat(cTemp, cHex);
		strcpy(cHex, cTemp);
	}
	return 0;
}
/************ETH2头解析****************/
int CPackageCovertWrapper::ETHER_TYPE_ETH2_Head_Aanalyze(CAPMSGGININFO*  pCapMsgGinInfo,PACKET_STRUCT* pPacket)
{
	//ETH2头结构
	char* p_packet_buf = (char*)pPacket->pPacket;
	if(p_packet_buf == NULL || pPacket->nLen < 54)//字节数不够
		return -1;
	int nstart = 16;
	//目的MAC地址
	ParseMac(p_packet_buf+nstart, pCapMsgGinInfo->cdst_mac);
	//源头MAC地址
	nstart += 6;
	ParseMac(p_packet_buf+nstart, pCapMsgGinInfo->csrc_mac);
	return 0;
}
/************IP头解析****************/
int CPackageCovertWrapper::ETHER_TYPE_IP_Head_Aanalyze(CAPMSGGININFO*  pCapMsgGinInfo,PACKET_STRUCT* pPacket)
{
	char* p_packet_buf = (char*)pPacket->pPacket +16;
	if(p_packet_buf == NULL || pPacket->nLen < 54)//字节数不够
		return -1;
	//跳过ETH2头
	int nstart = 0;
    if (m_pkt2msg.packetconvert_get_linkType()==101)
	{
	}
	else{
	nstart +=12;//直接跳到IP层
	if (0x81==(unsigned char)p_packet_buf[nstart] && 0x00==(unsigned char)p_packet_buf[nstart+1])//VLAN处理
	{
		nstart = nstart+4;
	}
	nstart +=2;
    }
	//IP结构
	//--版本号(4位)+头长度(4位置)      1字节 1
	//--服务类型                       1字节 2
	//--总长度                         2字节 4
	//--标识                           2字节 6
	//--标志(3位)+片偏移(13位)         2字节 8
	//--生存时间                       1字节 9
	//--上层协议标识                   1字节 10
	//--头部校验和                     2字节 12
	//--源IP地址                       4字节 16
	//--目标IP地址                     4字节 20
	//--选项                           8字节 28
	//--应用数据
	nstart += 12;//源IP
	ParseIP(p_packet_buf+nstart,pCapMsgGinInfo->csrc_ip);
	nstart += 4;//目的IP
	ParseIP(p_packet_buf+nstart,pCapMsgGinInfo->cdst_ip);
	return 0;
}
/************TCP头解析****************/
int CPackageCovertWrapper::ETHER_TYPE_TCP_Head_Aanalyze(CAPMSGGININFO*  pCapMsgGinInfo,PACKET_STRUCT* pPacket)
{
	if(pPacket->pPacket == NULL || pPacket->nLen < 54)//字节数不够
		return -1;
	char* p_packet_buf = (char*)pPacket->pPacket +16;//跳过PCAP报文头
	//跳过ETH2头
	int nstart = 0;//直接跳到IP层
    if (m_pkt2msg.packetconvert_get_linkType()!=101)
	{
	nstart += 12;
	if (0x81==(unsigned char)p_packet_buf[nstart] && 0x00==(unsigned char)p_packet_buf[nstart+1])//VLAN处理
	{
		nstart = nstart+4;
	}
	nstart +=2;
	}
	unsigned char ucharTemp = (unsigned char)p_packet_buf[nstart];
	ucharTemp = ucharTemp&0xf;//取字节后4位，计算IP报文头长度
	nstart += ucharTemp* 4;//跳到tcp层
	//TCP结构
	//--源端口      2字节   2
	//--目的端口    2字节   4
	//--序号        4字节   8
	//--确认号      4字节   12
	//--数据偏移(4bit)+保留(6bit)+URG紧急数据(1bit)+ACK确认(1bit)+PSH数据推送(1bit)+RST连接复位(1bit)+SYN同步(1bit)+FIN释放链接(1bit)  2字节  14
	//--窗口        2字节   16
	//--校验和      2字节   18
	//--紧急指针    2字节   20
	//--选项+填充   4字节   24
	//--应用数据
	pCapMsgGinInfo->nsrc_port = (unsigned char)p_packet_buf[nstart] * 0x100 + (unsigned char)p_packet_buf[nstart+1];
	nstart += 2;
	pCapMsgGinInfo->ndst_port = (unsigned char)p_packet_buf[nstart] * 0x100 +(unsigned char)p_packet_buf[nstart+1];
	nstart += 2;
//	int nseq = (unsigned char)p_packet_buf[nstart] * 0x100 * 0x100 * 0x100 + (unsigned char)p_packet_buf[nstart+1] * 0x100 * 0x100 +
//		        (unsigned char)p_packet_buf[nstart+2] * 0x100 +  (unsigned char)p_packet_buf[nstart+3];
	nstart += 4;
//	int nck = (unsigned char)p_packet_buf[nstart] * 0x100 * 0x100 * 0x100 + (unsigned char)p_packet_buf[nstart+1] * 0x100 * 0x100 +
//		(unsigned char)p_packet_buf[nstart+2] * 0x100 +  (unsigned char)p_packet_buf[nstart+3];
	nstart += 4;

	ucharTemp = (unsigned char)p_packet_buf[nstart+1];//取出标识字节

	BOOL bURG=FALSE,bACK=FALSE,bPSH=FALSE,bRST=FALSE,bSYN=FALSE,bFIN=FALSE;
	
	if((ucharTemp&0x20) == 0x20)//100000 URG紧急数据
		bURG = TRUE;
	if((ucharTemp&0x10) == 0x10)//010000 ACK确认
		bACK = TRUE;
	if((ucharTemp&0x8) == 0x8)  //001000 PSH数据推送
		bPSH = TRUE;
	if((ucharTemp&0x4) == 0x4)  //000100 RST连接复位
		bRST = TRUE;
	if((ucharTemp&0x2) == 0x2)  //000010 SYN建立连接请求/确认
		bSYN = TRUE;
	if((ucharTemp&0x1) == 0x1)  //000001 FIN释放链接
		bFIN = TRUE;
	if(bURG == FALSE && bACK == TRUE && bPSH == FALSE && bRST == FALSE && bSYN == FALSE && bFIN == FALSE)//保持连接
	{
		strcpy_s(pCapMsgGinInfo->ccontent, "保持连接");
	}
	if(bPSH == TRUE && bACK == TRUE)//PSH数据提交处理
	{
		strcpy_s(pCapMsgGinInfo->ccontent, "PSH应用数据传输");
		pCapMsgGinInfo->btcppsh = true;
	}
	if(bACK == FALSE && bSYN == TRUE)//SYN建立连接请求
	{
		strcpy_s(pCapMsgGinInfo->ccontent, "SYN请求链接");
		pCapMsgGinInfo->nAppConetentGood = 0;//置异常标识
	}
	if(bACK == TRUE && bSYN == TRUE)//建立连接请求确认
	{
		strcpy_s(pCapMsgGinInfo->ccontent, "SYN接受链接");
		pCapMsgGinInfo->nAppConetentGood = 0;//置异常标识
	}
	if(bRST == TRUE)//连接复位
	{
		strcpy_s(pCapMsgGinInfo->ccontent, "RST连接复位");
		pCapMsgGinInfo->nAppConetentGood = 0;//置异常标识
	}
	if(bFIN == TRUE)//连接终止
	{
		strcpy_s(pCapMsgGinInfo->ccontent, "FIN释放链接");
		pCapMsgGinInfo->nAppConetentGood = 0;//置异常标识
	}
	if(bURG == TRUE)//紧急数据
	{
		strcpy_s(pCapMsgGinInfo->ccontent, "紧急数据");
		pCapMsgGinInfo->nAppConetentGood = 0;//置异常标识
	}
	return 0;
}
/************UDP头解析****************/
int CPackageCovertWrapper::ETHER_TYPE_UDP_Head_Aanalyze(CAPMSGGININFO*  pCapMsgGinInfo,PACKET_STRUCT* pPacket)
{
	if(pPacket->pPacket== NULL || pPacket->nLen < 54)//字节数不够
		return -1;
	char* p_packet_buf = (char*)pPacket->pPacket +16;//跳过PCAP报文头

	//跳过ETH2头
	//int nstart = 14;//直接跳到IP层
	int nstart = 0;
    if (m_pkt2msg.packetconvert_get_linkType()!=101)
	{
	nstart += 12;//直接跳到IP层
	if (0x81==(unsigned char)p_packet_buf[nstart] && 0x00==(unsigned char)p_packet_buf[nstart+1])//VLAN处理
	{
		nstart = nstart+4;
	}
	nstart +=2;
	}

	unsigned char ucharTemp = (unsigned char)p_packet_buf[nstart];
	ucharTemp = ucharTemp&0xf;//取字节后4位，计算IP报文头长度
	nstart += ucharTemp* 4;//跳到UDP层
	//UDP结构
	//--源端口      2字节
	//--目的端口    2字节
	pCapMsgGinInfo->nsrc_port = (unsigned char)p_packet_buf[nstart] * 0x100 + (unsigned char)p_packet_buf[nstart+1];
	nstart += 2;
	pCapMsgGinInfo->ndst_port = (unsigned char)p_packet_buf[nstart] * 0x100 +(unsigned char)p_packet_buf[nstart+1];
	return 0;
}
/************ARP头解析****************/
int CPackageCovertWrapper::ETHER_TYPE_ARP_Head_Aanalyze(CAPMSGGININFO*  pCapMsgGinInfo,PACKET_STRUCT* pPacket)
{
	return 0;
}
/******COPT连续报文分析***/
/*
* @brief	COPT连续报文分析
* @param 	
* @param 	
* @return	int
* @notes	无
* @sample	无
*/
int CPackageCovertWrapper::COTP_LIST_ANALYZE(CAPCONNECTINFO* pConnection)
{
	//SRC1->SCR2
	Cotp_List_Aanlyze_Detail(pConnection->map_capmsginfo,pConnection,TRUE);
	//SCR2->SRC1
	Cotp_List_Aanlyze_Detail(pConnection->map_capmsginfo,pConnection,FALSE);
	return 0;
}
/******COTP_LIST_ANALYZE_DETAIL分析***/
/*
* @brief	COPT连续报文分析
* @param 	
* @param 	bdst2_src  分析方向
* @return	int
* @notes	无
* @sample	无
*/
int CPackageCovertWrapper::Cotp_List_Aanlyze_Detail(MAP_CAPMSGINFO map_capmsginfo,CAPCONNECTINFO* pConnection,BOOL bdst2_src)
{
	if(map_capmsginfo.size() == 0)
		return 0;
	std::map <int, CAPMSGGININFO* >::iterator iter;
	CAPMSGGININFO* pCapMsgGinInfo,*pCapMsgGinInfo_First;
	BOOL bCoptBegin = FALSE;//COTP报文开始
	MAP_CAPMSGINFO map_cotplist_temp;
//	CWSAnalyzerApp* pApp = (CWSAnalyzerApp*) AfxGetApp();
	int ntemp = map_capmsginfo.size();
	int ntotalsize = 0;
	for(iter = map_capmsginfo.begin(); iter != map_capmsginfo.end(); iter ++ )
	{
		pCapMsgGinInfo = iter->second;
		if(bdst2_src)//正向
		{
			if(strcmp(pCapMsgGinInfo->csrc_ip,pConnection->csrc1_ip) != 0)
			{
				 continue;
			}
		}
		else//反向
		{
			if(strcmp(pCapMsgGinInfo->cdst_ip,pConnection->csrc1_ip) != 0)
			{
				continue;
			}
		}
		if(pCapMsgGinInfo->napptype == ETHER_TYPE_COTP && bCoptBegin == FALSE && pCapMsgGinInfo->blastcotpunit == FALSE) //?第一帧必然是COTP，不会是TPKT和TCP
		{
			pCapMsgGinInfo_First = pCapMsgGinInfo;
			bCoptBegin = TRUE;
			ntotalsize = 0;
		}
		bool  bCoptFin=false;
		if(bCoptBegin && (pCapMsgGinInfo->napptype == ETHER_TYPE_COTP || pCapMsgGinInfo->napptype == ETHER_TYPE_TPKT || pCapMsgGinInfo->napptype == IEC61850_ETHER_TYPE_MMS
			|| (pCapMsgGinInfo->napptype == ETHER_TYPE_TCP && pCapMsgGinInfo->nsourceinfo_length > 100)))//pCapMsgGinInfo->nsourceinfo_length > 100 应用报文?
		{
			map_cotplist_temp.insert(std::map <int, CAPMSGGININFO*> :: value_type(pCapMsgGinInfo->nseq, pCapMsgGinInfo));
			ntotalsize += pCapMsgGinInfo->nsourceinfo_length;//统计总长度
			if (!pCapMsgGinInfo->blastcotpunit)
			{
				bCoptFin=Cotp_Packet_Fin(map_cotplist_temp,pCapMsgGinInfo_First);
			}
		}
		if(!bCoptFin && ntotalsize > 23010)//异常情况，最长报文15帧，超过15帧认为异常
		{
			ntotalsize = 0;
			map_cotplist_temp.clear();
			bCoptBegin = FALSE;
		}
		
		if((pCapMsgGinInfo->napptype == IEC61850_ETHER_TYPE_MMS || bCoptFin ||
			((pCapMsgGinInfo->napptype == ETHER_TYPE_COTP ||pCapMsgGinInfo->napptype == ETHER_TYPE_TPKT)&& pCapMsgGinInfo->blastcotpunit == true))
			&& map_cotplist_temp.size() > 0)
		{//帧>=2的mms报文分析
#ifdef _DEBUG
//			TRACE("[%d]ip_src:%s ip_dst:%s\r\n",pCapMsgGinInfo_First->nseq,pCapMsgGinInfo_First->csrc_ip,pCapMsgGinInfo_First->cdst_ip);
#endif
			Cotp_Packet_Aanlyze(map_cotplist_temp,pCapMsgGinInfo_First);//报文就绪,将报文放在开始第一帧
            g_ScanDissectPacketer->I_XJ_DISSECT_MUL_PACKET(pCapMsgGinInfo_First,0);
            g_capTransformer->I_XJ_PKT_STRUCT_MAKE_MMS_INFO_STRUCT(pCapMsgGinInfo_First,FALSE);//制作MMS报文,格式错误报文也显示
			map_cotplist_temp.clear();
			bCoptBegin = FALSE;
	
		}
	}
	//最后未出现报文的处理
	if(TRUE == bCoptBegin && map_cotplist_temp.size() > 0)
	{
#ifdef _DEBUG
//		TRACE("--[%d]ip_src:%s ip_dst:%s\r\n",pCapMsgGinInfo_First->nseq,pCapMsgGinInfo_First->csrc_ip,pCapMsgGinInfo_First->cdst_ip);
#endif	
/*		Cotp_Packet_Aanlyze(map_cotplist_temp,pCapMsgGinInfo_First);//报文就绪,将报文放在开始第一帧
		pApp->m_ScanDissectPacketer.I_XJ_DISSECT_PACKET(pCapMsgGinInfo_First,0);
		pApp->m_pcatransformer->I_XJ_PKT_STRUCT_MAKE_MMS_INFO_STRUCT(pCapMsgGinInfo_First,FALSE);//制作MMS报文,格式错误报文也显示*/
		map_cotplist_temp.clear();
	}
	return 0;
}
/**************************将多帧报文的数据全部攒到最后一帧，然后调用接口进行解析*******************************/
/*
1.取出所有应用层报文进行合并
2.在合并后的报文里抽取所有的COPT数据
3.以最后一个报文头为基础组成一个新的数据帧
4.修改新报文的TPKT中的长度和应用报文长度
*/
bool CPackageCovertWrapper::Cotp_Packet_Fin(MAP_CAPMSGINFO& map_capmsginfo_cotplist,CAPMSGGININFO* pCapMsgGinInfo_first)
{
	char c_tcp_pacekt[65600];
	memset(c_tcp_pacekt,0,65600);
	CAPMSGGININFO* pCapMsgGinInfo_copt;
	std::map <int, CAPMSGGININFO* >::iterator iter;
	int ntemp = map_capmsginfo_cotplist.size();
	char* c_temp;
	//1.取出所有应用层报文进行合并
	unsigned int ntcp_segment_length = 0;
	unsigned int ntcp_segment_total_length = 0;
	for(iter = map_capmsginfo_cotplist.begin(); iter != map_capmsginfo_cotplist.end(); iter ++ )
	{
		pCapMsgGinInfo_copt = iter->second;
		c_temp = Get_TcpSegments_Position(pCapMsgGinInfo_copt->csourceinfo,pCapMsgGinInfo_copt->nsourceinfo_length,ntcp_segment_length);
		if(c_temp == NULL || ntcp_segment_length == 0 || ntcp_segment_length > 1518)//无数据或者数据异常
			continue;
		if(ntcp_segment_total_length + ntcp_segment_length < 65600)
		{
			memcpy(c_tcp_pacekt + ntcp_segment_total_length,c_temp,ntcp_segment_length);
		}
		else//超出,拷贝剩余部分
		{
			memcpy(c_tcp_pacekt + ntcp_segment_total_length,c_temp,65600-ntcp_segment_total_length);
			break;
		}
		ntcp_segment_total_length += ntcp_segment_length;
		//pCapMsgGinInfo_first->map_cotplist.insert(std::map <int, CAPMSGGININFO*> :: value_type(pCapMsgGinInfo_copt->nseq, pCapMsgGinInfo_copt));//加入队列
	}
	//2.在合并后的报文里抽取所有的COPT数据
	unsigned int ncopt_segment_length = 0;
	unsigned int ncopt_segment_total_length = 0;
	unsigned int ntemplength = 0;
	unsigned int ntpktlength = 0;
	char c_copt_pacekt[65600];
	memset(c_copt_pacekt,0,65600);
	char* cotp_pos;
	bool blastdataunit = false;
	while(ntemplength < ntcp_segment_total_length)
	{
		cotp_pos = Get_CoptSegments_Postion_FromTpktPackage(c_tcp_pacekt+ntemplength,ntpktlength,ncopt_segment_length,blastdataunit);
		if(ncopt_segment_length == 0 || ncopt_segment_length> 1514|| cotp_pos == NULL)//长度异常判断
			break;
		if(ncopt_segment_total_length + ncopt_segment_length < 65600)//越限判断
		{
			memcpy(c_copt_pacekt+ncopt_segment_total_length,cotp_pos,ncopt_segment_length);//拷贝COPT数据
		}
		else
		{
			memcpy(c_copt_pacekt+ncopt_segment_total_length,cotp_pos,65600 -ncopt_segment_total_length);
			break;
		}
		ntemplength += ntpktlength;
		ncopt_segment_total_length += ncopt_segment_length;//copt报文长度
		if(true == blastdataunit)//找到了最后一帧
		{
			break;
		}
	}

	return blastdataunit;
}
/**************************将多帧报文的数据全部攒到最后一帧，然后调用接口进行解析*******************************/
/*
1.取出所有应用层报文进行合并
2.在合并后的报文里抽取所有的COPT数据
3.以最后一个报文头为基础组成一个新的数据帧
4.修改新报文的TPKT中的长度和应用报文长度
*/
int CPackageCovertWrapper::Cotp_Packet_Aanlyze(MAP_CAPMSGINFO map_capmsginfo_cotplist,CAPMSGGININFO* pCapMsgGinInfo_first)
{
	char c_tcp_pacekt[65600];
	memset(c_tcp_pacekt,0,65600);
	CAPMSGGININFO* pCapMsgGinInfo_copt;
	std::map <int, CAPMSGGININFO* >::iterator iter;
	int ntemp = map_capmsginfo_cotplist.size();
	char* c_temp;
	//1.取出所有应用层报文进行合并
	unsigned int ntcp_segment_length = 0;
	unsigned int ntcp_segment_total_length = 0;
	for(iter = map_capmsginfo_cotplist.begin(); iter != map_capmsginfo_cotplist.end(); iter ++ )
	{
		pCapMsgGinInfo_copt = iter->second;
		c_temp = Get_TcpSegments_Position(pCapMsgGinInfo_copt->csourceinfo,pCapMsgGinInfo_copt->nsourceinfo_length,ntcp_segment_length);
		if(c_temp == NULL || ntcp_segment_length == 0 || ntcp_segment_length > 1518)//无数据或者数据异常
			continue;
		if(ntcp_segment_total_length + ntcp_segment_length < 65600)
		{
			memcpy(c_tcp_pacekt + ntcp_segment_total_length,c_temp,ntcp_segment_length);
		}
		else//超出,拷贝剩余部分
		{
			memcpy(c_tcp_pacekt + ntcp_segment_total_length,c_temp,65600-ntcp_segment_total_length);
			break;
		}
		ntcp_segment_total_length += ntcp_segment_length;
		pCapMsgGinInfo_first->map_cotplist.insert(std::map <int, CAPMSGGININFO*> :: value_type(pCapMsgGinInfo_copt->nseq, pCapMsgGinInfo_copt));//加入队列
	}
	//2.在合并后的报文里抽取所有的COPT数据
	unsigned int ncopt_segment_length = 0;
	unsigned int ncopt_segment_total_length = 0;
	unsigned int ntemplength = 0;
	unsigned int ntpktlength = 0;
	char c_copt_pacekt[65600];
	memset(c_copt_pacekt,0,65600);
	char* cotp_pos;
	bool blastdataunit = false;
	while(ntemplength < ntcp_segment_total_length)
	{
		cotp_pos = Get_CoptSegments_Postion_FromTpktPackage(c_tcp_pacekt+ntemplength,ntpktlength,ncopt_segment_length,blastdataunit);
		if(ncopt_segment_length == 0 || ncopt_segment_length> 1514|| cotp_pos == NULL)//长度异常判断
			break;
		if(ncopt_segment_total_length + ncopt_segment_length < 65600)//越限判断
		{
			memcpy(c_copt_pacekt+ncopt_segment_total_length,cotp_pos,ncopt_segment_length);//拷贝COPT数据
		}
		else
		{
			memcpy(c_copt_pacekt+ncopt_segment_total_length,cotp_pos,65600 -ncopt_segment_total_length);
			break;
		}
		ntemplength += ntpktlength;
		ncopt_segment_total_length += ncopt_segment_length;//copt报文长度
		if(true == blastdataunit)//找到了最后一帧
		{
			break;
		}
	}
	//3.以最后一个报文头为基础组成一个新的数据帧
	 Get_TcpSegments_Position(pCapMsgGinInfo_first->csourceinfo,pCapMsgGinInfo_first->nsourceinfo_length,ntcp_segment_length);//得到最后一帧报文的应用报文
	 unsigned int npkt_head_length = pCapMsgGinInfo_first->nsourceinfo_length - ntcp_segment_length;//新报文的头长度,不包括TPKT和COPT
	 pCapMsgGinInfo_first->nsourceinfo_cotp_length = ncopt_segment_total_length + npkt_head_length + 7;//新报文copt长度=头长度+7+copt报文长度
	 pCapMsgGinInfo_first->csourceinfo_cotp = new char[pCapMsgGinInfo_first->nsourceinfo_cotp_length];
	 //拷贝新报文的报文头
	 memcpy(pCapMsgGinInfo_first->csourceinfo_cotp,pCapMsgGinInfo_first->csourceinfo,npkt_head_length);
	 //修改IP报文头中的报文长度
	 //获取IP报文开始位置
	 int ipstart = GetIP_ST_POSITION(pCapMsgGinInfo_first->csourceinfo_cotp);
	 unsigned short ip_length = pCapMsgGinInfo_first->nsourceinfo_cotp_length -ipstart;
	 pCapMsgGinInfo_first->csourceinfo_cotp[ipstart+2] = (ip_length>>8);
	 pCapMsgGinInfo_first->csourceinfo_cotp[ipstart+3] = ((ip_length<<8)/0x100);
//	 memcpy(pCapMsgGinInfo_Last->csourceinfo_cotp+ipstart+2,(char*)ip_length,1);
//	  memcpy(pCapMsgGinInfo_Last->csourceinfo_cotp+ipstart+3,(char*)ip_length+1,1);
	 //4.制作TPKT
	 char* ip_tpkt_len_pos = pCapMsgGinInfo_first->csourceinfo_cotp + npkt_head_length;
	 ip_tpkt_len_pos[0] = 0x3;//版本
	 ip_tpkt_len_pos[1] = 0x0;//备用
	 unsigned short tpkt_length = ncopt_segment_total_length+7;//不超过2字节
	 ip_tpkt_len_pos[2] = (tpkt_length>>8);
	 ip_tpkt_len_pos[3]= (tpkt_length<<8/0x100);
	 //5.制作COPT
	 ip_tpkt_len_pos[4]= 0x02;  //长度
     ip_tpkt_len_pos[5]= 0xf0; //PDU类型
	 ip_tpkt_len_pos[6]= 0x80;  //是否时最后数据单元
	 //5拷备所有COPT数据
	 memcpy(pCapMsgGinInfo_first->csourceinfo_cotp+npkt_head_length+7,c_copt_pacekt,ncopt_segment_total_length);

	return 0;
}
/********************获取TCP应用报文的开始位置以及应用报文的长度****************************/
/*返回的值是应用报文开始的指针位置
char* p_packet_src  完整数据包
unsigned int packet_src_length 数据包的长度
tcp_segment_length             TCP应用报文长度
*/
char* CPackageCovertWrapper::Get_TcpSegments_Position(char* p_packet_src,unsigned int packet_src_length,unsigned int& ntcp_segment_length)
{
	ntcp_segment_length = 0;
	int ntcpsegement_pos = 0;
	//先拷贝最后一帧的帧应用头
	int ncopylength;
	ntcpsegement_pos += 16;//跳过pcap头
	ncopylength = 14;//
	if (0x81==(unsigned char)p_packet_src[ntcpsegement_pos + ncopylength] && 0x00==(unsigned char)p_packet_src[ntcpsegement_pos+ncopylength+1])//VLAN处理
	{
		ncopylength = ncopylength+2;
	}
	ntcpsegement_pos += ncopylength;
	//IP报文头计算
	unsigned char ucharTemp = (unsigned char)p_packet_src[ntcpsegement_pos];
	ucharTemp = ucharTemp&0xf;//取字节后4位，计算IP报文头长度
	ncopylength = ucharTemp* 4;//IP的报文头长度
	ntcpsegement_pos += ncopylength;
	//TCP报文头计算
	ucharTemp = (unsigned char)p_packet_src[ntcpsegement_pos+12];//
	ncopylength = ucharTemp/0x4;//计算头长度
	ntcpsegement_pos += ncopylength;

	ntcp_segment_length = packet_src_length - ntcpsegement_pos;//
	return p_packet_src+ ntcpsegement_pos;//返回指针位置
}
/*
  从TPKT报文中获取COPT报文的开始指针以及长度
  返回值：COTP报文的起始位置
  char* p_tpkt_src                      tpkt报文开始位置
  unsigned int& tpkt_src_length         tpkt报文的长度
  unsigned int& ncoptsegement_length    报文中copt报文的长度
  bool&   lastdataunit                  连续报文结束标志
*/
char* CPackageCovertWrapper::Get_CoptSegments_Postion_FromTpktPackage(char* p_tpkt_src,unsigned int& tpkt_src_length,unsigned int& ncoptsegement_length,bool& blastdataunit)
{
   blastdataunit = false;
   int ncopt_startpos = 0;
/****************/
//tpkt报文结构
//版本     1字节          0X03
    ncopt_startpos +=1;
//备用     1字节          0X00
	ncopt_startpos +=1;
//长度     2字节  包含TPKT自身的4字节长度，
    tpkt_src_length = (unsigned char)p_tpkt_src[ncopt_startpos]*0x100+ (unsigned char)p_tpkt_src[ncopt_startpos+1];//TPKT的长度
	ncoptsegement_length = tpkt_src_length -7;//实际的COPT报文长度为TPKT的长度-7
	ncopt_startpos +=2;
/****************/
//cotp报文结构
//长度 1字节         一般为2
	ncopt_startpos +=1;
//PDU类型            1字节        一般为OXF0
	ncopt_startpos +=1;
//是否时最后数据单元 1字节 如果为否 为0X00 如果为是 值为0X80
	if(0x80 == (p_tpkt_src[ncopt_startpos]&0x80))
	{
		blastdataunit = true;
	}
	ncopt_startpos +=1;
	return p_tpkt_src + ncopt_startpos;//返回本帧copt报文的起始位置
}
/**********************得到IP层起始位置*****************/
/**********
char* p_packet_src 原始数据包
nip_beforlength    ip开始前的长度
*******/
int CPackageCovertWrapper::GetIP_ST_POSITION(char* p_packet_src)
{
	int nip_beforlength = 0;
	nip_beforlength += 16;//跳过pcap头
	//先拷贝最后一帧的帧应用头
	int ncopylength = 14;
	if (0x81==(unsigned char)p_packet_src[nip_beforlength + ncopylength] && 0x00==(unsigned char)p_packet_src[nip_beforlength+ncopylength+1])//VLAN处理
	{
		ncopylength = ncopylength+2;
	}
	nip_beforlength += ncopylength;
	return nip_beforlength;//返回IP开始部分
}

