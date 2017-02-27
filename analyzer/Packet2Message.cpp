#pragma execution_character_set("UTF-8")

#include "Msg2SmvPdu.h"
#include "ParseASN1.h"
#include "Packet2Message.h"

//CPacketConvert_I * createPktConvertI()
//{
//	CPacketConvert_I *p_pktconvert = new CPacketConvert;

//	return p_pktconvert;

//}

//void destroyPktConvertI(CPacketConvert_I * theInterface)
//{
//	if (NULL != theInterface)
//	{
//		delete (CPacketConvert *)theInterface;
//		theInterface = NULL;
//	}
//}

CPacketConvert::~CPacketConvert()
{
	End();
}

int CPacketConvert::packetconvert_init(PKTCONVERT_CFG_STRUCT CfgInfo)
{
	int nRet = RES_FAIL;

	nRet = OpenLogFile(CfgInfo.logInfo);

	m_bParseSmvDA = CfgInfo.bParseSmvDA;
	m_bParseGooseDA = CfgInfo.bParseGooseDA;

	return nRet;
}

int CPacketConvert::End()
{
	int nRet = RES_SUCCESS;

	m_LogFile.Close();

	return nRet;
}

int CPacketConvert::OpenLogFile(LOG_STRUCT logInfo)
{
	int nRet = RES_SUCCESS;
	string strSetLogpath = "";

	m_LogFile.SetLogLevel(logInfo.nLogLevel);
	m_LogFile.SetLogSize(logInfo.nLogMaxLen);
	strSetLogpath = GetFormatPath(logInfo.cLogPath);
	m_LogFile.SetLogPath(strSetLogpath.c_str());

	if (FALSE == m_LogFile.Open("packetconvert.log"))
	{
		printf("open log file:%s\\packetconvert.log fail!\n", logInfo.cLogPath);
		return RES_FAIL;
	}

	return nRet;
}

//int CPacketConvert::packetconvert_2smv(PACKET_CHAR_STRUCT* p_packet,int n_num, SMV_INFO_STRUCT *p_msg)
//{
//	int nRet = RES_SUCCESS;
//	int i=0;
//	char *p_buf_tmp =NULL;
//	int nStep;
//	int nstart = 28;
//	int npacketdatalen = p_packet->nLen;//全部报文长度
//	if(npacketdatalen < 76)//最小长度
//		return RES_FAIL;
//	ETHER_TYPE n_ethertype = IEC61850_ETHER_TYPE_UNKOWN;
//
//	if (NULL==p_packet || NULL==p_msg)
//	{
//		return RES_FAIL;
//	}
//
//	for (i=0; i<n_num; i++)
//	{
//		p_buf_tmp = p_packet[i].c_pacekt;
//		//获取协议类型
//		n_ethertype = packetconvert_get_ether_type(p_packet[i].c_pacekt);
//		if (IEC61850_ETHER_TYPE_SMV != n_ethertype)
//		{
//			m_LogFile.FormatAdd(CLogFile::error, "packetconvert_2smv失败, 第%d帧不是SMV报文", i+1);
//			nRet = RES_FAIL;
//			break;
//		}
//
//		nStep = 0;
//		
//		//解析报文到达时间
////		nStep += ParseAvtm(p_buf_tmp,p_msg[i].c_avtm_epocsec);//效率低
//		memcpy(p_msg[i].c_avtm_epocsec, p_buf_tmp, 8);//为了提高效率、和在线分析统一处理
//		nStep += 8;
//		
//		nStep += 8;//跳过InclLen和OrigLen
//		
//		//解析目的MAC地址
////		nStep += ParseMac(p_buf_tmp+nStep,p_msg[i].c_dest_mac);//效率低
//		memcpy(p_msg[i].c_dest_mac, p_buf_tmp+nStep, 6);//为了提高效率、和在线分析统一处理
//		nStep += 6;
//		
//		//解析源MAC地址
////		nStep += ParseMac(p_buf_tmp+nStep,p_msg[i].c_src_mac);//效率低
//		memcpy(p_msg[i].c_src_mac, p_buf_tmp+nStep, 6);//为了提高效率、和在线分析统一处理
//		nStep += 6;
//		
//		if (0x81==(unsigned char)p_buf_tmp[nstart] && 0x00==(unsigned char)p_buf_tmp[nstart+1])
//			nStep += 6;//跳过Priority tagged和ethertype
//		else
//			nStep += 2;
//		
//		//解析APPID
//		nStep += ParseAppid(p_buf_tmp+nStep,p_msg[i].n_app_id);
//		//解析msg_len	
//		nStep += ParseMsgLen(p_buf_tmp+nStep,p_msg[i].n_msg_len);
//
//		if(p_msg[i].n_msg_len > (npacketdatalen -nStep + 4))//应用数据长度判断 应用数据长度包含appid和length的占位
//		{
//			return RES_FAIL;
//		}
//		nStep += 4;//跳过reserve1和reserve2
//		//解析ASDU
//		nStep += ParseASDU(p_buf_tmp+nStep,&p_msg[i],m_bParseSmvDA);
//	}
//	
//	return nRet;
//}

//int CPacketConvert::packetconvert_2goose(PACKET_CHAR_STRUCT* p_packet,int n_num, GOOSE_INFO_STRUCT* p_msg)
//{
//	int nRet = RES_SUCCESS;
//	int i=0;
//	char *p_buf_tmp =NULL;
//	int nStep;
//	char *p_type = NULL;
//	int nstart = 28;
//	ETHER_TYPE n_ethertype = IEC61850_ETHER_TYPE_UNKOWN;
//	int npacketdatalen = p_packet->nLen;//全部报文长度
//	if(npacketdatalen < 76)//增加判断 add by yinzhehong 20130325
//		return RES_FAIL;
//	if (NULL==p_packet || NULL==p_msg)
//	{
//		return RES_FAIL;
//	}
//
//	for (i=0; i<n_num; i++)
//	{
//		p_buf_tmp = p_packet[i].c_pacekt;
//		//获取协议类型
//		n_ethertype = packetconvert_get_ether_type(p_packet[i].c_pacekt);
//		if (IEC61850_ETHER_TYPE_GOOSE != n_ethertype)
//		{
//			m_LogFile.FormatAdd(CLogFile::error, "packetconvert_2goose失败, 第%d帧不是GOOSE报文", i+1);
//			nRet = RES_FAIL;
//			break;
//		}
//
//		nStep = 0;
//		
//		//解析报文到达时间
//		nStep += ParseAvtm(p_buf_tmp,p_msg[i].c_avtm_epocsec);
//		
//		nStep += 8;//跳过InclLen和OrigLen
//		
//		//解析目的MAC地址
//		nStep += ParseMac(p_buf_tmp+nStep,p_msg[i].c_dest_mac);
//		
//		//解析源MAC地址
//		nStep += ParseMac(p_buf_tmp+nStep,p_msg[i].c_src_mac);
//		
//		if (0x81==(unsigned char)p_buf_tmp[nstart] && 0x00==(unsigned char)p_buf_tmp[nstart+1])
//			nStep += 6;//跳过Priority tagged和ethertype
//		else
//			nStep += 2;
//		
//		//解析APPID
//		nStep += ParseAppid(p_buf_tmp+nStep,p_msg[i].n_app_id);
//		
//		//解析msg_len
//		if(nStep +2 >= npacketdatalen)//增加判断 add by yinzhehong 20130325
//			return RES_FAIL;
//		nStep += ParseMsgLen(p_buf_tmp+nStep,p_msg[i].n_msg_len);
//
//		if(p_msg[i].n_msg_len > (npacketdatalen -nStep + 4))//应用数据长度判断 应用数据长度包含appid和length的占位
//		{
//			return RES_FAIL;
//		}
//		//解析reserve1
//		nStep += ParseReserve(p_buf_tmp+nStep,p_msg[i].c_reserved1);
//		
//		//解析reserve2
//		nStep += ParseReserve(p_buf_tmp+nStep,p_msg[i].c_reserved2);
//
//		nStep += ParseGoosePdu(p_buf_tmp+nStep,&p_msg[i], m_bParseGooseDA);
//	}
//	
//	return nRet;
//}
/******************1588报文解析*******************/
//int CPacketConvert::packetconvert_2ptp(PACKET_CHAR_STRUCT* p_packet,int n_num, PTP_INFO_STRUCT* p_msg)
//{
//	int nRet = RES_SUCCESS;
//	int i;
//	int nStep = 0;
//	int nstart = 28;
//	char *p_buf_tmp =NULL;
//	char *pTmp = NULL;
////	double d_correction_test=0;//测试
//
//	if (NULL==p_packet || NULL==p_msg)
//	{
//		return RES_FAIL;
//	}
//
//	for (i=0; i<n_num; i++)
//	{
//		p_buf_tmp = p_packet[i].c_pacekt;
//
//		//解析报文到达时间
//		nStep += ParseAvtm(p_buf_tmp,p_msg[i].c_avtm_epocsec);
//		nStep += 8;//跳过InclLen和OrigLen
//		//解析目的MAC地址
//		nStep += ParseMac(p_buf_tmp+nStep,p_msg[i].c_dest_mac);	
//		//解析源MAC地址
//		nStep += ParseMac(p_buf_tmp+nStep,p_msg[i].c_src_mac);
//		
//		if (0x81==(unsigned char)p_buf_tmp[nstart] && 0x00==(unsigned char)p_buf_tmp[nstart+1])
//			nStep += 6;//跳过Priority tagged和ethertype
//		else
//			nStep += 2;
//
//		//PTP报文头
// 		memcpy(&(p_msg[i].ptp_header), p_buf_tmp+nStep, 34);
// 		nStep += 34;
//		p_msg[i].ptp_header.enum_ptp_msg_type = p_msg[i].ptp_header.enum_ptp_msg_type & 0X0F;
//		p_msg[i].ptp_header.n_ptp_vertion = p_msg[i].ptp_header.n_ptp_vertion & 0X0F;
//		p_msg[i].ptp_header.n_msg_len = reverse_2byte(p_msg[i].ptp_header.n_msg_len);
//
//		/***********************测试************************************/
///*		char ctest[256]={0};
//		CLOCK_IDENTITY_STRUCT *ptest = &(p_msg[i].ptp_header.port_identity.clock_identity);
//		sprintf(ctest, "0x%0x%0x%0x%0x%0x%0x%0x%0x",\
//			ptest->c_bit0,ptest->c_bit1,ptest->c_bit2,ptest->c_bit3,ptest->c_bit4,ptest->c_bit5,\
//			ptest->c_bit6,ptest->c_bit7);
//
//		get_correction_val(p_msg[i].ptp_header.correction_field, d_correction_test); */
//		/**************************************************************/
//
//		p_msg[i].ptp_header.port_identity.u_port_id = reverse_2byte(p_msg[i].ptp_header.port_identity.u_port_id);
//		p_msg[i].ptp_header.n_sq_id = reverse_2byte(p_msg[i].ptp_header.n_sq_id);
//
//		//解析报文具体内容
//		nStep += ParsePTPbody(p_buf_tmp+nStep, p_msg[i].ptp_header.enum_ptp_msg_type, &p_msg[i]);
//	}
//
//	return nRet;
//}

int CPacketConvert::ParsePTPbody(char *p_buf, uint8 n_ptp_msg_type, PTP_INFO_STRUCT* p_msg)
{
	int nStep = 0;
	char cTmp = 0;
	char *pTmp = NULL;

	/****************测试*********/
	__int64 n_sec_test=0;
	UINT n_Nsec_test=0;
	/****************************/
	
	if (NULL==p_buf || NULL==p_msg)
	{
		return 0;
	}
	
	switch (n_ptp_msg_type)
	{
	case PTP_SYNC_MESSAGE:
		nStep = sizeof(SYNC_STRUCT);
		memcpy( &(p_msg->u.msg_sync), p_buf, nStep );
//2013/04/03删除，此处计算放到函数get_timestamp_s_ns中实现		p_msg->u.msg_sync.time_stamp_origin.u_nanoseconds = reverse_4byte(p_msg->u.msg_announce.time_stamp_origin.u_nanoseconds);
		break;
		
	case PTP_DELAY_REQ_MESSAGE:
		nStep = sizeof(DELAY_REQ_STRUCT);
		memcpy( &(p_msg->u.msg_delay_req), p_buf, nStep );
//2013/04/03删除，此处计算放到函数get_timestamp_s_ns中实现		p_msg->u.msg_delay_req.time_stamp_origin.u_nanoseconds = reverse_4byte(p_msg->u.msg_announce.time_stamp_origin.u_nanoseconds);
		break;
		
	case PTP_FOLLOWUP_GENERAL:
		nStep = sizeof(FOLLOW_UP_STRUCT);
		memcpy( &(p_msg->u.msg_follow_up), p_buf, nStep );
//2013/04/03删除，此处计算放到函数get_timestamp_s_ns中实现		p_msg->u.msg_follow_up.time_stamp_origin.u_nanoseconds = reverse_4byte(p_msg->u.msg_announce.time_stamp_origin.u_nanoseconds);
		break;
		
	case PTP_ANNOUNCE_GENERAL:
		nStep = sizeof(ANNOUNCE_STRUCT);
		memcpy( &(p_msg->u.msg_announce), p_buf, nStep );

		/************************测试********/
//		get_timestamp_s_ns(p_msg->u.msg_announce.time_stamp_origin, n_sec_test,n_Nsec_test );
		/************************************/

//删除，此处计算放到函数get_timestamp_s_ns中实现		p_msg->u.msg_announce.time_stamp_origin.u_nanoseconds = reverse_4byte(p_msg->u.msg_announce.time_stamp_origin.u_nanoseconds);
		p_msg->u.msg_announce.n_utcoffset = reverse_2byte(p_msg->u.msg_announce.n_utcoffset);
		p_msg->u.msg_announce.u_masterpriority1 = reverse_2byte(p_msg->u.msg_announce.u_masterpriority1);
		
		p_msg->u.msg_announce.clock_quality.u_offsetScaledLogVariance = \
			reverse_2byte(p_msg->u.msg_announce.clock_quality.u_offsetScaledLogVariance);
		p_msg->u.msg_announce.u_steps_removed = reverse_4byte(p_msg->u.msg_announce.u_steps_removed);
		break;
		
	case PTP_DELAY_RESP_GENERAL:
		nStep = sizeof(DELAY_RESP_STRUCT);
		memcpy( &(p_msg->u.msg_delay_resp), p_buf, nStep );
//2013/04/03删除，此处计算放到函数get_timestamp_s_ns中实现		p_msg->u.msg_delay_resp.time_stamp_origin.u_nanoseconds = reverse_4byte(p_msg->u.msg_announce.time_stamp_origin.u_nanoseconds);
		break;
		
	case PTP_PDELAY_REQ_MESSAGE:
		nStep = sizeof(PDELAY_REQ_STRUCT);
		memcpy( &(p_msg->u.msg_pdelay_req), p_buf, nStep );
//2013/04/03删除，此处计算放到函数get_timestamp_s_ns中实现		p_msg->u.msg_pdelay_req.time_stamp_origin.u_nanoseconds = reverse_4byte(p_msg->u.msg_announce.time_stamp_origin.u_nanoseconds);
		break;
		
	case PTP_PDELAY_RESP_MESSAGE:
		nStep = sizeof(PDELAY_RESP_STRUCT);
		memcpy( &(p_msg->u.msg_pdelay_resp), p_buf, nStep );
//2013/04/03删除，此处计算放到函数get_timestamp_s_ns中实现		p_msg->u.msg_pdelay_resp.time_stamp_origin.u_nanoseconds = reverse_4byte(p_msg->u.msg_announce.time_stamp_origin.u_nanoseconds);
		break;
		
	case PTP_MANAGEMENT_GENERAL:
		nStep = 20;
		memcpy( &(p_msg->u.msg_ptp_manage), p_buf, nStep );
		p_msg->u.msg_ptp_manage.n_action_filed = p_msg->u.msg_ptp_manage.n_action_filed & 0X0F;
		p_msg->u.msg_ptp_manage.management_tlv.u_length_field = reverse_2byte(p_msg->u.msg_ptp_manage.management_tlv.u_length_field);
		p_msg->u.msg_ptp_manage.management_tlv.u_management_id = reverse_2byte(p_msg->u.msg_ptp_manage.management_tlv.u_management_id);

/*		nStep = 12;
		memcpy( &(p_msg->u.msg_ptp_manage), p_buf, nStep );
		
		pTmp = p_buf+nStep;
		cTmp = pTmp[0];
		cTmp = cTmp & 0X0F;
		p_msg->u.msg_ptp_manage.n_action_filed = (ACTITION_TYPE)cTmp;
		nStep+=1;//跳过reserved和n_action_filed
		
		nStep+=1;//跳过c_reserved
		
		memcpy( &(p_msg->u.msg_ptp_manage.management_tlv.n_tlv_type),p_buf+nStep, 2);
		nStep+=2;//跳过tlv_type
		
		memcpy( &(p_msg->u.msg_ptp_manage.management_tlv.u_length_field),p_buf+nStep, 2);
		nStep+=2;//跳过tlv_length
	*/	
		nStep+=p_msg->u.msg_ptp_manage.management_tlv.u_length_field;
		break;

	case PTP_SIGNALING_GENERAL:
		break;
		
	case PTP_PDELAY_RESP_FOLLOW_UP_GENERAL:
		break;
		
	default:
		break;
	}
	
	return nStep;
}

/********将4字节转换成整数符号*************/
int CPacketConvert::Parser4Char2Int(char *c_buf)
{
	int nTemp = 0;
	char c_temp[8];
	memset(c_temp,0,8);
	memcpy(c_temp,c_buf,4);
	c_temp[4] = c_temp[3];
	c_temp[5] = c_temp[2];
	c_temp[6] = c_temp[1];
	c_temp[7] = c_temp[0];
	memcpy((char *)&nTemp,c_temp+4,4);
	return nTemp;
}

int CPacketConvert::ParseAvtm(char *p_packet_buf, char *c_avtm)
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
	
//	sprintf(c_avtm, "%d.%06d", n_secs, n_usecs);
	sprintf(c_avtm, "%u.06u", n_secs, n_usecs);//modified on 2013/03/31
	
	nLen = 8;
	return nLen;
}
/*
int CPacketConvert::ParseMac(char *p_packet_buf, char *p_mac)
{
	int i=0;
	int nLen = 0;
	int n_pos =0;
	int n_start = 0;
	if (NULL==p_packet_buf || NULL==p_mac)
	{
		return 0;
	}
	
	//解析目的MAC地址
	for (i=0; i<6; i++)
	{
		sprintf(&p_mac[n_pos],"%02x",(unsigned char)p_packet_buf[i]);
		if (i<5)
		{
			strcat(p_mac,"-");
		}
		n_pos = 3*(i+1);
	}
	
	nLen = 6;
	return nLen;
}*/
int CPacketConvert::ParseMac(char *p_packet_buf, char *p_mac)
{
	int i=0;
	int nLen = 0;

	sprintf(p_mac,"%02x-%02x-%02x-%02x-%02x-%02x",
		(unsigned char)p_packet_buf[0], (unsigned char)p_packet_buf[1], \
		(unsigned char)p_packet_buf[2], (unsigned char)p_packet_buf[3], \
		(unsigned char)p_packet_buf[4], (unsigned char)p_packet_buf[5]);
	
	nLen = 6;
	return nLen;
}
/*
int CPacketConvert::ParseAppid(char *p_packet_buf, unsigned int &n_appid)
{
	int nLen = 0;
	if (NULL==p_packet_buf)
	{
		return 0;
	}
	
	unsigned short n_tmp = 0;
	ValueBuf2Uint16(p_packet_buf,n_tmp);
	n_appid = n_tmp;
	
	nLen = 2;
	return nLen;
}*/
int CPacketConvert::ParseAppid(char *p_packet_buf, unsigned int &n_appid)
{

	n_appid = 256*((unsigned char)p_packet_buf[0]) + (unsigned char)p_packet_buf[1];
	
	return 2;
}

/*int CPacketConvert::ParseMsgLen(char *p_packet_buf, int &n_msglen)
{
	int nLen = 0;
	if (NULL==p_packet_buf)
	{
		return 0;
	}
	
	unsigned short n_tmp = 0;
	ValueBuf2Uint16(p_packet_buf,n_tmp);
	n_msglen = n_tmp;
	
	nLen = 2;
	return nLen;
}*/

int CPacketConvert::ParseMsgLen(char *p_packet_buf, int &n_msglen)
{
	n_msglen = 256*((unsigned char)p_packet_buf[0]) + (unsigned char)p_packet_buf[1];

	return 2;
}

int CPacketConvert::ParseReserve(char *p_packet_buf,char *c_reserve)
{
	int nLen = 0;
	
	sprintf(&c_reserve[0],"%02x",(unsigned char)p_packet_buf[0]);
	
	nLen = 2;
	return nLen;
}

//int CPacketConvert::ParseASDU(char *p_packet_buf,SMV_INFO_STRUCT *p_smv_info,bool b_parseData)
//{
//	int nLen = 0;
//	if (NULL==p_packet_buf || NULL==p_smv_info)
//	{
//		return 0;
//	}
//	
//	nLen += MSIS_ASDU_Sum(p_packet_buf, p_smv_info);
//	p_smv_info->n_nofasdu_actual = p_smv_info->n_asdu_num;
//	
//	//构造每一个ASDU结构
//	CreateAsduInfo(p_smv_info);
//	for(int i=0; i<p_smv_info->n_asdu_num; i++)
//	{
//		nLen += MSIS_ASDU(p_packet_buf+nLen,&(p_smv_info->p_asdu_info_struct[i]),b_parseData);
//	}
//
//	return nLen;
//}

int CPacketConvert::ValueBuf2Uint16(char *p_value_buf, unsigned short &n_value)
{
	int nLen = 0;
	char c_tmp_buf[3];
	if (NULL==p_value_buf)
	{
		return 0;
	}
	
	memset(c_tmp_buf,0,3);
	ReverseBeginNchar(p_value_buf,2,c_tmp_buf);
	memcpy((char*)&n_value,c_tmp_buf,2);
	
	nLen = 2;
	return nLen;
}

int CPacketConvert::ReverseBeginNchar(char *p_packet_buf, int n_reverse, char *p_dest)
{
	int nRet = RES_SUCCESS;
	int i = 0;
	char c_tmp;
	if (NULL==p_packet_buf || NULL==p_dest)
	{
		return RES_FAIL;
	}
	memcpy(p_dest,p_packet_buf,n_reverse);
	for (i=0; i<n_reverse/2; i++)
	{
		c_tmp = p_dest[i];
		p_dest[i] = p_dest[n_reverse-1-i];
		p_dest[n_reverse-1-i] = c_tmp;
	}
	
	return nRet;
}

int CPacketConvert::Parse2char(char *p_buf,char *c_data)
{
	int n_offset = 0;
	TLV_STRUCT_EX tlv;
	if (NULL==p_buf || NULL==c_data)
	{
		return 0;
	}

	memset(&tlv,0,sizeof(tlv));
	ParseASN1_TLV_ex(p_buf, &tlv);
	n_offset = tlv.nlen_T + tlv.nlen_L + tlv.nlen_V;

	memset(c_data,0,strlen(c_data));
	memcpy(c_data, tlv.p_V, tlv.nlen_V);

	return n_offset;
}

int CPacketConvert::Parse2UnInt(char *p_buf,UINT &n_data)
{
	int n_offset = 0;
	TLV_STRUCT_EX tlv;
	if (NULL==p_buf)
	{
		return 0;
	}
	char c_dest[MAX_DATA_LEN_TLV];//p_buf逆序后的前N个元素
	char c_value[MAX_PACKET_LEN];//值的字符表示

	memset(&tlv, 0, sizeof(tlv));
	ParseASN1_TLV_ex(p_buf, &tlv);
	n_offset = tlv.nlen_T + tlv.nlen_L + tlv.nlen_V;

	memset(c_dest,0,MAX_DATA_LEN_TLV);
	ReverseBeginNchar(tlv.p_V, tlv.nlen_V, c_dest);

	memset(c_value,0,MAX_PACKET_LEN);
	if (tlv.nlen_V >= 4)
	{
        sInt32ToAscii(*(int*)c_dest,c_value);
	}
	else if (tlv.nlen_V >= 2)
	{
        sInt16ToAscii(*(short*)c_dest,c_value);
	}
	else
	{
        sInt8ToAscii(*(int*)c_dest,c_value);
	}
//	sscanf(c_value,"%d",&n_data);

	sscanf(c_value,"%u",&n_data);

	return n_offset;
}

int CPacketConvert::Parse2Int(char *p_buf,int &n_data)
{
	int n_offset = 0;
	TLV_STRUCT_EX tlv;
	if (NULL==p_buf)
	{
		return 0;
	}
	char c_dest[MAX_DATA_LEN_TLV];//p_buf逆序后的前N个元素
	char c_value[MAX_PACKET_LEN];//值的字符表示

	memset(&tlv, 0, sizeof(tlv));
	ParseASN1_TLV_ex(p_buf, &tlv);
	n_offset = tlv.nlen_T + tlv.nlen_L + tlv.nlen_V;

	memset(c_dest,0,MAX_DATA_LEN_TLV);
	ReverseBeginNchar(tlv.p_V, tlv.nlen_V, c_dest);

	memset(c_value,0,MAX_PACKET_LEN);
	if (tlv.nlen_V >= 4)
	{
        sInt32ToAscii(*(int*)c_dest,c_value);
	}
	else if (tlv.nlen_V >= 2)
	{
        sInt16ToAscii(*(short*)c_dest,c_value);
	}
	else
	{
        sInt8ToAscii(*(char*)c_dest,c_value);
	}
	sscanf(c_value,"%d",&n_data);

	return n_offset;
}

int CPacketConvert::Parse2uInt16(char *p_buf, unsigned short &n_data)
{
	int n_offset = 0;
	TLV_STRUCT_EX tlv;
	if (NULL==p_buf)
	{
		return 0;
	}
	char c_tmp[MAX_PACKET_LEN];
	memset(c_tmp,0,MAX_PACKET_LEN);

	memset(&tlv, 0, sizeof(tlv));
	ParseASN1_TLV_ex(p_buf, &tlv);
	n_offset = tlv.nlen_T + tlv.nlen_L + tlv.nlen_V;

	uInt16ToAscii(*(short*)tlv.p_V, c_tmp);
	sscanf(c_tmp,"%d",&n_data);

	return n_offset;
}

int CPacketConvert::Parse2Float(char *p_buf,float &f_data)
{
	int n_offset = 0;
	TLV_STRUCT_EX tlv;
	if (NULL==p_buf)
	{
		return 0;
	}
	memset(&tlv, 0, sizeof(tlv));
	ParseASN1_TLV_ex(p_buf,&tlv);
	n_offset = tlv.nlen_T + tlv.nlen_L + tlv.nlen_V;

	memcpy((char*)&f_data, tlv.p_V, 4);

	return n_offset;
}

int CPacketConvert::Parse2Double(char *p_buf,double &d_data)
{
	int n_offset = 0;
	TLV_STRUCT_EX tlv;
	if (NULL==p_buf)
	{
		return 0;
	}
	memset(&tlv, 0, sizeof(tlv));
	ParseASN1_TLV_ex(p_buf,&tlv);
	n_offset = tlv.nlen_T + tlv.nlen_L + tlv.nlen_V;

	memcpy((char*)&d_data, tlv.p_V, 8);

	return n_offset;
}

int CPacketConvert::Parse2Bool(char *p_buf, bool &b_data)
{
	int n_offset = 0;
	TLV_STRUCT_EX tlv;
	if (NULL==p_buf)
	{
		return 0;
	}

	memset(&tlv, 0, sizeof(tlv));
	ParseASN1_TLV_ex(p_buf, &tlv);
	n_offset = tlv.nlen_T + tlv.nlen_L + tlv.nlen_V;

	memcpy((char*)&b_data, tlv.p_V, 1);

	return n_offset;
}

//modified on 2012-06-29 ljm
int CPacketConvert::Buf2MMSDataVetor(char *p_buf, vector<MMS_DATA_STRUCT>& v_mms_data)
{
	TLV_STRUCT_EX tlv;
	int n_offset =0;
	char *p_tmpbuf = NULL;
	if (NULL==p_buf)
	{
		return 0;
	}
	
	v_mms_data.clear();
	memset(&tlv,0,sizeof(tlv));
	ParseASN1_TLV_ex(p_buf,&tlv);
	n_offset = tlv.nlen_T + tlv.nlen_L;
	p_tmpbuf = p_buf+n_offset;

	//测试
//	m_LogFile.FormatAdd(CLogFile::trace, "tlv_nlen_v: %d", tlv.nlen_V);
	
	n_offset = 0;
	MMS_DATA_STRUCT tmp_mms_data;
	while (n_offset <tlv.nlen_V)
	{
		init_mms_data_ex(&tmp_mms_data);
		n_offset += ParseMMSData(p_tmpbuf+n_offset,&tmp_mms_data);
		v_mms_data.push_back(tmp_mms_data);
	}
	
	return n_offset;
}

int CPacketConvert::ParseMMSStructData(char *p_buf, MMS_DATA_STRUCT* p_mms_data)
{
	int n_offset = 0;
	int i;
	if (NULL==p_buf || NULL==p_mms_data)
	{
		return NULL;
	}

	vector<MMS_DATA_STRUCT> v_mms_datas;

	n_offset = Buf2MMSDataVetor(p_buf,v_mms_datas);
	if (0 >= v_mms_datas.size())
	{
		return n_offset;
	}

	p_mms_data->n_struct_num = v_mms_datas.size();
	p_mms_data->p_struct = CreateMMSDatas(v_mms_datas);

	for (i=0; i<v_mms_datas.size(); i++)
	{
		release_mms_data_ex(v_mms_datas[i]);
	}
	v_mms_datas.clear();

	return n_offset;
}

int CPacketConvert::init_mms_data(MMS_DATA_STRUCT* pmms_da, int n_num)
{
	int i;
	if (NULL==pmms_da)
	{
		return RES_FAIL;
	}

	for (i=0; i<n_num; i++)
	{
		memset(pmms_da[i].c_data, 0, sizeof(pmms_da[i].c_data) );
		pmms_da[i].n_struct_num = 0;
		pmms_da[i].p_struct = NULL;
		pmms_da[i].result = 0;
	}

	return RES_SUCCESS;
}

int CPacketConvert::set_mms_data(MMS_DATA_STRUCT mms_da_src, MMS_DATA_STRUCT* p_mms_da_dst)
{
	int nRet = RES_SUCCESS;
	int i;
	if (NULL==p_mms_da_dst)
	{
		return RES_FAIL;
	}

	p_mms_da_dst->n_struct_num = mms_da_src.n_struct_num;
	strcpy(p_mms_da_dst->c_data, mms_da_src.c_data);
	p_mms_da_dst->n_data_type = mms_da_src.n_data_type;
	p_mms_da_dst->result = mms_da_src.result;
	if (mms_da_src.n_struct_num>0)
	{
		p_mms_da_dst->p_struct = new MMS_DATA_STRUCT[mms_da_src.n_struct_num];
		for (i=0; i<mms_da_src.n_struct_num; i++)
		{
			set_mms_data(mms_da_src.p_struct[i], &p_mms_da_dst->p_struct[i]);
		}
	}

	return nRet;
}

MMS_DATA_STRUCT* CPacketConvert::CreateMMSDatas(vector<MMS_DATA_STRUCT> v_mms_data)
{
	MMS_DATA_STRUCT *p_datas = NULL;
	int i = 0;
	if (0 >= v_mms_data.size())
	{
		return NULL;
	}

	p_datas = new MMS_DATA_STRUCT[v_mms_data.size()];
//	init_mms_data(p_datas, v_mms_data.size());
	for (i=0; i<v_mms_data.size(); i++)
	{
		init_mms_data_ex(&p_datas[i]);
		set_mms_data(v_mms_data[i], &p_datas[i]);
//		memcpy(&p_datas[i],&v_mms_data[i],sizeof(MMS_DATA_STRUCT));
		int nTest = 0;
	}

	return p_datas;
}

int CPacketConvert::ParseGooseMMSDatas(char *p_buf, GOOSE_INFO_STRUCT* p_goose_info)
{
	int n_offset = 0;
	vector<MMS_DATA_STRUCT> v_mms_datas;
	int i;

	n_offset = Buf2MMSDataVetor(p_buf,v_mms_datas);
	if (0 >= v_mms_datas.size())
	{
		return n_offset;
	}

	p_goose_info->n_numDataStructs = v_mms_datas.size();
	p_goose_info->p_data_struct = CreateMMSDatas(v_mms_datas);

	for (i=0; i<v_mms_datas.size(); i++)
	{
		release_mms_data_ex(v_mms_datas[i]);
	}
	v_mms_datas.clear();

	return n_offset;
}

int CPacketConvert::UtcValsToString (char *dest, unsigned int secs, unsigned int fraction, unsigned int qflags)
{
        char theDate[MAX_TIME_STRING_LEN];
        char theFraction[25];
        char theQual[25];
    double dFraction;
	char *pFract;
    int b0, b1, b2, b3, rest;
	time_t t = secs;
	struct tm *pTm;

	/* get the date portion */
	pTm = gmtime (&t);
	if (!pTm)
	{
//		SLOGALWAYS0 ("UtcValsToString:  conversion failure - invalid seconds.");
		return RES_FAIL;
	}

	strftime (theDate, MAX_TIME_STRING_LEN, UTC_DEF_TIME_FORMAT, gmtime (&t));

	/* get the fraction portion */
//	dFraction = ((double) fraction / (double) 0x00FFFFFF);//和wireshark解析结果微秒有差异
    dFraction = ((double) fraction / (double) 0x01000000);//modified by ljm on 20120920 和wireshark解析结果统一
	sprintf (theFraction, " %#0.09f", dFraction);
	pFract = strchr (theFraction, '.');
	if (!pFract)
	{
//		SLOGALWAYS1 ("UtcToString - unable to convert fraction %d", fraction);
		return RES_FAIL;
	}

	/* get the qflags     */
	b0 = (qflags & 0x00000080);
	b1 = (qflags & 0x00000040);
	b2 = (qflags & 0x00000020);
	b3 = (qflags & 0x00000010);
	rest = (qflags &0x0000000F);

	b0 >>= 7;
	b1 >>= 6;
	b2 >>= 5;
	b3 >>= 4;

	sprintf (theQual, "Z(qual=%d,%d,%d,%d,%d)", b0, b1, b2, b3, rest);

	/* put em all together  */
	sprintf (dest, "%s%s%s", theDate, pFract, theQual);

	return RES_SUCCESS;
}

int CPacketConvert::ValueBuf2Utctime(char *p_value_buf, char *p_utctime)
{
	int nRet = RES_SUCCESS;
    unsigned int n_secs = 0;
    unsigned int n_usecs = 0;
    unsigned int n_qflags = 0;
	char c_dest[MAX_DATA_LEN_TLV];
	char c_tmp[MAX_DATA_LEN_TLV];

	if (NULL==p_value_buf || NULL==p_utctime)
	{
		return RES_FAIL;
	}

	//前四个字节表示相对1970-01-01的秒的整数
	memset(c_tmp,0,MAX_DATA_LEN_TLV);
	memcpy(c_tmp,p_value_buf,4);
	memset(c_dest,0,MAX_DATA_LEN_TLV);
	ReverseBeginNchar(c_tmp,4,c_dest);
	memcpy((unsigned char*)&n_secs,c_dest,4);
	n_secs += 8*60*60;//modified by ljm on 20120727 UTC时间格式转换

	//后三个字节表示相对1970-01-01的秒的小数部分
	memset(c_tmp,0,MAX_DATA_LEN_TLV);
	memcpy(c_tmp,p_value_buf+4,3);
	memset(c_dest,0,MAX_DATA_LEN_TLV);
	ReverseBeginNchar(c_tmp,3,c_dest);
	memcpy((unsigned char*)&n_usecs,c_dest,3);

	memcpy((unsigned char*)&n_qflags,p_value_buf+4+3,1);
	//最后一个字节表示时间品质

	UtcValsToString(p_utctime,n_secs,n_usecs,n_qflags);

	return nRet;
}

int CPacketConvert::Parse2Utctime(char *p_buf, char *p_utctime)
{
	TLV_STRUCT_EX tlv;
	int n_offset = 0;
	if (NULL==p_buf || NULL==p_utctime)
	{
		return 0;
	}

	memset(&tlv, 0, sizeof(tlv));
	ParseASN1_TLV_ex(p_buf, &tlv);
	n_offset = tlv.nlen_T + tlv.nlen_L + tlv.nlen_V;

	ValueBuf2Utctime(tlv.p_V,p_utctime);

	return n_offset;
}

int CPacketConvert::Parse2Bitstring(char *p_buf, char *c_data)
{
	TLV_STRUCT_EX tlv;
	int n_offset = 0;

	if (NULL==p_buf || NULL==c_data)
	{
		return 0;
	}

	memset(&tlv, 0, sizeof(tlv));
	ParseASN1_TLV_ex(p_buf,&tlv);
	n_offset = tlv.nlen_T + tlv.nlen_L + tlv.nlen_V;

//modified on 20121101 许昌联调	ValueBuf2Bitstring(tlv.p_V, 2, c_data);	
	ValueBuf2Bitstring(tlv.p_V, tlv.nlen_V-1, c_data);	

	return n_offset;
}

int CPacketConvert::Parse2MMSstring(char *p_buf, char *c_data)
{
	TLV_STRUCT_EX tlv;
	char* pstr = NULL;
	int n_offset = 0;
	if (NULL==p_buf || NULL==c_data)
	{
		return 0;
	}

	memset(&tlv, 0, sizeof(tlv));
	ParseASN1_TLV_ex(p_buf,&tlv);
	n_offset = tlv.nlen_T + tlv.nlen_L + tlv.nlen_V;

	return n_offset;
}

int CPacketConvert::ParseMMSData(char *p_buf, MMS_DATA_STRUCT *p_data_struct)
{
	bool b_data = false;
	int n_data = 0;
    unsigned short u_data = 0;
	float f_data=0;
	double d_data=0;
	int n_offset = 0;
	if (NULL==p_buf || NULL==p_data_struct)
	{
		return 0;
	}
	TLV_STRUCT_EX tlv;

	memset(&tlv,0,sizeof(tlv));
	ParseASN1_TLV_ex(p_buf,&tlv);
	n_offset = tlv.nlen_T + tlv.nlen_L + tlv.nlen_V;

	switch ( (unsigned char)(tlv.p_T[0]) )
	{
	case 0xa1://数组
		p_data_struct->n_data_type = n_mdt_array;
		break;

	case 0xa2://结构
		p_data_struct->n_data_type = n_mdt_structure;
		ParseMMSStructData(p_buf,p_data_struct);
		break;

	case 0x83://布尔类型
		p_data_struct->n_data_type = n_mdt_boolean;
		memcpy((char*)&b_data, tlv.p_V, 1);
		if (b_data)
			strcpy(p_data_struct->c_data,"true");
		else
			strcpy(p_data_struct->c_data,"false");
		break;

	case 0x84://bit-string类型
		p_data_struct->n_data_type = n_mdt_bit_string;
//modified on 20121101 许昌联调			ValueBuf2Bitstring(tlv.p_V, 2, p_data_struct->c_data);
		ValueBuf2Bitstring(tlv.p_V, tlv.nlen_V-1, p_data_struct->c_data);
		break;

	case 0x85://integer类型
		p_data_struct->n_data_type = n_mdt_integer;
		//sInt16ToAscii(*(short*)tlv.p_V, p_data_struct->c_data);
		tlv2int(&tlv,true,p_data_struct->c_data);
		break;

	case 0x86://unsigned
		p_data_struct->n_data_type = n_mdt_unsigned;
		//uInt16ToAscii(*(short*)tlv.p_V, p_data_struct->c_data);
		tlv2int(&tlv,false,p_data_struct->c_data);
		break;

	case 0x87://float-point
		{
		p_data_struct->n_data_type = n_mdt_flating_poing;
		int nEndTest=1;
		bool bLEndian=1==*((char *)&nEndTest);
		if (0x08 == tlv.p_V[0])//单精度浮点数,双精度0x0B
		{
			memcpy((char*)&f_data, tlv.p_V+1, 4);
			//sprintf(p_data_struct->c_data,"%f",f_data);
			if (bLEndian)
			{
				char * tc=(char*)&f_data;
				tc[0]^=tc[3]^=tc[0]^=tc[3];
				tc[1]^=tc[2]^=tc[1]^=tc[2];
			}
			sprintf(p_data_struct->c_data,"%f",f_data);
		}
		else
		{
			memcpy((char*)&d_data,tlv.p_V+1, 8);
			if (bLEndian)
			{
				char * tc=(char*)&d_data;
				tc[0]^=tc[7]^=tc[0]^=tc[7];
				tc[1]^=tc[6]^=tc[1]^=tc[6];
				tc[2]^=tc[5]^=tc[2]^=tc[5];
				tc[3]^=tc[4]^=tc[3]^=tc[4];
			}
			sprintf(p_data_struct->c_data,"%lf",d_data);
		}

		}
		break;

	case 0x88://reserved
		p_data_struct->n_data_type = n_mdt_reserved;
		break;

	case 0x89://octet-string
		p_data_struct->n_data_type = n_mdt_octet_string;
		break;

	case 0x8a://visible-string
		p_data_struct->n_data_type = n_mdt_visible_string;
		break;

	case 0x8b://generalized-time
		p_data_struct->n_data_type = n_mdt_generalized_time;
		break;

	case 0x8c://binary-time
		p_data_struct->n_data_type = n_mdt_binary_time;
		break;

	case 0x8d://bcd
		p_data_struct->n_data_type = n_mdt_bcd;
		break;

	case 0x8e://booleanArray
		p_data_struct->n_data_type = n_mdt_booleanArray;
		break;

	case 0x8f://objid
		p_data_struct->n_data_type = n_mdt_obj_id;
		break;

	case 0x90://mMSstring
		p_data_struct->n_data_type = n_mdt_mms_string;
		break;

	case 0x91://utc-time
		p_data_struct->n_data_type = n_mdt_utc_time;
		ValueBuf2Utctime(tlv.p_V, p_data_struct->c_data);
		break;

	default:
		p_data_struct->n_data_type = n_mdt_init;
		break;
	}

	return n_offset;
}
int CPacketConvert::tlv2int(TLV_STRUCT_EX *p_tlv,bool signedint,char *dst)
{
	unsigned int val=p_tlv->p_V[0];
	char dformat[]="%u";
	for (int i=1;i<p_tlv->nlen_V;i++)
	{
		val<<=8;
		val+=p_tlv->p_V[i];
	}
	if (signedint)
	{
		dformat[1]='d';
	}
	sprintf(dst,dformat,val);
	return 0;
	
}
char* CPacketConvert::lToStr(long int val,char *dst, int radix)
{
	char buffer[65];
	char *p;
	long int new_val;
	
	if (radix < 0)                                /* -10 */
	{
		if (val < 0)
		{
			*dst++ = '-';
			val = -val;
		}
	}
	
	p = &buffer[sizeof(buffer)-1];
	*p = '\0';
	new_val= (long) ((unsigned long int) val / 10);
	*--p = '0'+ (char) ((unsigned long int) val - (unsigned long) new_val * 10);
	val = new_val;
	
	while (val != 0)
	{
		new_val=val/10;
		*--p = '0' + (char) (val-new_val*10);
		val= new_val;
	}
	while ((*dst++ = *p++) != 0) ;
	return dst-1;
}

int CPacketConvert::packetconvert_get_appid(const char *p_Buf)
{
	int nRet = RES_FAIL;
	int nStart = 28;
	int nStep = 0;
	int nTmp = 0;
	unsigned int nAppid=0;
	
	if (0x81==(unsigned char)p_Buf[nStart] && 0x00==(unsigned char)p_Buf[nStart+1])
	{
		nStep =4;
	}
	else
	{
		nStep = 0;
	}
	
	memcpy(&nAppid, p_Buf+nStart+nStep+2, 1);//APPID的高字节
	memcpy(&nTmp, p_Buf+nStart+nStep+3, 1);//APPID的低字节
	nAppid = nAppid*256 + nTmp;


/*	unsigned int nAppid=0;

	ParseAppid((char *)p_Buf, nAppid);*/

	return nAppid;
	
}

int CPacketConvert::packetconvert_get_utctime(char *p_packet_buf, char *c_utctime)
{
	int n_secs = 0;
	int n_usecs = 0;
	int nLen = 0;
	char c_epoc[256];
	
	if (NULL==p_packet_buf || NULL==c_utctime)
	{
		return 0;
	}
	memset(c_epoc,0,sizeof(c_epoc));
	
	memcpy((char*)&n_secs,p_packet_buf,4);
	memcpy((char*)&n_usecs,p_packet_buf+4,4);
//	sprintf(c_epoc, "%d.%06d",n_secs,n_usecs);
	sprintf(c_epoc, "%u.%06u",n_secs,n_usecs);
	
	strcpy(c_utctime, c_epoc);
	
	nLen = 8;
	return nLen;
}

//int CPacketConvert::packetconvert_get_date_time(char *p_packet_buf, char *c_data_time)
//{
//
// 	int nLen = 0;
// 	char c_epoc[256];
//
// 	memset(c_epoc,0,sizeof(c_epoc));
//
//	packetconvert_get_utctime(p_packet_buf, c_epoc);
//	EpocChar2utc(c_epoc, c_data_time);
//	
//	nLen = 8;
//	return nLen;
//}

int CPacketConvert::EpocChar2utc(char *p_epoc, char *p_utc)
{
	int nRet = RES_SUCCESS;
    unsigned int n_secs=0;
    unsigned int n_fraction=0;
	
	//判断参数是否合法
	if (NULL==p_utc || NULL==p_epoc)
	{
		return RES_FAIL;
	}
	//将整数和小数部分分别存入n_secs和n_fraction
	sscanf(p_epoc, "%d.%d", &n_secs, &n_fraction);
	
	//将加上当前时区后的整数秒及小数部分，转换为UTC格式的时间字符
	nRet = UtcValsToString_ex(p_utc,n_secs+60*60*8,n_fraction);//测试
	
	return nRet;
}

int CPacketConvert::UtcValsToString_ex(char *dest, unsigned int secs, unsigned int fraction)
{
        char theDate[256];
        char theFraction[25];
    double dFraction=0;
	char *pFract;
	time_t t = secs;
	struct tm *pTm;
	
	/* get the date portion */
	pTm = gmtime (&t);
	if (!pTm)
	{
		m_LogFile.FormatAdd(CLogFile::error, "UtcValsToString:  转换失败 - 无效的秒%d.", secs);
		return RES_FAIL;
	}
	
	strftime (theDate, 256, "%Y-%m-%d %H:%M:%S", gmtime (&t));
	
	/* get the fraction portion */
    dFraction = (double) fraction/pow(10.0,6.0);
	sprintf (theFraction, " %#0.06f", dFraction);
	pFract = strchr (theFraction, '.');
	if (!pFract)
	{
		//		SLOGALWAYS1 ("UtcToString - unable to convert fraction %d", fraction);
		m_LogFile.FormatAdd( CLogFile::error, "不能转换小数部分%d", fraction);
		return RES_FAIL;
	}
	
	/* put em all together  */
	sprintf (dest, "%s%s", theDate, pFract);
	
	return RES_SUCCESS;
}

ETHER_TYPE CPacketConvert::packetconvert_get_ether_type(char *p_packet_buf)
{
	ETHER_TYPE n_ethertype = IEC61850_ETHER_TYPE_UNKOWN;

	if (NULL==p_packet_buf)
	{
		return IEC61850_ETHER_TYPE_UNKOWN;
	}
	if (memcmp(p_packet_buf+8,p_packet_buf+12,4))//caplen != len
	{
		int nCapLen,nLen;
		memcpy(&nCapLen,p_packet_buf+8,4);
		memcpy(&nLen,p_packet_buf+12,4);
		if (nCapLen-nLen>7)
		{
			if (p_packet_buf[nCapLen+16-8] & 0xE0)
			{
				return ETHER_TYPE_DROP;
			}
		}
	}
	int nstart = 16;
	if (m_nLinkType!=101)
	{
		nstart += 12;
	if (0x81==(unsigned char)p_packet_buf[nstart] && 0x00==(unsigned char)p_packet_buf[nstart+1])
	{
		nstart = nstart+4;
	}

	if (0x88 == (unsigned char)p_packet_buf[nstart])
	{
		if (0xba == (unsigned char)p_packet_buf[nstart+1])
		{
			n_ethertype = IEC61850_ETHER_TYPE_SMV;
		}
		else if (0xb8 == (unsigned char)p_packet_buf[nstart+1])
		{
			n_ethertype = IEC61850_ETHER_TYPE_GOOSE;
		}
		else if (0xf7 == (unsigned char)p_packet_buf[nstart+1])
		{
			n_ethertype = IEC61850_ETHER_TYPE_PTP_1588;
		}
	}
	else if (0x08 == (unsigned char)p_packet_buf[nstart])
	{
		if (0x06 == (unsigned char)p_packet_buf[nstart+1])
		{
			n_ethertype = ETHER_TYPE_ARP;
		}
		else if(0x00 == (unsigned char)p_packet_buf[nstart+1])//解析到IP层以及TCP层或UDP  add by yinzhehong 20130316
		{
			n_ethertype = ETHER_TYPE_IP;
			//判断是否为TCP，还是UDP
			if(0x06 == (unsigned char)p_packet_buf[nstart+1+10])//TCP报文
			{
				n_ethertype = ETHER_TYPE_TCP;
			}
			else if(0x11 ==(unsigned char)p_packet_buf[nstart+1+10])//UDP报文
			{
				n_ethertype = ETHER_TYPE_UDP;
			}
		}
	}
    }
	else
	{
		n_ethertype = ETHER_TYPE_IP;
		//判断是否为TCP，还是UDP
		if(0x06 == (unsigned char)p_packet_buf[nstart+1+8])//TCP报文
		{
			n_ethertype = ETHER_TYPE_TCP;
		}
		else if(0x11 ==(unsigned char)p_packet_buf[nstart+1+8])//UDP报文
		{
			n_ethertype = ETHER_TYPE_UDP;
		}
	}
/*	if (0x81==(unsigned char)p_packet_buf[nstart] && 0x00==(unsigned char)p_packet_buf[nstart+1])
	{
		if (0x88 == (unsigned char)p_packet_buf[nstart+4])
		{
			if (0xba == (unsigned char)p_packet_buf[nstart+5])
			{
				n_ethertype = IEC61850_ETHER_TYPE_SMV;
			}
			else if (0xb8 == (unsigned char)p_packet_buf[nstart+5])
			{
				n_ethertype = IEC61850_ETHER_TYPE_GOOSE;
			}
			else if (0xf7 == (unsigned char)p_packet_buf[nstart+5])
			{
				n_ethertype = IEC61850_ETHER_TYPE_PTP_1588;
			}
		}
		else if (0x08 == (unsigned char)p_packet_buf[nstart+4])
		{
			if (0x06 == (unsigned char)p_packet_buf[nstart+5])
			{
				n_ethertype = ETHER_TYPE_ARP;
			}
		}
	}
	else
	{
		if (0x88 == (unsigned char)p_packet_buf[nstart])
		{
			if (0xba == (unsigned char)p_packet_buf[nstart+1])
			{
				n_ethertype = IEC61850_ETHER_TYPE_SMV;
			}
			else if (0xb8 == (unsigned char)p_packet_buf[nstart+1])
			{
				n_ethertype = IEC61850_ETHER_TYPE_GOOSE;
			}
			else if (0xf7 == (unsigned char)p_packet_buf[nstart+1])
			{
				n_ethertype = IEC61850_ETHER_TYPE_PTP_1588;
			}
		}
		else if (0x08 == (unsigned char)p_packet_buf[nstart])
		{
			if (0x06 == (unsigned char)p_packet_buf[nstart+1])
			{
				n_ethertype = ETHER_TYPE_ARP;
			}
		}
	}*/
	
	return n_ethertype;
}

int CPacketConvert::packetconvert_release_goose_mms_data(GOOSE_INFO_STRUCT* pGoose, int n_num)
{
	int nRet = RES_SUCCESS;
	int i;
	
	if (NULL==pGoose)
	{
		return RES_FAIL;
	}
	
	for (i=0; i<n_num; i++)
	{
		packetconvert_release_mms_data(pGoose[i].p_data_struct, pGoose[i].n_numDataStructs);

		//测试
//		m_LogFile.FormatAdd(CLogFile::error, "appid:0X%04X=====================i=%d", pGoose[i].n_app_id, i);
// 		if (pGoose[i].n_app_id == 0XFFFFFFFF)
// 		{
// 			m_LogFile.FormatAdd(CLogFile::error, "i=%d\n", i);
// 		}
	}
	
	return nRet;
}

int CPacketConvert::init_mms_data_ex(MMS_DATA_STRUCT* p_mms_data)
{
	int nRet = RES_SUCCESS;

	if (NULL==p_mms_data)
	{
		return RES_FAIL;
	}

	memset(p_mms_data->c_data, 0, sizeof(p_mms_data->c_data) );
	p_mms_data->n_struct_num = 0;
	p_mms_data->p_struct = NULL;
	p_mms_data->result = 0;

	return nRet;
}

int CPacketConvert::release_mms_data_ex(MMS_DATA_STRUCT &mms_data)
{
	int nRet = RES_SUCCESS;
	int i;

	if (NULL==mms_data.p_struct || mms_data.n_struct_num<=0)
	{
		return RES_SUCCESS;
	}

	for (i=0; i<mms_data.n_struct_num; i++)
	{
		release_mms_data_ex(mms_data.p_struct[i]);
	}

	delete[] mms_data.p_struct;
	mms_data.p_struct = NULL;

	return nRet;
}

int CPacketConvert::packetconvert_release_mms_data(MMS_DATA_STRUCT* p_mms_data, int n_num)
{
	int nRet = RES_SUCCESS;
	int i=0;
	
	if (NULL==p_mms_data)
	{
		return RES_SUCCESS;
	}
	
	while (i < n_num)
	{
		if (p_mms_data[i].p_struct && p_mms_data[i].n_struct_num>0)
		{
			packetconvert_release_mms_data(p_mms_data[i].p_struct, p_mms_data[i].n_struct_num);
		}

		i++;
	}
	
	delete[] p_mms_data;
	p_mms_data = NULL;
	
	return nRet;
}

int CPacketConvert::packetconvert_release_smv_asdu(SMV_INFO_STRUCT* pSmv, int n_num)
{
	int nRet = RES_SUCCESS;
	int i=0;

	if (NULL==pSmv)
	{
		return RES_SUCCESS;
	}

	for (i=0; i<n_num; i++)
	{
		packetconvert_release_asdu_info( pSmv[i].p_asdu_info_struct, pSmv[i].n_asdu_num );
	}

	return nRet;

}

int CPacketConvert::packetconvert_release_asdu_info(ASDU_INFO_STRUCT* p_asdu_info, int n_num)
{
	int nRet = RES_SUCCESS;
	int i;
	if (NULL==p_asdu_info)
	{
		return RES_FAIL;
	}
	
	for (i=0; i<n_num; i++)
	{
		if (NULL!=p_asdu_info[i].p_smv_data_struct)
		{
			delete[] p_asdu_info[i].p_smv_data_struct;
			p_asdu_info[i].p_smv_data_struct = NULL;
		}
	}
	
	delete[] p_asdu_info;
	p_asdu_info = NULL;
	
	return nRet;
}

//int CPacketConvert::packetconvert_get_dstip(char *p_packet_buf, char *pIP)
//{
//	int nRet = RES_FAIL;
//
//	if (NULL==p_packet_buf || NULL==pIP)
//	{
//		return RES_FAIL;
//	}
//	
//	int nstart = 28;
//	int nPos;
//	
//	if (0x81==(unsigned char)p_packet_buf[nstart] && 0x00==(unsigned char)p_packet_buf[nstart+1])
//	{
//		if (0x08 == (unsigned char)p_packet_buf[nstart+4])
//		{
//			if (0x00 == (unsigned char)p_packet_buf[nstart+5])
//			{
//				nRet = RES_SUCCESS;
//				nPos = nstart+6+16;
//			}
//		}
//	}
//	else
//	{
//		if (0x08 == (unsigned char)p_packet_buf[nstart])
//		{
//			if (0x00 == (unsigned char)p_packet_buf[nstart+1])
//			{
//				nRet = RES_SUCCESS;
//				nPos = nstart+2+16;
//			}
//		}
//	}
//
//	if (RES_SUCCESS==nRet)
//	{
//		sprintf(pIP, "%d.%d.%d.%d", \
//			(unsigned char)p_packet_buf[nPos],\
//			(unsigned char)p_packet_buf[nPos+1],\
//			(unsigned char)p_packet_buf[nPos+2],\
//			(unsigned char)p_packet_buf[nPos+3]);
//	}
//
//	return nRet;
//
//}

int CPacketConvert::packetconvert_get_srctip(char *p_packet_buf, char *pIP)
{
	int nRet = RES_FAIL;
	
	if (NULL==p_packet_buf || NULL==pIP)
	{
		return RES_FAIL;
	}
	
	int nstart = 28;
	int nPos;
	
	if (0x81==(unsigned char)p_packet_buf[nstart] && 0x00==(unsigned char)p_packet_buf[nstart+1])
	{
		if (0x08 == (unsigned char)p_packet_buf[nstart+4])
		{
			if (0x00 == (unsigned char)p_packet_buf[nstart+5])
			{
				nRet = RES_SUCCESS;
				nPos = nstart+6+12;
			}
		}
	}
	else
	{
		if (0x08 == (unsigned char)p_packet_buf[nstart])
		{
			if (0x00 == (unsigned char)p_packet_buf[nstart+1])
			{
				nRet = RES_SUCCESS;
				nPos = nstart+2+12;
			}
		}
	}
	
	if (RES_SUCCESS==nRet)
	{
//		sprintf(pIP, "%d.%d.%d.%d", (unsigned char)p_packet_buf[nPos++],(unsigned char)p_packet_buf[nPos++],(unsigned char)p_packet_buf[nPos++],(unsigned char)p_packet_buf[nPos++]);
		sprintf(pIP, "%d.%d.%d.%d", \
			(unsigned char)p_packet_buf[nPos],\
			(unsigned char)p_packet_buf[nPos+1],\
			(unsigned char)p_packet_buf[nPos+2],\
			(unsigned char)p_packet_buf[nPos+3]);
	}
	
	return nRet;
	
}

int CPacketConvert::packetconvert_get_dest_mac(char *p_packet_buf, char *p_mac)
{
	int nRet = RES_SUCCESS;
	int nstart = 16;

	if (0==ParseMac(p_packet_buf+nstart, p_mac))
		return RES_FAIL;

	return nRet;
}

int CPacketConvert::packetconvert_get_src_mac(char *p_packet_buf, char *p_mac)
{
	int nRet = RES_SUCCESS;
	int nstart = 22;
	
	if (0==ParseMac(p_packet_buf+nstart, p_mac))
		return RES_FAIL;
	
	return nRet;
}

u_short CPacketConvert::reverse_2byte(u_short u_value)
{
	u_short u_val_dest = 0; 
	u_short u_Hbyte = 0;
	u_short u_Lbyte = 0;

	u_Lbyte = u_value & 0XFF00;
	u_val_dest = u_Lbyte/256;

	u_Hbyte = u_value & 0X00FF;
	u_val_dest += 256 * u_Hbyte;

	return u_val_dest;
}

UINT CPacketConvert::reverse_4byte(UINT u_value)
{
	UINT u_val_dest = 0;
	UINT u_tmp =0;

	u_val_dest = u_value << 24;

	u_tmp = u_value & 0X0000FF00;
	u_tmp = u_tmp * 256;
	u_val_dest += u_tmp;

	u_tmp = u_value & 0X00FF0000;
	u_tmp = u_tmp / 256;
	u_val_dest += u_tmp;

 	u_tmp = u_value & 0XFF000000;
	u_tmp = u_tmp >> 24;
 	u_val_dest += u_tmp;

	return u_val_dest;
}

//__int64 CPacketConvert::reverse_6byte(UINT nuint16_val, u_short nshort_val)
//{
//	__int64 nint64_value_dest;
//	__int64 nint64_tmp=0;
//	
// 	nshort_val = reverse_2byte(nshort_val);
//	nint64_value_dest = nshort_val;
//
//	nuint16_val = reverse_4byte(nuint16_val);
//	//nuint16_val = nuint16_val * 65536;//溢出
//	nint64_value_dest += (__int64)nuint16_val*65536;
//
//	return nint64_value_dest;
//
//}

//int CPacketConvert::get_correction_val(CORRECTION_FIELD correctionField, double &d_correction)
//{
//	int nRet = RES_SUCCESS;
//	__int64 time_ns=0;		//纳秒
//	u_short time_subns=0;	//纳秒的小数
//
//	time_ns = reverse_6byte(correctionField.n_Ns_6byte.u_LSB_4byte, correctionField.n_Ns_6byte.u_MSB_2byte);
//	time_subns = reverse_2byte(correctionField.n_SubNs_2byte);
//	d_correction = (double)time_subns / 65536.0;
//
//	d_correction += (double)time_ns;
//
//	return nRet;
//}

//int CPacketConvert::get_timestamp_s_ns(PTP_TIME_STAMP timestamp, __int64 &time_s, UINT &time_ns)
//{
//	int nRet = RES_SUCCESS;
////	__int64 time_s=0;		//秒
////	UINT time_ns=0;			//纳秒
//
//	time_s = reverse_6byte(timestamp.u_seconds.u_LSB_4byte, timestamp.u_seconds.u_MSB_2byte);
//
//	time_ns = reverse_4byte(timestamp.u_nanoseconds);
//
//	return nRet;
//}

unsigned short CPacketConvert::buf2ushort(char *p_packet_buf, int nbyte_num)
{
	unsigned short nvalue = 0;

	nvalue = 256*p_packet_buf[0] + p_packet_buf[1];
	
	return nvalue;
}

int CPacketConvert::ValueBuf2Bitstring(char *p_value_buf, int n_bytes, char *p_bitstring)
{
	int nRet = RES_SUCCESS;
	unsigned int n_fill = 0;
	char cTemp[MAX_PACKET_LEN];
	int i=0,j=0;
	unsigned char uc_tmp;

	if (NULL==p_value_buf || NULL==p_bitstring)
	{
		return RES_FAIL;
	}
	
	memcpy((unsigned char*)&n_fill,p_value_buf,1);//第一个字节表示后两个字节往后自动填充的位数
	
	//防异常处理
	if (8 <= n_fill)
	{
		return RES_FAIL;
	}
	
	//转换为2进制字符串
	for (i=0; i<n_bytes; i++)
	{
		uc_tmp=0;
		memcpy((unsigned char*)&uc_tmp,p_value_buf+i+1,1);
		j=0;
		while(j < 8) 
		{ 
			sprintf(&p_bitstring[i+j],"%d",uc_tmp & 0x80);
			uc_tmp <<= 1; 
			j++;
		}
	}
	
	//前面补齐0
	memset(cTemp,0,MAX_PACKET_LEN);
	while (strlen(p_bitstring) < 8*n_bytes)//2字节16bit
	{
		strcpy(cTemp, "0");
		strcat(cTemp, p_bitstring);
		strcpy(p_bitstring, cTemp);
	}
	
	//删除后面n_fill个bit位
	memset(cTemp,0,MAX_PACKET_LEN);
	strncpy(cTemp,p_bitstring,8*n_bytes-n_fill);
	strcpy(p_bitstring,cTemp);
	
	return nRet;
}

int CPacketConvert::packetconvert_2smv_ex2(PACKET_STRUCT* p_packet,int n_num, SMV_INFO_STRUCT *p_msg)
{
	int nRet = RES_FAIL;
	int i, j, k;
	char *p_buf_tmp;
	char *p_data_buf;
//	int npacket_len = 0;//每帧报文的长度（包括报文头:16字节）
	unsigned int ntag;
	int nStep;
//	unsigned int n_secs;
//	unsigned int n_usecs;
	int n_dataset_len;
	int n_data_num;
	TLV_STRUCT_EX tlv;
	unsigned int ntmp_v;
	//////////////
	int ntmp_step;
	int ntmp_len=0;
	bool btag_err = false;
	//////////////////
	
	if (NULL==p_packet || NULL==p_msg)
	{
		return RES_FAIL;
	}
	
	for (i=0; i<n_num; i++)
	{
		p_msg[i].u_result =0;
		p_buf_tmp = (char*)p_packet[i].pPacket;

		//增加报文长度异常处理
		ntmp_step = 0;
		
		memcpy(p_msg[i].c_avtm_epocsec, p_buf_tmp, 8);
		nStep = 16;//跳过arvtime, InclLen和OrigLen
		ntmp_step += nStep;
		
		//解析目的MAC地址
		p_buf_tmp = p_buf_tmp + nStep;
		memcpy(p_msg[i].c_dest_mac, p_buf_tmp, 6);
		nStep = 6;
		ntmp_step +=  nStep;
		
		//解析源MAC地址
		p_buf_tmp = p_buf_tmp + nStep;
		memcpy(p_msg[i].c_src_mac, p_buf_tmp, 6);
		nStep = 6;
		ntmp_step +=  nStep;	

		p_buf_tmp = p_buf_tmp + nStep;	

		if (p_packet[i].nLen < 76)//magic
		{
			p_msg[i].u_result |= DISSECT_SMV_PKTLEN_ERROR;
			continue;
		}
		if (0x81==(unsigned char)p_buf_tmp[0] && 0x00==(unsigned char)p_buf_tmp[1])
			nStep = 6;//跳过Priority tagged和ethertype
		else
			nStep = 2;
		ntmp_step +=  nStep;
		
		//解析APPID
		p_buf_tmp = p_buf_tmp + nStep;
		p_msg[i].n_app_id = 256*((unsigned char)p_buf_tmp[0]) + (unsigned char)p_buf_tmp[1];
		nStep = 2;
		
		//解析msg_len
		p_buf_tmp = p_buf_tmp + nStep;
		p_msg[i].n_msg_len = 256*((unsigned char)p_buf_tmp[0]) + (unsigned char)p_buf_tmp[1];
		
//////////////////////////////////////////////////////////////////////////////////////////////		
		//解析ASDU
		p_buf_tmp = p_buf_tmp + 6;//跳过msg_len, reserve1和reserve2

		//增加判断msg_len异常判断
		int nDiff=p_msg[i].n_msg_len - (p_packet[i].nLen - ntmp_step);
		if (nDiff!=0)
		{
			p_msg[i].u_result |= DISSECT_SMV_MSGLEN_ERROR;
			continue;
		}

		//PDU首结构，tag为60
		memset(&tlv, 0, sizeof(TLV_STRUCT_EX));
		ParseASN1_TLV_ex(p_buf_tmp, &tlv);
		nStep = tlv.nlen_T + tlv.nlen_L;

		//解析ASDU个数
		p_buf_tmp = p_buf_tmp + nStep;
		memset(&tlv, 0, sizeof(TLV_STRUCT_EX));
		ParseASN1_TLV_ex(p_buf_tmp, &tlv);
		if ( 0x80 == (unsigned char)(tlv.p_T[0]) )//增加标识，是否已解析出nofasdu
		{
			p_msg[i].u_result |= DISSECT_SMV_NOFASDU_OK;
		}
		else
		{
			continue;
		}
		Parse_uInt_byTLV(&tlv, ntmp_v);
		if (0 == ntmp_v)
		{
			p_msg[i].u_result |= DISSECT_SMV_ASDU_NUM_ZERO;
		}
		p_msg[i].n_nofasdu_actual = ntmp_v;
		//unsigned int nMinAsdu=p_msg[i].n_asdu_num;
		if (ntmp_v != p_msg[i].n_asdu_num)
		{
 			continue;//直接跳到解析下一帧
			//if(ntmp_v<nMinAsdu)nMinAsdu=ntmp_v;
			
		}
		
		nStep = tlv.nlen_T + tlv.nlen_L + tlv.nlen_V; //跳过ASDU个数

		//跳过sequence of
		p_buf_tmp = p_buf_tmp + nStep; 
		memset(&tlv, 0, sizeof(TLV_STRUCT_EX));
		ParseASN1_TLV_ex(p_buf_tmp, &tlv);
		nStep = tlv.nlen_T + tlv.nlen_L;

		//解析ASDU
		for (j=0; j<p_msg[i].n_asdu_num; j++)//
		{
			//ASDU头，30开头
			p_buf_tmp = p_buf_tmp + nStep; 
			memset(&tlv, 0, sizeof(TLV_STRUCT_EX));
			ParseASN1_TLV_ex(p_buf_tmp, &tlv);
			nStep = tlv.nlen_T + tlv.nlen_L;

			ntmp_step = 0;
			ntmp_len = tlv.nlen_V;
			while (ntmp_step < ntmp_len)
			{
				p_buf_tmp = p_buf_tmp + nStep; 
				memset(&tlv, 0, sizeof(TLV_STRUCT_EX));
				ParseASN1_TLV_ex(p_buf_tmp, &tlv); 
				////////////////////////////////////////////////////////
				ntmp_step += tlv.nlen_T + tlv.nlen_L + tlv.nlen_V;//每项的步长
				if (ntmp_step <= 0)
				{
					btag_err = true;
					break;//异常处理
				}
				///////////////////////////////////////////////////////
				ntag = 0;
				memcpy(&ntag, (unsigned char*)p_buf_tmp, 1);
				switch ( ntag )
				{
				case 0X80:			//sv_id
					memset(p_msg[i].p_asdu_info_struct[j].c_svID, 0, MAX_DATA_LEN_VISIBLE_STRING);
					memcpy(p_msg[i].p_asdu_info_struct[j].c_svID, tlv.p_V, tlv.nlen_V);
					nStep = tlv.nlen_T + tlv.nlen_L + tlv.nlen_V;
					p_msg[i].u_result |= DISSECT_SMV_SVID_OK;
					break;
				case 0X81:			//dataSet
					memset(p_msg[i].p_asdu_info_struct[j].c_dataset, 0, MAX_DATA_LEN_OBJ_REF);
					memcpy(p_msg[i].p_asdu_info_struct[j].c_dataset, tlv.p_V, tlv.nlen_V);
					nStep = tlv.nlen_T + tlv.nlen_L + tlv.nlen_V;
					p_msg[i].u_result |= DISSECT_SMV_DATASET_OK;
					break;
				case  0X82:			//smpCnt	规范定为Uint16
					Parse_uInt_byTLV(&tlv, ntmp_v);
					p_msg[i].p_asdu_info_struct[j].n_smpCnt = ntmp_v;
					nStep = tlv.nlen_T + tlv.nlen_L + tlv.nlen_V;
					p_msg[i].u_result |= DISSECT_SMV_SMPCNT_OK;
					break;
				case 0x83:			//confRev		规范定为Uint32
					Parse_uInt_byTLV(&tlv, ntmp_v);
					p_msg[i].p_asdu_info_struct[j].n_confRev = ntmp_v;
					nStep = tlv.nlen_T + tlv.nlen_L + tlv.nlen_V;
					p_msg[i].u_result |= DISSECT_SMV_CONFREV_OK;
					break;
				case 0x84:			//refrTm
					memset(p_msg[i].p_asdu_info_struct[j].c_refrTm, 0, MAX_DATA_LEN_ENTRY_TIME);
					memcpy(p_msg[i].p_asdu_info_struct[j].c_refrTm, tlv.p_V, tlv.nlen_V);
					nStep = tlv.nlen_T + tlv.nlen_L + tlv.nlen_V;
					p_msg[i].u_result |= DISSECT_SMV_REFRTM_OK;
					break;
				case 0x85:			//smpSynch
					Parse_uInt_byTLV(&tlv, ntmp_v);
					p_msg[i].p_asdu_info_struct[j].n_smpSynch = (int)ntmp_v;
					p_msg[i].p_asdu_info_struct[j].b_smpSynch = 1==(int)ntmp_v;
					nStep = tlv.nlen_T + tlv.nlen_L + tlv.nlen_V;
					p_msg[i].u_result |= DISSECT_SMV_SMPSYNCH_OK;
					if (ntmp_v>1)// 只有0、1是有效值
					{
						p_msg[i].u_result |=DISSECT_SMV_INVALID_FIELD_VAL ;
					}
					break;
				case 0x86:			//smpRate	规范定为Uint16
					 Parse_uInt_byTLV(&tlv, ntmp_v);
					 p_msg[i].p_asdu_info_struct[j].n_smpRate = ntmp_v;
					 nStep = tlv.nlen_T + tlv.nlen_L + tlv.nlen_V;
					 p_msg[i].u_result |= DISSECT_SMV_SMPRATE_OK;
					break;

				case 0X87:			//sequence of Data
					//ntmp_v = 0;
					ntmp_v = *((unsigned char*)tlv.p_L);//memcpy((char *)&ntmp_v, tlv.p_L, 1);
					if(ntmp_v & 0x80)	//长模式
					{
						//去高位
						if ((ntmp_v &= 0x7F) > 0)	// 定长模式的长形式
						{
							n_dataset_len = 0;
							if (ntmp_v == 1)
							{
								n_dataset_len = ((unsigned char*)tlv.p_L + 1)[0];//memcpy((char *)&n_dataset_len, tlv.p_L + 1, 1);
							}
							else if (ntmp_v == 2)
							{
//								n_dataset_len = (unsigned char)(tlv.p_L + 1)[1] + ( ((unsigned char)(tlv.p_T + 1)[0]) << 8 );
								n_dataset_len = (unsigned char)(tlv.p_L + 1)[1] + ( ((unsigned char)(tlv.p_L + 1)[0]) << 8 );//modified on 2013/03/30 ljm
							}
							//通道数目前最多50，即长度最长400字节，不会多于2字节
						}
					}
					else
					{
						n_dataset_len = ((unsigned char*)tlv.p_L)[0];//memcpy((char *)&n_dataset_len, tlv.p_L + 1, 1);
					}
					
					n_data_num = n_dataset_len/8;
					p_msg[i].p_asdu_info_struct[j].n_danum_actual = n_data_num;
					if (p_msg[i].p_asdu_info_struct[j].n_data_num == n_data_num)//配置通道数与报文中通道数相等时，才解析通道值和品质
					{
						p_data_buf = tlv.p_V;
						for (k=0; k<n_data_num; k++)
						{
							(p_msg[i].p_asdu_info_struct[j]).p_smv_data_struct[k].n_value = Buf2Int32(p_data_buf);
							memcpy( (p_msg[i].p_asdu_info_struct[j]).p_smv_data_struct[k].c_quality, p_data_buf+4, 4);

							p_data_buf = p_data_buf + 8;
						}
					}

					nStep = tlv.nlen_T + tlv.nlen_L;
					p_msg[i].u_result |= DISSECT_SMV_SEQUENCEOFDATA_OK;
					break;

				default:
					btag_err = true;
					break;

				}//switch 循环结束

		/*		if (ntag == 0X87)	//tag到87时，跳出while循环
				{
					break;
				}*/
				if (btag_err)
					break;
			}//while 循环结束

			if (btag_err)
				break;
		}//for asdu 循环结束

		if (!btag_err)
		{
			nRet = RES_SUCCESS;
		}
//////////////////////////////////////////////////////////////////////////////////////////////

//		noffset += p_msg[i].n_msg_len;//记录每帧报文长度（包括报文头:16字节）此注释不要删，以后判PDU长度异常时有用
	}//for 多帧循环结束
	
	return nRet;
}

int CPacketConvert::packetconvert_2goose_ex(PACKET_STRUCT* p_packet,int n_num, GOOSE_INFO_STRUCT* p_msg)
{
	int nRet = RES_FAIL;
	int i=0;
	char *p_buf_tmp =NULL;
	int nStep;
	char *p_type = NULL;
	int nstart = 28;
	
	if (NULL==p_packet || NULL==p_msg)
	{
		return RES_FAIL;
	}
	
	for (i=0; i<n_num; i++)
	{
		p_buf_tmp = (char*)p_packet[i].pPacket;
		p_msg[i].u_result =0;
		p_msg[i].p_data_struct=NULL;
		p_msg[i].n_numDataStructs=0;//避免释放时候出错。
		//异常处理
		if (p_packet[i].nLen < 76)
		{
			p_msg[i].u_result |= DISSECT_GOOSE_PKTLEN_ERROR;
			continue;
		}
		
		nStep = 0;
				
		//解析报文到达时间(直接拷贝8字节，和SMV解析统一处理)
		memcpy(p_msg[i].c_avtm_epocsec, p_buf_tmp, 8);
		nStep += 16;//跳过arvtime, InclLen和OrigLen

		//解析目的MAC地址
		memcpy(p_msg[i].c_dest_mac, p_buf_tmp+nStep, 6);
		nStep += 6;
		
		//解析源MAC地址
		memcpy(p_msg[i].c_src_mac, p_buf_tmp+nStep, 6);
		nStep += 6;

		if (0x81==(unsigned char)p_buf_tmp[nstart] && 0x00==(unsigned char)p_buf_tmp[nstart+1])
			nStep += 6;//跳过Priority tagged和ethertype
		else
			nStep += 2;
		
		//解析APPID
		nStep += ParseAppid(p_buf_tmp+nStep,p_msg[i].n_app_id);
		
		//解析msg_len
		nStep += ParseMsgLen(p_buf_tmp+nStep,p_msg[i].n_msg_len);
		int nDiff=p_msg[i].n_msg_len - (p_packet[i].nLen - nStep + 4);
		if (nDiff!=0)
		{
			p_msg[i].u_result |= DISSECT_GOOSE_MSGLEN_ERROR;
			continue;
		}
		
		nStep += 4;//跳过reserver1 、reserve2

		if (RES_SUCCESS == ParseGoosePdu(p_buf_tmp+nStep,&p_msg[i], m_bParseGooseDA) )
		nRet = RES_SUCCESS;
	}
	
	return nRet;
}

int CPacketConvert::ParseGoosePdu(char *p_buf,GOOSE_INFO_STRUCT *p_goose_info,bool b_parseData)
{
	int nRet = RES_SUCCESS;

	if (NULL==p_buf || NULL==p_goose_info)
	{
		return 0;
	}
//	int nlen_pdu = 0;
	int n_offset = 0;
	TLV_STRUCT_EX tlv;
	int n_byte_tl = 0;//TLV中TL占用的字节数
	char *p_tmp = NULL;
	
	//PDU首结构 tag为61，L可能为一个字节或三个字节
//	memset(&tlv,0,sizeof(tlv));
	ParseASN1_TLV_ex(p_buf, &tlv);
	n_offset = tlv.nlen_T + tlv.nlen_L;
	if (0x61 != (unsigned char)tlv.p_T[0])
	{
		return RES_FAIL;
	}
	else
	{
		p_goose_info->u_result |= DISSECT_GOOSE_PDU_TAG_OK;
	}

//	nlen_pdu = tlv.nlen_T + tlv.nlen_L + tlv.nlen_V;
	
	p_tmp = p_buf+n_offset;
	if (0x80 == (unsigned char)p_tmp[0])
	{
		//解析gocbRef
		n_offset += Parse2char(p_tmp,p_goose_info->c_gocbRef);
		p_tmp = p_buf+n_offset;
		p_goose_info->u_result |= DISSECT_GOOSE_GOCB_OK;
	}
	if (0x81 == (unsigned char)p_tmp[0])
	{
//		memset(&tlv, 0, sizeof(TLV_STRUCT_EX));
		ParseASN1_TLV_ex(p_tmp, &tlv);
		unsigned int ntmp_da=0;
		Parse_uInt_byTLV(&tlv,ntmp_da);
		p_goose_info->n_timeAllowedtoLive = ntmp_da;
		n_offset += tlv.nlen_T + tlv.nlen_L + tlv.nlen_V;
		//解析n_timeAllowedtoLive
//modified on 		n_offset += Parse2Int(p_tmp,p_goose_info->n_timeAllowedtoLive);
		p_tmp = p_buf+n_offset;
		p_goose_info->u_result |= DISSECT_GOOSE_TAL_OK;
	}
	if (0x82 == (unsigned char)p_tmp[0])
	{
		//解析dataSet
		n_offset += Parse2char(p_tmp,p_goose_info->c_dataSet);
		p_tmp = p_buf+n_offset;
		p_goose_info->u_result |= DISSECT_GOOSE_DATASET_OK;
	}
	if (0x83 == (unsigned char)p_tmp[0])
	{
		//解析goID
		n_offset += Parse2char(p_tmp,p_goose_info->c_goID);
		p_tmp = p_buf+n_offset;
		p_goose_info->u_result |= DISSECT_GOOSE_GOID_OK;
	}
	if (0x84 == (unsigned char)p_tmp[0])
	{
		//解析t
		n_offset += Parse2Utctime(p_tmp,p_goose_info->c_t);
		p_tmp = p_buf+n_offset;
		p_goose_info->u_result |= DISSECT_GOOSE_T_OK;
	}
	if (0x85 == (unsigned char)p_tmp[0])
	{
//		memset(&tlv, 0, sizeof(TLV_STRUCT_EX));
		ParseASN1_TLV_ex(p_tmp, &tlv);
		//解析n_stNum
//modified on 2012-10-30 by ljm		n_offset += Parse2UnInt(p_tmp,p_goose_info->n_stNum);
		Parse_uInt_byTLV(&tlv,p_goose_info->n_stNum);
		n_offset += tlv.nlen_T + tlv.nlen_L + tlv.nlen_V;
		p_tmp = p_buf+n_offset;
		p_goose_info->u_result |= DISSECT_GOOSE_STNUM_OK;
	}
	if (0x86 == (unsigned char)p_tmp[0])
	{
//		memset(&tlv, 0, sizeof(TLV_STRUCT_EX));
		ParseASN1_TLV_ex(p_tmp, &tlv);
		//解析n_sqNum
//modified on 2012-10-30 by ljm				n_offset += Parse2UnInt(p_tmp,p_goose_info->n_sqNum);
		Parse_uInt_byTLV(&tlv,p_goose_info->n_sqNum);
		n_offset += tlv.nlen_T + tlv.nlen_L + tlv.nlen_V;
		p_tmp = p_buf+n_offset;
		p_goose_info->u_result |= DISSECT_GOOSE_SQNUM_OK;
	}
	if (0x87 == (unsigned char)p_tmp[0])
	{	
		//解析b_test
		n_offset += Parse2Bool(p_tmp,p_goose_info->b_test);
		p_tmp = p_buf+n_offset;
		p_goose_info->u_result |= DISSECT_GOOSE_TEST_OK;
	}
	if (0x88 == (unsigned char)p_tmp[0])
	{
//		memset(&tlv, 0, sizeof(TLV_STRUCT_EX));
		ParseASN1_TLV_ex(p_tmp, &tlv);
		unsigned int ntmp_da=0;
		//解析n_confRev
		Parse_uInt_byTLV(&tlv, ntmp_da);
		p_goose_info->n_confRev=ntmp_da;
		n_offset += tlv.nlen_T + tlv.nlen_L + tlv.nlen_V;
//modified on 2012-10-30 by ljm		n_offset += Parse2Int(p_tmp,p_goose_info->n_confRev);
		p_tmp = p_buf+n_offset;
		p_goose_info->u_result |= DISSECT_GOOSE_CONFREV_OK;
	}
	if (0x89 == (unsigned char)p_tmp[0])
	{
		//解析b_ndsCom
		n_offset += Parse2Bool(p_tmp,p_goose_info->b_ndsCom);
		p_tmp = p_buf+n_offset;
		p_goose_info->u_result |= DISSECT_GOOSE_NDSCOM_OK;
	}
	if (0x8a == (unsigned char)p_tmp[0])
	{
//		memset(&tlv, 0, sizeof(TLV_STRUCT_EX));
		ParseASN1_TLV_ex(p_tmp, &tlv);
		unsigned int ntmp_da=0;
		//解析n_numDatSetEntries
		Parse_uInt_byTLV(&tlv, ntmp_da);
		p_goose_info->n_numDatSetEntries = ntmp_da;
		n_offset += tlv.nlen_T + tlv.nlen_L + tlv.nlen_V;
//modified on 2012-10-30 by ljm				n_offset += Parse2Int(p_tmp,p_goose_info->n_numDatSetEntries);
		p_tmp = p_buf+n_offset;
		p_goose_info->u_result |= DISSECT_GOOSE_NUMDATASETENTRIES_OK;
	}
	
	if (b_parseData)
	{
		//解析p_data_struct
		//解析n_numDataStructs
		n_offset += ParseGooseMMSDatas(p_buf+n_offset,p_goose_info);
	}
	else
	{
		ParseASN1_TLV_ex(p_buf+n_offset,&tlv);
		n_offset += tlv.nlen_T + tlv.nlen_L + tlv.nlen_V;
	}
	
	return nRet;
//	return nlen_pdu;
}
//p_packet代表一个报文，对应一个appid，对应一个asdu，对应一个数据集，测量通道可以划分成为多个asdu上送
int CPacketConvert::packetconvert_2smv_ex(PACKET_STRUCT* p_packet,int n_num, SMV_INFO_STRUCT *p_msg)
{
	int nRet = RES_FAIL;
	int i, j, k;
	char *p_buf_tmp;
	char *p_data_buf;
//	int npacket_len = 0;//每帧报文的长度（包括报文头:16字节）
	unsigned int ntag;
	int nStep;
//	unsigned int n_secs;
//	unsigned int n_usecs;
	int n_dataset_len;
	int n_data_num;
	TLV_STRUCT_EX tlv;
	unsigned int ntmp_v;
	//////////////
	int ntmp_step;
	int ntmp_len=0;
	bool btag_err = false;
	//////////////////
	
	if (NULL==p_packet || NULL==p_msg)
	{
		return RES_FAIL;
	}
	
	for (i=0; i<n_num; i++)
	{
		p_buf_tmp = (char*)p_packet[i].pPacket;

		//增加报文长度异常处理
		ntmp_step = 0;

		
		memcpy(p_msg[i].c_avtm_epocsec, p_buf_tmp, 8);
		nStep = 16;//跳过arvtime, InclLen和OrigLen
		ntmp_step += nStep;
		
		//解析目的MAC地址
		p_buf_tmp = p_buf_tmp + nStep;
		memcpy(p_msg[i].c_dest_mac, p_buf_tmp, 6);
		nStep = 6;
		ntmp_step +=  nStep;
		
		//解析源MAC地址
		p_buf_tmp = p_buf_tmp + nStep;
		memcpy(p_msg[i].c_src_mac, p_buf_tmp, 6);
		nStep = 6;
		ntmp_step +=  nStep;
		
		p_buf_tmp = p_buf_tmp + nStep;
		if (p_packet[i].nLen < 76)
		{
			p_msg[i].u_result |= DISSECT_SMV_PKTLEN_ERROR;
			continue;
		}

		if (0x81==(unsigned char)p_buf_tmp[0] && 0x00==(unsigned char)p_buf_tmp[1])
			nStep = 6;//跳过Priority tagged和ethertype
		else
			nStep = 2;
		ntmp_step +=  nStep;
		
		//解析APPID
		p_buf_tmp = p_buf_tmp + nStep;
		p_msg[i].n_app_id = 256*((unsigned char)p_buf_tmp[0]) + (unsigned char)p_buf_tmp[1];
		nStep = 2;
		
		//解析msg_len
		p_buf_tmp = p_buf_tmp + nStep;
		p_msg[i].n_msg_len = 256*((unsigned char)p_buf_tmp[0]) + (unsigned char)p_buf_tmp[1];
		
//////////////////////////////////////////////////////////////////////////////////////////////		
		//解析ASDU
		p_buf_tmp = p_buf_tmp + 6;//跳过msg_len, reserve1和reserve2

		//增加判断msg_len异常判断
		int nDiff=p_msg[i].n_msg_len - (p_packet[i].nLen - ntmp_step);
		if (nDiff!=0)
		{
			p_msg[i].u_result |= DISSECT_SMV_MSGLEN_ERROR;
			continue;
		}

		//PDU首结构，tag为60
//		memset(&tlv, 0, sizeof(TLV_STRUCT_EX));//关闭memset函数，在ParseASN1_TLV_ex增加了设置结构中属性值函数 modify by yzh 20130330
		ParseASN1_TLV_ex(p_buf_tmp, &tlv);
		nStep = tlv.nlen_T + tlv.nlen_L;

		//解析ASDU个数
		p_buf_tmp = p_buf_tmp + nStep;
//		memset(&tlv, 0, sizeof(TLV_STRUCT_EX));
		ParseASN1_TLV_ex(p_buf_tmp, &tlv);
		if ( 0x80 == (unsigned char)(tlv.p_T[0]) )//增加标识，是否已解析出nofasdu
		{
			p_msg[i].u_result |= DISSECT_SMV_NOFASDU_OK;
		}
		else
		{
			continue;
		}
		Parse_uInt_byTLV(&tlv, ntmp_v);
		p_msg[i].n_nofasdu_actual = ntmp_v;
		p_msg[i].n_asdu_num = ntmp_v;
		nStep = tlv.nlen_T + tlv.nlen_L + tlv.nlen_V; //跳过ASDU个数
		if (0 == p_msg[i].n_nofasdu_actual || 1000< p_msg[i].n_nofasdu_actual)
		{
			p_msg[i].u_result |= DISSECT_SMV_ASDU_NUM_ZERO;
			continue;
		}
		p_msg[i].p_asdu_info_struct = new ASDU_INFO_STRUCT[p_msg[i].n_nofasdu_actual];

		//跳过sequence of
		p_buf_tmp = p_buf_tmp + nStep; 
//		memset(&tlv, 0, sizeof(TLV_STRUCT_EX));
		ParseASN1_TLV_ex(p_buf_tmp, &tlv);
		nStep = tlv.nlen_T + tlv.nlen_L;

		//解析ASDU
		for (j=0; j<p_msg[i].n_nofasdu_actual; j++)
		{
			//ASDU头，30开头
			p_buf_tmp = p_buf_tmp + nStep; 
//			memset(&tlv, 0, sizeof(TLV_STRUCT_EX));
			ParseASN1_TLV_ex(p_buf_tmp, &tlv);
			nStep = tlv.nlen_T + tlv.nlen_L;

			ntmp_step = 0;
			ntmp_len = tlv.nlen_V;
			while (ntmp_step < ntmp_len)
			{
				p_buf_tmp = p_buf_tmp + nStep; 
//				memset(&tlv, 0, sizeof(TLV_STRUCT_EX));
				ParseASN1_TLV_ex(p_buf_tmp, &tlv); 
				////////////////////////////////////////////////////////
				ntmp_step += tlv.nlen_T + tlv.nlen_L + tlv.nlen_V;//每项的步长
				if (ntmp_step <= 0)
				{
					btag_err = true;
					break;//异常处理
				}
				///////////////////////////////////////////////////////
				ntag = 0;
				memcpy(&ntag, (unsigned char*)p_buf_tmp, 1);
				switch ( ntag )
				{
				case 0X80:			//sv_id
					memset(p_msg[i].p_asdu_info_struct[j].c_svID, 0, MAX_DATA_LEN_VISIBLE_STRING);
					memcpy(p_msg[i].p_asdu_info_struct[j].c_svID, tlv.p_V, tlv.nlen_V);
					nStep = tlv.nlen_T + tlv.nlen_L + tlv.nlen_V;
					p_msg[i].u_result |= DISSECT_SMV_SVID_OK;
					break;
				case 0X81:			//dataSet
					memset(p_msg[i].p_asdu_info_struct[j].c_dataset, 0, MAX_DATA_LEN_OBJ_REF);
					memcpy(p_msg[i].p_asdu_info_struct[j].c_dataset, tlv.p_V, tlv.nlen_V);
					nStep = tlv.nlen_T + tlv.nlen_L + tlv.nlen_V;
					p_msg[i].u_result |= DISSECT_SMV_DATASET_OK;
					break;
				case  0X82:			//smpCnt	规范定为Uint16
					Parse_uInt_byTLV(&tlv, ntmp_v);
					p_msg[i].p_asdu_info_struct[j].n_smpCnt = ntmp_v;
					nStep = tlv.nlen_T + tlv.nlen_L + tlv.nlen_V;
					p_msg[i].u_result |= DISSECT_SMV_SMPCNT_OK;
					break;
				case 0x83:			//confRev		规范定为Uint32
					Parse_uInt_byTLV(&tlv, ntmp_v);
					p_msg[i].p_asdu_info_struct[j].n_confRev = ntmp_v;
					nStep = tlv.nlen_T + tlv.nlen_L + tlv.nlen_V;
					p_msg[i].u_result |= DISSECT_SMV_CONFREV_OK;
					break;
				case 0x84:			//refrTm
					memset(p_msg[i].p_asdu_info_struct[j].c_refrTm, 0, MAX_DATA_LEN_ENTRY_TIME);
					memcpy(p_msg[i].p_asdu_info_struct[j].c_refrTm, tlv.p_V, tlv.nlen_V);
					nStep = tlv.nlen_T + tlv.nlen_L + tlv.nlen_V;
					p_msg[i].u_result |= DISSECT_SMV_REFRTM_OK;
					break;
				case 0x85:			//smpSynch
					Parse_uInt_byTLV(&tlv, ntmp_v);
					p_msg[i].p_asdu_info_struct[j].n_smpSynch = (int)ntmp_v;
					p_msg[i].p_asdu_info_struct[j].b_smpSynch = 1==(int)ntmp_v;
					nStep = tlv.nlen_T + tlv.nlen_L + tlv.nlen_V;
					p_msg[i].u_result |= DISSECT_SMV_SMPSYNCH_OK;
					break;
				case 0x86:			//smpRate	规范定为Uint16
					 Parse_uInt_byTLV(&tlv, ntmp_v);
					 p_msg[i].p_asdu_info_struct[j].n_smpRate = ntmp_v;
					 nStep = tlv.nlen_T + tlv.nlen_L + tlv.nlen_V;
					 p_msg[i].u_result |= DISSECT_SMV_SMPRATE_OK;
					break;

				case 0X87:			//sequence of Data
					ntmp_v = 0;
					memcpy((char *)&ntmp_v, tlv.p_L, 1);
					if(ntmp_v & 0x80)	//长模式
					{
						//去高位
						if ((ntmp_v &= 0x7F) > 0)	// 定长模式的长形式
						{
							n_dataset_len = 0;
							if (ntmp_v == 1)
							{
								n_dataset_len = ((unsigned char*)tlv.p_L + 1)[0];//memcpy((char *)&n_dataset_len, tlv.p_L + 1, 1);
							}
							else if (ntmp_v == 2)
							{
								//n_dataset_len = (unsigned char)(tlv.p_T + 1)[2] + ( ((unsigned char)(tlv.p_T + 1)[1]) << 8 );
								//n_dataset_len = (unsigned char)(tlv.p_L + 1)[1] + ( ((unsigned char)(tlv.p_T + 1)[0]) << 8 );//错误代码 modify by yzh 20130330
								n_dataset_len = (unsigned char)(tlv.p_L + 1)[1] + ( ((unsigned char)(tlv.p_L + 1)[0]) << 8 );//modified on 2013/03/30 ljm
							}
							//通道数目前最多50，即长度最长400字节，不会多于2字节
						}
					}
					else
					{
						n_dataset_len = ((unsigned char*)tlv.p_L)[0];//memcpy((char *)&n_dataset_len, tlv.p_L + 1, 1);
					}
					
					n_data_num = n_dataset_len/8;
					p_msg[i].p_asdu_info_struct[j].n_danum_actual = n_data_num;
					p_msg[i].p_asdu_info_struct[j].n_data_num = n_data_num;
//					if (p_msg[i].p_asdu_info_struct[j].n_data_num == n_data_num)//配置通道数与报文中通道数相等时，才解析通道值和品质
					if (p_msg[i].p_asdu_info_struct[j].n_data_num > 0 )
					{
						p_msg[i].p_asdu_info_struct[j].p_smv_data_struct = new SMV_DATA_STRUCT[p_msg[i].p_asdu_info_struct[j].n_data_num];
						p_data_buf = tlv.p_V;
						for (k=0; k<n_data_num; k++)
						{
							(p_msg[i].p_asdu_info_struct[j]).p_smv_data_struct[k].n_value = Buf2Int32(p_data_buf);
							memcpy( (p_msg[i].p_asdu_info_struct[j]).p_smv_data_struct[k].c_quality, p_data_buf+4, 4);

							p_data_buf = p_data_buf + 8;
						}
					}

					nStep = tlv.nlen_T + tlv.nlen_L;
					p_msg[i].u_result |= DISSECT_SMV_SEQUENCEOFDATA_OK;
					break;

				default:
					btag_err = true;
					break;

				}//switch 循环结束

		/*		if (ntag == 0X87)	//tag到87时，跳出while循环
				{
					break;
				}*/
				if (btag_err)
					break;
			}//while 循环结束

			if (btag_err)
				break;
		}//for asdu 循环结束

		if (!btag_err)
		{
			nRet = RES_SUCCESS;
		}
//////////////////////////////////////////////////////////////////////////////////////////////

//		noffset += p_msg[i].n_msg_len;//记录每帧报文长度（包括报文头:16字节）此注释不要删，以后判PDU长度异常时有用
	}//for 多帧循环结束
	
	return nRet;
}

int CPacketConvert::packetconvert_2ptp_ex(PACKET_STRUCT* p_packet,int n_num, PTP_INFO_STRUCT* p_msg)
{
	int nRet = RES_SUCCESS;
	int i;
	int nStep = 0;
	int nstart = 28;
	char *p_buf_tmp =NULL;
	char *pTmp = NULL;
//	double d_correction_test=0;//测试

	if (NULL==p_packet || NULL==p_msg)
	{
		return RES_FAIL;
	}

	for (i=0; i<n_num; i++)
	{
		p_buf_tmp = (char*)p_packet[i].pPacket;

		//解析报文到达时间
//		nStep += ParseAvtm(p_buf_tmp,p_msg[i].c_avtm_epocsec);
/*		memcpy(p_msg[i].c_avtm_epocsec, p_buf_tmp, 4);//时间戳的秒
		nStep += 4;
		memcpy(p_msg[i].c_avtm_epocsec+4, p_buf_tmp+4, 4);//时间戳的微秒
		nStep += 4;

		nStep += 8;//跳过InclLen和OrigLen
		//解析目的MAC地址
		nStep += ParseMac(p_buf_tmp+nStep,p_msg[i].c_dest_mac);	
		//解析源MAC地址
		nStep += ParseMac(p_buf_tmp+nStep,p_msg[i].c_src_mac);
		*/
		//解析报文到达时间(直接拷贝8字节，和SMV解析统一处理)
		memcpy(p_msg[i].c_avtm_epocsec, p_buf_tmp, 8);
		nStep += 16;//跳过arvtime, InclLen和OrigLen
		
		//解析目的MAC地址
		memcpy(p_msg[i].c_dest_mac, p_buf_tmp+nStep, 6);
		nStep += 6;
		
		//解析源MAC地址
		memcpy(p_msg[i].c_src_mac, p_buf_tmp+nStep, 6);
		nStep += 6;

		if (0x81==(unsigned char)p_buf_tmp[nstart] && 0x00==(unsigned char)p_buf_tmp[nstart+1])
			nStep += 6;//跳过Priority tagged和ethertype
		else
			nStep += 2;

		//PTP报文头
 		memcpy(&(p_msg[i].ptp_header), p_buf_tmp+nStep, 34);
 		nStep += 34;
		p_msg[i].ptp_header.enum_ptp_msg_type = p_msg[i].ptp_header.enum_ptp_msg_type & 0X0F;
		p_msg[i].ptp_header.n_ptp_vertion = p_msg[i].ptp_header.n_ptp_vertion & 0X0F;
		p_msg[i].ptp_header.n_msg_len = reverse_2byte(p_msg[i].ptp_header.n_msg_len);

		/***********************测试************************************/
/*		char ctest[256]={0};
		CLOCK_IDENTITY_STRUCT *ptest = &(p_msg[i].ptp_header.port_identity.clock_identity);
		sprintf(ctest, "0x%0x%0x%0x%0x%0x%0x%0x%0x",\
			ptest->c_bit0,ptest->c_bit1,ptest->c_bit2,ptest->c_bit3,ptest->c_bit4,ptest->c_bit5,\
			ptest->c_bit6,ptest->c_bit7);

		get_correction_val(p_msg[i].ptp_header.correction_field, d_correction_test); */
		/**************************************************************/

		p_msg[i].ptp_header.port_identity.u_port_id = reverse_2byte(p_msg[i].ptp_header.port_identity.u_port_id);
		p_msg[i].ptp_header.n_sq_id = reverse_2byte(p_msg[i].ptp_header.n_sq_id);

		//解析报文具体内容
		nStep += ParsePTPbody(p_buf_tmp+nStep, p_msg[i].ptp_header.enum_ptp_msg_type, &p_msg[i]);
	}

	return nRet;
}
