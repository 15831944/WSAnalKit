#ifndef PACKET_2_MESSAGE_H
#define PACKET_2_MESSAGE_H

#include "LogFile.h"
#include "share_scan.h"
#include "mmsstruct.h"
#include "AT_STRUCT.h"
#include "ptp_struct_def.h"
#include "ParseASN1.h"

#define MAX_TIME_STRING_LEN 256
#define UTC_DEF_TIME_FORMAT "%Y-%m-%dT%H:%M:%S"

//copy from ShareMemFileCtrl_I.h  djf
typedef struct PACKET_STRUCT{

    //单帧报文内容起始地址
    void *pPacket;
    //单帧报文长度，包括长帧片段，在链路层异常时，包括尾部附加的8字节信息
    int nLen;

    unsigned int nAppid;

    ETHER_TYPE nEthType;

    PACKET_STRUCT()
    {
        pPacket = 0;
        nLen = 0;
        nAppid = 0;
        nEthType = IEC61850_ETHER_TYPE_UNKOWN;
    }

}PACKET_STRUCT;

//copy from Packet2Message_I.h djf
typedef struct _PKTCONVERT_CFG_STRUCT
{
        LOG_STRUCT logInfo;

        bool bParseSmvDA;
        bool bParseGooseDA;


        _PKTCONVERT_CFG_STRUCT()
        {
                bParseSmvDA = false;
                bParseGooseDA = false;

        }

}PKTCONVERT_CFG_STRUCT;

class CPacketConvert
{
public:
        CPacketConvert(){}
	virtual ~CPacketConvert();
	
public:
	int packetconvert_init(PKTCONVERT_CFG_STRUCT CfgInfo);

	int packetconvert_get_appid(const char *p_Buf);

        int packetconvert_get_utctime(char *p_packet_buf, char *c_utctime);

        virtual void packetconvert_set_linkType(int nLinkType){
		m_nLinkType = nLinkType;//101 == raw IP, with no link
	}

	virtual int packetconvert_get_linkType(){
		return m_nLinkType;//101 == raw IP, with no link
	}

	ETHER_TYPE packetconvert_get_ether_type(char *p_packet_buf);
	int packetconvert_release_goose_mms_data(GOOSE_INFO_STRUCT* pGoose, int n_num);
	int packetconvert_release_mms_data(MMS_DATA_STRUCT* p_mms_data, int n_num);
	int packetconvert_release_smv_asdu(SMV_INFO_STRUCT* pSmv, int n_num);
	int packetconvert_release_asdu_info(ASDU_INFO_STRUCT* p_asdu_info, int n_num);
	//int packetconvert_get_dstip(char *p_packet_buf, char *pIP);
	int packetconvert_get_srctip(char *p_packet_buf, char *pIP);
	int packetconvert_get_dest_mac(char *p_packet_buf, char *p_mac);
	int packetconvert_get_src_mac(char *p_packet_buf, char *p_mac);

	//int get_correction_val(CORRECTION_FIELD correctionField, double &d_correction);
	//int get_timestamp_s_ns(PTP_TIME_STAMP timestamp, __int64 &time_s, UINT &time_ns);

private:
	int release_mms_data_ex(MMS_DATA_STRUCT &mms_data);
	int init_mms_data_ex(MMS_DATA_STRUCT* p_mms_data);
	int set_mms_data(MMS_DATA_STRUCT mms_da_src, MMS_DATA_STRUCT* p_mms_da_dst);


private:
	int OpenLogFile(LOG_STRUCT logInfo);
	int End();

private:
	int ParseAvtm(char *p_packet_buf, char *c_avtm);
	int ParseMac(char *p_packet_buf, char *p_mac);
	int ParseAppid(char *p_packet_buf, unsigned int &n_appid);
	int ParseMsgLen(char *p_packet_buf, int &n_msglen);
	int ParseReserve(char *p_packet_buf,char *c_reserve);
	int ParseASDU(char *p_packet_buf,SMV_INFO_STRUCT *p_smv_info,bool b_parseData);
        int ValueBuf2Uint16(char *p_value_buf, unsigned short &n_value);
	int ReverseBeginNchar(char *p_packet_buf, int n_reverse, char *p_dest);

private:
	int ParseGoosePdu(char *p_buf,GOOSE_INFO_STRUCT *p_goose_info,bool b_parseData);
	int ParseMMSData(char *p_buf, MMS_DATA_STRUCT *p_data_struct);
	int Parse2MMSstring(char *p_buf, char *c_data);
	int Parse2Bitstring(char *p_buf, char *c_data);
	int ValueBuf2Bitstring(char *p_value_buf, int n_bytes, char *p_bitstring);
	int Parse2Utctime(char *p_buf, char *p_utctime);
	int ValueBuf2Utctime(char *p_value_buf, char *p_utctime);
        int UtcValsToString (char *dest, UINT secs, UINT fraction, UINT qflags);
	int ParseGooseMMSDatas(char *p_buf, GOOSE_INFO_STRUCT* p_goose_info);
	MMS_DATA_STRUCT* CreateMMSDatas(vector<MMS_DATA_STRUCT> v_mms_data);
	int ParseMMSStructData(char *p_buf, MMS_DATA_STRUCT* p_mms_data);
	int Buf2MMSDataVetor(char *p_buf, vector<MMS_DATA_STRUCT>& v_mms_data);
	int Parse2Bool(char *p_buf, bool &b_data);
	int Parse2Double(char *p_buf,double &d_data);
	int Parse2Float(char *p_buf,float &f_data);
        int Parse2uInt16(char *p_buf, unsigned short &n_data);
	int Parse2Int(char *p_buf,int &n_data);
	int Parse2UnInt(char *p_buf,UINT &n_data);
	int Parse2char(char *p_buf,char *c_data);

        int UtcValsToString_ex(char *dest, UINT secs, UINT fraction);
	int EpocChar2utc(char *p_epoc, char *p_utc);

	int init_mms_data(MMS_DATA_STRUCT* pmms_da, int n_num);

	int Parser4Char2Int(char *c_buf);
	int ParsePTPbody(char *p_buf, uint8 n_ptp_msg_type, PTP_INFO_STRUCT *p_msg);
	u_short reverse_2byte(u_short u_value);
	UINT reverse_4byte(UINT u_value);
	//__int64 reverse_6byte(UINT nuint16_val, u_short nshort_val);

private:
	static int tlv2int(TLV_STRUCT_EX *p_tlv,bool signedint,char *dst);
	static char* lToStr(long int val,char *dst, int radix);
        char *sInt8ToAscii  (char   v, char *p) {lToStr ((long) v, p, -10); return p;}
        char *uInt8ToAscii  (unsigned char  v, char *p) {lToStr ((long) v, p,  10); return p;}
        char *sInt16ToAscii (short  v, char *p) {lToStr ((long) v, p, -10); return p;}
        char *uInt16ToAscii (unsigned short v, char *p) {lToStr ((long) v, p,  10); return p;}
        char *sInt32ToAscii (int  v, char *p) {lToStr ((long) v, p, -10); return p;}
        char *uInt32ToAscii (unsigned int v, char *p) {lToStr ((long) v, p,  10); return p;}
        char *sIntToAscii   (int    v, char *p) {lToStr ((long) v, p, -10); return p;}
        char *uIntToAscii   (unsigned int   v, char *p) {lToStr ((long) v, p,  10); return p;}
        char *sLongToAscii  (unsigned long   v, char *p) {lToStr ((long) v, p, -10); return p;}
        char *uLongToAscii  (unsigned long  v, char *p) {lToStr ((long) v, p,  10); return p;}

private:
	CLogFile m_LogFile;

	bool m_bParseSmvDA;
	bool m_bParseGooseDA;
	int m_nLinkType;//101 == raw ip,no link

public:
	//GOOSE报文解析，p_packet:原始报文数组，n_num数组大小，p_msg是外部已经分配好资源的GOOSE_INFO_STRUCT数组
	int packetconvert_2goose_ex(PACKET_STRUCT* p_packet,int n_num, GOOSE_INFO_STRUCT* p_msg);

	//SMV报文解析，p_packet:原始报文数组，n_num数组大小，p_msg是外部已经分配好资源的SMV_INFO_STRUCT数组
	//且每个SMV_INFO_STRUCT中ASDU_INFO_STRUCT资源也已分配好,每个ASDU_INFO_STRUCT数组中的SMV_DATA_STRUCT的资源也已经分配好
	int packetconvert_2smv_ex2(PACKET_STRUCT* p_packet,int n_num, SMV_INFO_STRUCT *p_msg);

	//SMV报文解析，p_packet:原始报文数组，n_num数组大小，p_msg是外部已经分配好资源的SMV_INFO_STRUCT数组
	int packetconvert_2smv_ex(PACKET_STRUCT* p_packet,int n_num, SMV_INFO_STRUCT *p_msg);

	int packetconvert_2ptp_ex(PACKET_STRUCT* p_packet,int n_num, PTP_INFO_STRUCT* p_msg);

private:
	unsigned short buf2ushort(char *p_packet_buf, int nbyte_num);

};


#endif  /*PACKET_2_MESSAGE_H*/
