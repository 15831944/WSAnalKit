#ifndef SMFC_I_H_HEADER_INCLUDED_B3305D3B
#define SMFC_I_H_HEADER_INCLUDED_B3305D3B

#include "define_scan.h"
#include "const_scan.h"
#include "share_scan.h"
#include "SYS_MODEL_STRUCT.h"

#ifdef OS_LINUX
#define __int64 long long 
#endif

/*
enum ETHER_TYPE
{
	ETHER_TYPE_MMS =1,
	ETHER_TYPE_GOOSE,
	ETHER_TYPE_SMV,
		
	ETHER_TYPE_UNKOWN=9999
};	*/

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

//流量统计
typedef struct PACKET_STATISTICS_STRUCT
{
	int nStartTime;
//	unsigned long nPacketNum;
	__int64 nPacketNum;//modified on 2013/03/28 ljm 处理帧数翻转//用于判断缓冲区写入位置，和帧速统计，当前超长帧片段被认为是一帧，暂不考虑增加一变量来特殊处理超长帧片段。
	unsigned long nTotalSize_MB;
	unsigned long nTotalSize_BYTE;
	//time_t秒数
	unsigned long	lSec;		// timestamp seconds 
	//毫秒数
	unsigned long 	lUsec;	// timestamp microseconds (nsecs for PCAP_NSEC_MAGIC) 
	
	PACKET_STATISTICS_STRUCT(){
		nStartTime=0;
		nPacketNum=0;
		nTotalSize_MB=0;
		nTotalSize_BYTE=0;
		lSec = 0;
		lUsec = 0;
	}

}_PACKET_STATISTICS_STRUCT;

//具体链路的流量统计
typedef struct LINK_STATISTICS_STRUCT
{
	PACKET_STATISTICS_STRUCT statLink;

	unsigned int nAppid;

	LINK_STATISTICS_STRUCT()
	{
		nAppid = 0;
	}

}_LINK_STATISTICS_STRUCT;

//端口流量统计
typedef struct PORT_STATISTICS_STRUCT{

	PACKET_STATISTICS_STRUCT statGoose;

	PACKET_STATISTICS_STRUCT statOther;

	LINK_STATISTICS_STRUCT *pStatLinkArray;//采样值流量统计

	int nAppidNum;//SMV的链路数

	PORT_STATISTICS_STRUCT()
	{
		pStatLinkArray = NULL;
		nAppidNum = 0;
	}


}_PORT_STATISTICS_STRUCT;

/*
typedef struct _PORT_INFO_STRUCT
{
	int nPort;
	
	int *pAppid;

	int nAppidNum;

	_PORT_INFO_STRUCT()
	{
		pAppid = NULL;
	}

}PORT_INFO_STRUCT;*/

typedef struct _SMFC_CFG_STRUCT
{
/*	char cLogPath[255];

	int nLogLevel;

	int nLogSize;*/

	LOG_STRUCT logInfo;

	unsigned int nMaxPktLen_goose;
	unsigned int nMaxPktLen_smv;
	unsigned int nMaxPktLen_other;
	unsigned long lMaxSMFileSize_goose;//goose共享内存文件大小
	unsigned long lMaxSMFileSize_smv;//smv共享内存文件大小
	unsigned long lMaxSMFileSize_other;//其它报文共享内存文件大小

	SNIFFER_PORT **pPortInfo;

	int nPortNum;

	_SMFC_CFG_STRUCT()
	{
		pPortInfo = NULL;
		nMaxPktLen_goose=0;
		nMaxPktLen_smv=0;
		nMaxPktLen_other=0;
		lMaxSMFileSize_goose = 0;
		lMaxSMFileSize_smv = 0;
		lMaxSMFileSize_other = 0;
	}

}SMFC_CFG_STRUCT;


#ifdef OS_WINDOWS

#ifdef SMFC_DLL_FILE 

class _declspec(dllexport) CSMFC_I //导出类 

#else 

class _declspec(dllimport) CSMFC_I //导入类 

#endif//SMFC_DLL_FILE

#endif//OS_WINDOWS

#ifdef OS_LINUX

	class CSMFC_I

#endif //OS_LINUX

	{
		protected:
			CSMFC_I(){};

		public:
			
			virtual int smfc_write_packet(int nPort, PACKET_STRUCT *pStruct)=0;

			//往后读
			virtual int smfc_read_packet(int nPort, PACKET_STRUCT *pStruct, int nPacketNum)=0;

			//往后间隔读
			virtual int smfc_read_step_packet(int nPort, PACKET_STRUCT *pStruct, int nPacketNum, int nStep)=0;

			//往前读
			virtual int smfc_read_rpacket(int nPort, PACKET_STRUCT *pStruct, int nPacketNum)=0;

			//往前间隔读
			virtual int smfc_read_rstep_packet(int nPort, PACKET_STRUCT *pStruct, int nPacketNum, int nStep)=0;

			virtual int smfc_read_statistics(int nPort, PORT_STATISTICS_STRUCT *pStruct)=0;

			virtual int smfc_release_file()=0;
			virtual int smfc_read_rpacket_ex(int nPort, PACKET_STRUCT *pStruct, int nPacketNum)=0;

			//从smfc_read_rpacket接口调用时，记录的写指针往前读nPacketNum帧，包括已读过的。端口不在配置时，返回-1，成功返回0，失败返回1
			virtual int smfc_read_rpacket_from_lastwritepos(int nPort, PACKET_STRUCT *pStruct, int nPacketNum)=0;

			virtual int smfc_read_rstep_packet_from_lastwritepos(int nPort, PACKET_STRUCT *pStruct, int nPacketNum, int nStep)=0;

			//读指定SMV节点的统计值
			virtual int smfc_read_smvlink_statistics(int nPort, LINK_STATISTICS_STRUCT* pStruct)=0;
			//读指定GOOSE节点的统计值
			virtual int smfc_read_gooselink_statistics(int nPort, LINK_STATISTICS_STRUCT* pStruct)=0;
			//读指定PTP节点的统计值
			virtual int smfc_read_ptp_statistics(int nPort, char *cMac, PACKET_STATISTICS_STRUCT* pStatic)=0;

			//写成员变量(该成员变量用于记录统计共享内存中的帧数，读报文时的起始位置)
			virtual int smfc_set_member_lastpktnum(int nPort, int nEthType, unsigned int nAppid)=0;
			//读其他报文的统计值，包括未配置smv和其他报文
			virtual int smfc_read_other_statistics(int nPort, PACKET_STATISTICS_STRUCT *pstatistics)=0;
			//读广播报文的统计值
			virtual int smfc_read_broadcast_statistics(int nPort, PACKET_STATISTICS_STRUCT *pstatistics)=0;
			//读MMS报文的统计值
			virtual int smfc_read_mms_statistics(int nPort, PACKET_STATISTICS_STRUCT *pstatistics)=0;

			//删除记录未配置appid的文件
			virtual int smfc_delete_uncfg_appid_file()=0;

			//add on 2013/03/18 ljm 增加端口总流量统计
			virtual int smfc_read_port_whole_statistics(int nPort, PACKET_STATISTICS_STRUCT *pstatistics)=0;

			
	};


#ifdef OS_WINDOWS

#ifdef SMFC_DLL_FILE 

//导出函数

extern "C"  __declspec( dllexport ) CSMFC_I * createSMFC_I(SMFC_CFG_STRUCT* pSmfcCfg);
extern "C"  __declspec( dllexport ) void destroySMFC_I(CSMFC_I* theInterface);

#else 

//导入函数

extern "C"  __declspec( dllimport ) CSMFC_I * createSMFC_I(SMFC_CFG_STRUCT* pSmfcCfg);
extern "C"  __declspec( dllimport ) void destroySMFC_I(CSMFC_I* theInterface);

#endif //DLL_FILE_PACKETCAP
#endif //OS_WINDOWS

#ifdef OS_LINUX
#ifdef __cplusplus
extern "C"
{
#endif
	
	CSMFC_I * createSMFC_I(SMFC_CFG_STRUCT* pSmfcCfg);
	void destroySMFC_I(CSMFC_I* theInterface);
	
#ifdef __cplusplus
}
#endif

#endif //OS_LINUX

#endif /* SMFC_I_H_HEADER_INCLUDED_B3305D3B */