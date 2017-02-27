#ifndef AT_STRUCT_H_HEADER_INCLUDED_88888888
#define AT_STRUCT_H_HEADER_INCLUDED_88888888

#include <memory>
#include "mmsstruct.h"
//#include "..\mms2acsi\mmsstruct.h"  //modify by yinzhehong 20101118
#include "const_scan.h"

#define MAX_DATA_LEN_OBJ_REF 129+1 

#define MAX_DATA_LEN_VISIBLE_STRING  65+1 
#define MAX_DATA_LEN_ENTRY_TIME		 48+1

#define SHORT_DATA_LEN				 64+1

#define	MAX_DATA_LEN 256+1
#define MAX_REF_LEN	 128+1

//#define MAX_MAC_LEN 17+1
#define MAX_ARRIVAL_TIME_LEN 255+1

#define  DES_LEN     64
#define  CONTENT_LEN 64
//AnalyzeTxt内容结构
typedef struct AT_ITEM_STRUCT{
	char c_des[DES_LEN];//MAX_DES_LEN
	char c_content[CONTENT_LEN];	//实际内容
	
	//初始化清空
	AT_ITEM_STRUCT()
	{
		memset(c_des,0,sizeof(c_des));
		memset(c_content,0,sizeof(c_content));
	}
}_AT_ITEM_STRUCT;

//AnalyzeTxt结果结构
typedef struct AT_STRUCT{
	int n_item_num;	//节点个数
	AT_ITEM_STRUCT *p_item;	//节点结构首地址

	int n_child_num;		//子节点个数
	AT_STRUCT *p_child;	//子节点结构首地址
	AT_STRUCT *p_parent;	//父节点指针

	//初始化清空
	AT_STRUCT()
	{
		n_item_num	 =	0;
		p_item			  =	NULL;
		n_child_num		    =	0;
		p_child					=	NULL;
		p_parent				=	NULL;
	}
}_AT_STRUCT;

//单步解析结果结构,针对单一帧报文
typedef struct AT_STRUCT_STEP{
	
	//数据类型 0: 不解析类型 1: mms 2: goose 3: smv
	int n_type;

	//本帧报文解析结果
	AT_STRUCT *p_at_struct;

	AT_STRUCT_STEP(){
		n_type=0;
		p_at_struct=NULL;
	};
	
}_AT_STRUCT_STEP;

typedef struct SMV_DATA_STRUCT{

	//值
	int n_value;
	//品质因素
	char c_quality[9];

	SMV_DATA_STRUCT(){
		n_value=0;
		memset(c_quality,0,sizeof(c_quality));
	}

}_SMV_DATA_STRUCT;


//asdu信息结构
typedef struct ASDU_INFO_STRUCT{

	int n_asdu_len;
	//MsvID或UsvID
	char c_svID[MAX_DATA_LEN_VISIBLE_STRING];

	char c_dataset[MAX_DATA_LEN_OBJ_REF];

	unsigned int n_smpCnt;
	int	 n_confRev;
	char  c_refrTm[MAX_DATA_LEN_ENTRY_TIME];
	bool  b_smpSynch;
	int	  n_smpRate;

	//通道个数（在线分析时是配置中的通道个数）
	int  n_data_num;

	SMV_DATA_STRUCT *p_smv_data_struct;

	//报文中实际通道个数
	unsigned short n_danum_actual;
	int  n_smpSynch;//同步的取值范围，可能超出true|false

	ASDU_INFO_STRUCT(){
		n_asdu_len=0;
		memset(c_svID,0,sizeof(c_svID));
		memset(c_dataset,0,sizeof(c_dataset));
		n_smpCnt=0;
		n_confRev=0;
		memset(c_refrTm,0,sizeof(c_refrTm));
		b_smpSynch=false;
		n_smpRate=0;
		n_data_num=0;
		p_smv_data_struct=NULL;
		n_danum_actual = 0;
		n_smpSynch=0;
	}


}_ASDU_INFO_STRUCT;


typedef struct SMV_INFO_STRUCT{

	//源MAC地址
	char c_src_mac[MAX_MAC_LEN];

	//目的MAC地址
	char c_dest_mac[MAX_MAC_LEN];

	//报文到达时间，以纪元秒表示//在直接解析中，是pcap单元头的8字节sec.usec，在wireshark解析中，是被解析的结果字符串
	char c_avtm_epocsec[MAX_ARV_TIME_LEN];

	//APPID号
	unsigned int n_app_id;
	//报文长度
	int n_msg_len;

	//asdu个数(在线分析时是配置中的asdu个数)
	int n_asdu_num;
	
	//ASDU信息结构数组首地址
	ASDU_INFO_STRUCT *p_asdu_info_struct;

	//报文中实际ASDU个数
	unsigned short n_nofasdu_actual;

	//Bit31:packet_len<76字节 Bit30:表示msg_len异常 Bit29:表示ASDU个数为0
	//Bit15:nofasdu Bit14:sv_id Bit13:smpCunt Bit12:confRev Bit11:SmpSynch Bit10:DataSet Bit9:RefrTm Bit8:SmpRate  Bit7:sequence of data)，其它Bit位预留
	unsigned int u_result;//解析结果 add on 2013/03/28 ljm 默认0x00000000，高字节第4个字节表示解析异常结果，第3个字节预留，第1、2个字节表示解析结果标识

	//初始化清空
	SMV_INFO_STRUCT()
	{
		memset(c_src_mac,0,sizeof(c_src_mac));
		memset(c_dest_mac,0,sizeof(c_dest_mac));
		memset(c_avtm_epocsec,0,sizeof(c_avtm_epocsec));//modified on 20110827
		n_app_id=0;
		n_msg_len=0;
		n_asdu_num=0;
		p_asdu_info_struct=NULL;
		n_nofasdu_actual = 0;
		u_result = 0x00000000;

	}

}_SMV_INFO_STRUCT;


typedef struct GOOSE_INFO_STRUCT{

	//源MAC地址
	char c_src_mac[MAX_MAC_LEN];//add by ljm

	//目的MAC地址
	char c_dest_mac[MAX_MAC_LEN];//add by ljm

	//报文到达时间，以纪元秒表示
	char c_avtm_epocsec[MAX_ARV_TIME_LEN];

	//APPID号
	unsigned int  n_app_id;
	//报文长度
	int n_msg_len;
	//保留字段1
	char c_reserved1[SHORT_DATA_LEN];
	//保留字段2
	char c_reserved2[SHORT_DATA_LEN];

	//goose报告控制块  参引
	char c_gocbRef[MAX_DATA_LEN_OBJ_REF];

	//消息最大允许有效时间
	int n_timeAllowedtoLive;

	//数据集参引
	char c_dataSet[MAX_DATA_LEN_OBJ_REF];

	//goose控制块ID号
	char c_goID[MAX_DATA_LEN_VISIBLE_STRING];

	//utc时间
	char c_t[SHORT_DATA_LEN];

	//st数
	unsigned int n_stNum;//modified on 20110825

	//sq数
	unsigned int n_sqNum; //modified on 20110825

	//测试标志位
	bool b_test;
	
	//配置版本hao
	int n_confRev;

	//NdsCom
	bool b_ndsCom;

	//数据集条目数
	int n_numDatSetEntries;

	//未用
	int n_security;

	//data结构的原数据结构指针，具体内容根据服务类型再做解析
	MMS_DATA_STRUCT *p_data_struct;

	//实际的数据条目
	int n_numDataStructs;//add by yinzhehong 20101124

	//Bit31:packet_len异常，Bit30:msg_len异常
	//Bit23:PDU头的tag正确=1，Bit22:gocbRef, Bit21:timeAllowed Bit20:dataSet Bit19:T Bit18:stNum Bit17:sqNum Bit16:test Bit15:confRev Bit14:ndsCom Bit13:numDataSetEntries
	//Bit12:allData Bit11:goid 其它预留
	unsigned int u_result;//解析结果 add on 2013/03/28 ljm 默认0x00000000，高字节第4个字节表示解析异常结果，3、2、1个字节表示解析结果标识

	GOOSE_INFO_STRUCT(){
		memset(c_src_mac,0,sizeof(c_src_mac));
		memset(c_dest_mac,0,sizeof(c_dest_mac));
		memset(c_avtm_epocsec,0,sizeof(c_avtm_epocsec));//modified on 20110827
		n_app_id = -1;
		n_msg_len=0;
		memset(c_reserved1,0,sizeof(c_reserved1));
		memset(c_reserved2,0,sizeof(c_reserved2));
		
		memset(c_gocbRef,0,sizeof(c_gocbRef));
		n_timeAllowedtoLive = 0;
		memset(c_dataSet,0,sizeof(c_dataSet));
		memset(c_goID,0,sizeof(c_goID));
		memset(c_t,0,sizeof(c_t));
		n_stNum =0;
		n_sqNum =0;
		b_test = false;
		n_confRev = 0;
		b_ndsCom = false;
		n_numDatSetEntries=0;

		n_security=0;
		//data结构的原数据结构指针，具体内容根据服务类型再做解析
		p_data_struct=NULL;
		n_numDataStructs = 0;
		u_result = 0x00000000;
	}

}_GOOSE_INFO_STRUCT;


#endif  /*AT_STRUCT_H_HEADER_INCLUDED_88888888*/
