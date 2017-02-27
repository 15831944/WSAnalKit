#ifndef SYS_MODEL_STRUCT_INCLUDED_00000000000
#define SYS_MODEL_STRUCT_INCLUDED_00000000000
/********************************************************************
*	filename: 	SYS_MODEL_STRUCT.h
*	author:		yinzhehong
*	created:	2010/11/03
*	purpose:  	系统模型定义   
*   version:    1.0
*********************************************************************/

//#include <memory>
#include "define_scan.h"

#define MAX_SNIFFER_NUM	       16    //系统记录装置最大个数
#define MAX_SNIFFER_CARD_NUM   6     //单采集装置携带的采集板卡最大个数
#define MAX_SNIFFER_PORT_NUM   4     //采集卡可携带的最大端口数
#define MAX_SNIFFER_MU_NUM     16    //每个端口可接入的最大MU个数
#define MAX_SMV_ITEM           32    //单个MU最大的采样通道个数
#define MAX_GOOSE_ITEM         256   //单个智能操作箱最大goose条目
#define MAX_DESCRIBE_LEN	   256   //描述最大字符长度
#define WS_MAX_IP_LEN		   31    //IP地址长度
#define MAX_SHORT_DATA_LEN     10    //应用数据长度
#define MAX_NAME_LENGTH        120   //名称占用字节数
#define MAX_USER_PSWD_LEN      17    //帐号密码长度字节

//被监视的节点，报文采集端口下的某个链路收发其数据
typedef struct SNIFFER_APP
{
	int nsys_appsqe;                     //系统编号 从100开始，该编号不能与端口的系统编号重复
	char         cdesc[MAX_NAME_LENGTH]; //节点描述
	int snifferport_sys_id;              //所属采集端口系统编号
	int napptype;                        //节点类型  1:mms 2:goose 3:9-2 5:1588 6：其他
	unsigned int nappid;                 //app_id
	char   ciedname[100];                //节点对应的ied名字
	char   cipaddress[20];               //节点IP地址
	char   cmacaddress[30];              //mac地址
	char   ccbname[MAX_NAME_LENGTH];    //控制块名称
	char   cdsname[MAX_NAME_LENGTH];    //数据集名称
	char   cgoid[MAX_NAME_LENGTH];      //GOOSE控制块ID
	char   csvid[MAX_NAME_LENGTH];      //SMV控制块ID
	int    nconfrev;                    //版本号
	int ndssize;                        //数据集中数据项个数
	int nmdatalistsize;                 //监视的信号量个数
	int nnofaudu;                       //单帧asdu个数
	int nsamprate;                      //采样频率
	int nmintime;                       //报文发送最小时间间隔，默认值为2毫秒
	int nmaxtime;                       //报文发送最大时间间隔，默认值为5000毫秒
	bool         bmonitor;              //是否进行监视
	float        flmtflowup;            //流量上限
	float        flmtflowdown;          //流量下限
	float        fRCT;                  //CT变比
	float        fRPT;                  //PT变比
	int          ntimeout;              //节点中断最大时间，单位为秒
	bool         bck_2ad;               //是否检查双AD
	SNIFFER_APP()
	{
		nsys_appsqe = 100;
		memset(cdesc,0,sizeof(cdesc));
		memset(cipaddress,0,sizeof(cipaddress));
		memset(cmacaddress,0,sizeof(cmacaddress));
		memset(cgoid,0,sizeof(cgoid));
		memset(csvid,0,sizeof(csvid));
		nconfrev = 0;
		snifferport_sys_id = 1;
		napptype    = 3;
		nappid      = 0;
		memset(ciedname,0,sizeof(ciedname));
		memset(ccbname,0,sizeof(ccbname));
		memset(cdsname,0,sizeof(cdsname));
		ndssize = 12;
		nnofaudu = 1;
		nsamprate = 4000;
		nmintime = 2;
		nmaxtime = 5000;
		bmonitor = 1;
		flmtflowup = 1.0f;
		flmtflowdown = 0.001f;
		fRPT = 350.0f;
		fRCT = 600.0f;
		nmdatalistsize = 12;
		ntimeout       = 60;
		bck_2ad        = false;
	}
}_SNIFFER_APP;

//网络数据捕捉器端口配置
typedef struct SNIFFER_PORT
{
	int ncard_portseq;                  //该端口在数据卡的编号，从1开始，目前最大值为6
	int nsys_portseq;                   //系统级别端口序号,全系统唯一，从1开始
	char cportname[MAX_DESCRIBE_LEN];   //端口名称
	int nusetype;                       //端口用途  1:mms数据采集 2:goose报文数据采集 3:9-2报文数据采集 4:9-1报文 5:1588对时报文  10; 混合报文
	int nsniffer_cardseq;               //数据捕捉器板卡的编号
	float flmtflowup;                     //端口流量上限，单位M字节
	float flmtflowdown;                   //端口流量下限，单位M字节
	int nstoragegroup;                  //采集数据存储组号，磁盘进行分组管理，共3组，本配置用以描述本端口采集到的数据存到哪一个组，本项值为1-3
	int nstoragegroup_slow;            //慢数据存储组号,描述GOOSE数据及其他数据的存储组号，本项值为1-3
	int nfilebufferlen_goose;	       //goose报文缓冲，单位M 
	int nfilebufferlen_other;	       //其它报文缓冲含SMV，单位M

	int nappnum_goose;
	SNIFFER_APP **plisthead_snifferapp_goose;

	int nappnum_smv;
	SNIFFER_APP **plisthead_snifferapp_smv;

	int nappnum_mms;
	SNIFFER_APP **plisthead_snifferapp_mms;
	
    SNIFFER_PORT()
	{
		ncard_portseq = 1;
		nsys_portseq  = 1;
		memset(cportname,0,sizeof(cportname));
		nusetype      = 1;
		flmtflowup    = 6.0f;
		flmtflowdown  = 0.1f;
		nstoragegroup     = 1;
		nstoragegroup_slow =2;
		nappnum_goose = 0;
		plisthead_snifferapp_goose = NULL;
		nappnum_smv = 0;
		plisthead_snifferapp_smv = NULL;
		nappnum_mms = 0;
		plisthead_snifferapp_mms = NULL;

		nfilebufferlen_goose  = 1;
		nfilebufferlen_other  = 1;
	}
}_SNIFFER_PORT;

//数据捕捉器板卡
typedef struct SNIFFER_CARD
{
	int  nsniffer_cardseq;               //该板卡在采集装置中的序号，要求唯一，从2开始编，范围2-7
	char ccardname[MAX_DESCRIBE_LEN];    //采集卡名称
	char mfcsn[64];                      //生产厂家编码，用于驱动加载等用途
	int  nportnum;                       //有效采集口个数(指接入系统中实际应用的个数)
	char cip1addr[WS_MAX_IP_LEN];         //采集板ip地址1
	char cip2addr[WS_MAX_IP_LEN];         //采集板ip地址2
	SNIFFER_PORT** plisthead_snifferport; //端口队列
	int  ndatasavemode;                   //数据存储方式，0:按端口存 1:按卡存 按卡存时，所有数据存到卡上已配置的第一个端口下
	SNIFFER_CARD()
	{
		nsniffer_cardseq = 1;
		memset(ccardname,0,sizeof(ccardname));
		memset(mfcsn,0,sizeof(mfcsn));
		memset(cip1addr,0,sizeof(cip1addr));//ip地址1
		memset(cip2addr,0,sizeof(cip2addr));//ip地址2
		nportnum = 0;
		plisthead_snifferport = NULL;
		ndatasavemode         = 0;
	}
}_SNIFFER_CARD;

//数据捕捉器
typedef struct SNIFFER
{
	int  nsys_seq;                           //捕捉器编号，系统中唯一，从1开始编写
	char csniffername[MAX_DESCRIBE_LEN];     //捕捉器名称
	int  ncardnum;                           //采集板卡个数
	SNIFFER_CARD** plisthead_sniffercard;    //采集板指针
	char cip1address[WS_MAX_IP_LEN];         //捕捉器IP地址1，用以系统组网
	char cip2address[WS_MAX_IP_LEN];         //捕捉器IP地址2，用以系统组网
	char cFtpUser[MAX_USER_PSWD_LEN];         //捕捉器ftp
	char cFtpPswd[MAX_USER_PSWD_LEN];         //捕捉器ftp
	int  nFtpPort;                            //捕捉器ftp
	SNIFFER()
	{
		nsys_seq = 1;
		memset(csniffername,0,sizeof(csniffername));
		ncardnum = 1;
		nFtpPort = 21;
		plisthead_sniffercard = NULL;
		memset(cip1address,0,sizeof(cip1address));
		memset(cip2address,0,sizeof(cip2address));
		strcpy(cFtpUser,"ftp");
		strcpy(cFtpPswd,"ftp");
	}
}_SNIFFER;
typedef struct SCANNER
{
	char csysname[MAX_DESCRIBE_LEN];     //系统名称 根据实际工程配置修改
	char csysdate[32];                   //配置文件生成时间yyyy-mm-dd hh-mm-ss
	char csysmaker[16];                  //配置文件生成人姓名
	char cnotes[MAX_DESCRIBE_LEN];       //备注说明
	int  nsniffernum;                    //记录装置个数,至少1个
	SNIFFER** plisthead_sniffer;         //记录装置首地址

	SCANNER()//初始化清空
	{
		memset(csysname,0,sizeof(csysname));
		memset(csysdate,0,sizeof(csysdate));
		memset(csysmaker,0,sizeof(csysmaker));
		memset(cnotes,0,sizeof(cnotes));
		nsniffernum  = 0;
		plisthead_sniffer= NULL;
	}
}_SCANNER;


//通通道结构定义
typedef struct CFG_REC_CHANNEL
{
	int  nsys_channelseq;                 //"id"通道编号，由本系统分配，全系统唯一编号，所有的通道需顺序编号，从1开始
	char cname[MAX_DESCRIBE_LEN];         //通道名称
	char cdesc[MAX_DESCRIBE_LEN];         //说明
	int  nsnifferport_sys_id;             //数据采集口对应的sys_id
	int  nchaneltype;                     //通道类别  0：模拟量通道 1：开关量通道
	char  cphase[5];                      //相别
	char  cunits[12];                     //单位
	int nTwinChannel;                    //双通道
	float fratio;                        //精度、单位整数对应的浮点值//应该不是变比ct或者pt
	float fratioSpec;                    //特殊倍率
	float fmin;                          //最小值
	float fmax;                          //最大值
	int  nstatus;                        //状态值 通道正常状态，常开：1 常闭：0  开关量通道时常用
	int  n61850_data_type;               //61850数据类型
	char c_scd_ref[MAX_DESCRIBE_LEN];    //61850参引
	int  n_sniffapp_sys_appseq;          //所属应用链路的序号
	int  n_index_in_list;               //在链路中通道队列中的位置
	//初始化
	CFG_REC_CHANNEL()
	{
		nsys_channelseq = 1;
		nsnifferport_sys_id = 0;
		fratio =1.0;
		fratioSpec = -1.0;
		nTwinChannel = -1;
		memset(cname,0,sizeof(cname));
		memset(cunits,0,sizeof(cunits));
		memset(cphase,0,sizeof(cphase));
		memset(cdesc,0,sizeof(cdesc));
		fmin = 0.0;
		fmax = 0.0;
		nchaneltype = 0;
		nstatus = 0;
		n61850_data_type = 999;
		memset(c_scd_ref,0,sizeof(c_scd_ref));
		n_sniffapp_sys_appseq = 0;
		n_index_in_list = 0;
	}
}_CFG_REC_CHANNEL;//通道

//应用节点通道定义
typedef struct _APP_CHANNEL_RELATION
{
	int n_sniffer_app_sys_id;
	int n_yc_channel_num;
	int n_yx_channel_num;
	CFG_REC_CHANNEL** pyc_channel_list;//遥测通道队列
	CFG_REC_CHANNEL** pyx_channel_list;//遥信通道队列

	int n_sys_yc_channel_num;             //系统自有的遥信个数
	int n_sys_yx_channel_num;             //系统自有的遥测个数

	CFG_REC_CHANNEL** pyc_sys_channel_list;//遥测通道队列_系统自有
	CFG_REC_CHANNEL** pyx_sys_channel_list;//遥信通道队列_系统自有

	_APP_CHANNEL_RELATION()
	{
		n_sniffer_app_sys_id = 0;
		n_yc_channel_num     = 0;
		n_yx_channel_num     = 0;
		pyc_channel_list     = NULL;
		pyx_channel_list     = NULL;
		n_sys_yc_channel_num = 0;
		n_sys_yx_channel_num = 0;
		pyc_sys_channel_list = NULL;
		pyx_sys_channel_list = NULL;
	}
}APP_CHANNEL_RELATION;

/**********虚端子结构************/
typedef struct TS_IED_EXTREF
{
	char c_iedname[32];    //iedname
	char c_apname[32];     //accesspoint
	char c_ldname[64];     //ld名称
	char c_lddesc[64];     //ld描述
	char c_intaddr[128];   //内部地址
	char c_intdesc[128];   //内部描述
	char c_iedname_ext[32];//输入IED名称
	char c_ldinst_ext[32]; //输入IED的LD
	char c_prefix_ext[32]; //输入LN的前缀
	char c_lnclass_ext[32];//输入的LN类型
	char c_lninst_ext[10]; //输入的LN实例号
	char c_doname_ext[32]; //输入的doname
	char c_daname_ext[64];//输入的daname 此属性为复数属性
	char c_outdesc_ext[128];//输入的外部描述
	void* pvoid;           //一个备用的指针
	TS_IED_EXTREF()
	{
		//内部属性
		memset(c_iedname,0,sizeof(c_iedname));
		memset(c_apname,0,sizeof(c_apname));
		memset(c_ldname,0,sizeof(c_ldname));
		memset(c_lddesc,0,sizeof(c_lddesc));
		memset(c_intaddr,0,sizeof(c_intaddr));
		memset(c_intdesc,0,sizeof(c_intdesc));
		//外部属性
		memset(c_iedname_ext,0,sizeof(c_iedname_ext));
		memset(c_ldinst_ext,0,sizeof(c_ldinst_ext));
		memset(c_prefix_ext,0,sizeof(c_prefix_ext));
		memset(c_lnclass_ext,0,sizeof(c_lnclass_ext));
		memset(c_lninst_ext,0,sizeof(c_lninst_ext));
		memset(c_doname_ext,0,sizeof(c_doname_ext));
		memset(c_daname_ext,0,sizeof(c_daname_ext));
		memset(c_outdesc_ext,0,sizeof(c_outdesc_ext));
		pvoid = NULL;
	}
}_TS_IED_EXTREF;
/**********虚端子关联关系************/
typedef struct TS_EXTREF_REC_CHANNE_RELATION
{
	TS_IED_EXTREF*         p_ts_ied_exref;       //输入通道的指针
	CFG_REC_CHANNEL*       p_cfg_channel;        //输出通道的指针                 
	TS_EXTREF_REC_CHANNE_RELATION()
	{
		p_ts_ied_exref = NULL;
		p_cfg_channel  = NULL;
	}
}_TS_EXTREF_REC_CHANNE_RELATION;
/**********链路输入输出管理表************/
//按链路进行管理
/*typedef struct TS_SNIFFER_APP_INOUT_MNGR
{
	SNIFFER_APP* p_sniffer_app;    //应用节点
	TS_EXTREF_REC_CHANNE_RELATION** p_ts_extref_rec_channel_relationlist;
	int n_relationlist_size;       //队列长度
	TS_SNIFFER_APP_INOUT_MNGR()
	{
		p_ts_extref_rec_channel_relationlist = NULL;
		p_sniffer_app = NULL;
		n_relationlist_size = 0;
	}
}_TS_SNIFFER_APP_INOUT_MNGR;*/
/**********装置输入输出管理表************/
/*struct TS_IED;
typedef struct TS_IED_INOUT_MNGR
{
	TS_IED* p_ts_ied;
	TS_SNIFFER_APP_INOUT_MNGR** p_ts_sniffer_app_inout_mngr_list;
	int n_inout_mngr_list_size;
	TS_IED_INOUT_MNGR()
	{
		p_ts_ied = NULL;
		p_ts_sniffer_app_inout_mngr_list = NULL;
		n_inout_mngr_list_size           = 0;
	}
}_TS_IED_INOUT_MNGR;*/
/**********智能终端结构************/
typedef struct TS_IED
{
	 char c_name[32];                    //名称，全站唯一
	 char c_desc[64];                    //描述
	 char c_manufacturer[64];            //生产厂家
	 char c_type[64];                    //型号
	 TS_IED_EXTREF** p_ts_ied_extreflist;//虚端子队列
	 int n_extreflist_size;              //虚端子个数
	 SNIFFER_APP** p_sniff_out_applist;     //IED下对应的输出链路
	 int n_snff_out_applist_size;         //IED下对应的输出链路个数
	 SNIFFER_APP** p_sniff_in_applist;     //IED下对应的输入链路
	 int n_snff_in_applist_size;         //IED下对应的输人链路个数
	 TS_EXTREF_REC_CHANNE_RELATION** p_ts_ied_in_relation_list;//有输出关联的ied列表
	 int  n_ts_ied_in_relation_list_size;//输入关联的ied的个数
	 TS_EXTREF_REC_CHANNE_RELATION** p_ts_ied_out_relation_list;//有输出关联的ied列表
	 int  n_ts_ied_out_relation_list_size;//输入关联的ied的个数
	 TS_IED()
	 {
		memset(c_name,0,sizeof(c_name));
		memset(c_desc,0,sizeof(c_desc));
		memset(c_manufacturer,0,sizeof(c_manufacturer));
		memset(c_type,0,sizeof(c_type));
		p_ts_ied_extreflist = NULL;
		n_extreflist_size = 0;
		p_sniff_out_applist = NULL;
		n_snff_out_applist_size = 0;
		p_sniff_in_applist  = NULL;
		n_snff_in_applist_size = 0;
		p_ts_ied_in_relation_list = NULL;
		n_ts_ied_in_relation_list_size = 0;
		p_ts_ied_out_relation_list = NULL;
		n_ts_ied_out_relation_list_size = 0;
	}
}_TS_IED;

#endif //SYS_MODEL_STRUCT_INCLUDED_00000000000
