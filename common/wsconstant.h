#if !defined(_WSCONST_H)
#define _WSCONST_H

//定义全局宏
//***************配置文件部分*********************************************************//
#define WSANALYZER_CONFIG_FILE	   "wsanalyzer_config.xml"               //程序系统配置
#define WSANALYZER_NAMESPACE_FILE   "wsanalyzer_namespace.xml"           //名称空间解析配置
#define WSANALYZER__ERRORCODE_FILE  "wsanalyzer_error_code.xml"          //错误码表
///////////////////////////////////////////////////////////////////////////////////////

//常量定义
const  int MAX_CHAR_LENTH = 254 ;                                        //字符最大长度
//常量定义-协议类型
const int PROTOAPPTYPE_UNKOWN       = -1;//未知协议
const int PROTOAPPTYPE_OTHER		= 0; //其他协议
const int PROTOAPPTYPE_MMS			= 1; //MMS
const int PROTOAPPTYPE_GOOSE		= 2; //GOOSE
const int PROTOAPPTYPE_SMV92		= 3; //SMV92
const int PROTOAPPTYPE_SMV91		= 4; //SMV91
const int PROTOAPPTYPE_TIME1588     = 5; //1588对时报文
const int PROTOAPPTYPE_ARP          = 6; //ARP报文
const int PROTOAPPTYPE_IP           = 7; //IP报文
const int PROTOAPPTYPE_TCP          = 8; //TCP报文
const int PROTOAPPTYPE_UDP         = 9; //UDP
const int PROTOAPPTYPE_MIX		    = 10; //混合
const int PROTOAPPTYPE_IGMP         = 11; //互联网组网消息协议
const int PROTOAPPTYPE_LLDP         = 12; //链路层发现协议
const int PROTOAPPTYPE_COTP         = 13; //COPT协议
const int PROTOAPPTYPE_TPKT         = 21; //TPKT协议
const int PROTOAPPTYPE_DROP         = 22; //ETHER_TYPE_DROP
const int PROTOAPPTYPE_DESC         = 97; //内容描述
const int PROTOAPPTYPE_TOTAL        = 98;//全部协议
const int PROTOAPPTYPE_ERROR        = 99; //错误报文链路
const int PROTOAPPTYPE_EVENT        = 100; //事件报文链路
//常量定义-文件解析格式
const int CAP_PARSER_TXT_ALL         = 0;
const int CAP_PARSER_TXT_61850       = 1;

//***************界面部分***********************************************************//
//文件解析文档通知视图
const int CAPLOAD_PARSERFILE_PARSER_BRIEF_OK   = 0x0101; //生成概要文件成功
const int CAPLOAD_PARSERFILE_PARSER_BRIEF_FAIL = 0x0102; //生成概要文件失败

const int CAPLOAD_PARSERFILE_LOAD_BRIEF_OK     = 0x0103; //加载概要文件成功
const int CAPLOAD_PARSERFILE_LOAD_BRIEF_FAIL   = 0x0104; //加载概要文件失败

const int CAPLOAD_PARSERFILE_PARSER_DETAIL_OK  =  0x0105; //生成详细文件成功
const int CAPLOAD_PARSERFILE_PARSER_DETAIL_FAIL = 0x0106; //生成详细文件失败

const int CAPLOAD_PARSERFILE_LOAD_DETAIL_OK    =  0x0107; //加载详细文件成功
const int CAPLOAD_PARSERFILE_LOAD_DETAIL_FAIL  =  0x0108; //加载详细文件失败

const int CAPLOAD_PARSERFILE_ANALYZER_NET_OK    = 0x0109; //完成链路分析成功
const int CAPLOAD_PARSERFILE_ANALYZER_NET_FAIL  = 0x0110;//完成链路分析失败
const int CAPLOAD_PARSERFILE_ANALYZER_NET_SHOW  = 0x00111;//指定链路显示通知

const int CAPSHOW_DATATYE_ALL                   = 0;//全部数据
const int CAPSHOW_DATATYE_ALARM                 = 1;//告警数据
const int CAPSHOW_DATATYE_EVENT                 = 2;//事件数据

//向主框架发送的消息
#define	WM_WS_WRITELOG				WM_USER + 1001        //写日志
#define WM_WS_SHOWMSG				WM_USER + 1002        //显示解析后的消息
#define WM_WS_SHWOORIN              WM_USER + 1003        //显示原始的消息    
//////////////////////////////////////////////////////////////////////////////////

/*******************SMV分析定值*********************************/
#define SETTING_SMV_DELAY						0X00000001				//延迟
#define SETTING_SMV_APPID_ZERO					0X00000002				//APPID为零
#define SETTING_SMV_PDULEN_ZERO					0X00000004				//PDU长度为零
#define SETTING_SMV_DESTMAC_ERR					0X00000008				//目的MAC地址错误
#define SETTING_SMV_MAC_DIFFER_CFG				0X00000010				//目的MAC地址与配置不一致
#define SETTING_SMV_FORMAT_ERR					0X00000020				//格式错误
#define SETTING_SMV_ASDU_DIFFER_CFG				0X00000040				//ASDU个数与配置不一致
#define SETTING_SMV_TREMBLE						0X00000080				//抖动
#define SETTING_SMV_RATE_UNSTABLE				0X00000100				//频率不稳定
#define SETTING_SMV_DOUBLE						0X00000200				//双SMV
#define SETTING_SMV_SMPCNT_JUMP					0X00000400				//序号跳变
#define SETTING_SMV_SMPCNT_REVERSE				0X00000800				//序号逆转
#define SETTING_SMV_ASYNCHRONISM				0X00001000				//丢失同步信号
#define SETTING_SMV_DANUM_DIFFER_DSMEMBERNUM	0X00002000				//通道数与配置不一致
#define SETTING_SMV_DS_DIFFER_CFG				0X00004000				//ds与配置不一致
#define SETTING_SMV_SVID_DIFFER_CFG				0X00008000				//svID与配置不一致
#define SETTING_SMV_CONFREV_DIFFER_CFG			0X00010000				//confRev与配置不一致
#define SETTING_SMV_DROP_PKT					0X00020000				//丢帧
#define SETTING_SMV_DELAY_TR_TG_CHANGE			0X00040000				//通道延时变化
///////////////#define SETTING_SMV_DELAY						0X00040000				//延迟
#define SETTING_SMV_QUALITY_CHANGE				0X00080000				//SMV数据品质变化
#define SETTING_SMV_DA_ERR						0X00100000				//数据异常
#define SETTING_SMV_DOUBLE_AD_DATA_DIFFER		0X00200000				//双AD数据不一致
#define SETTING_SMV_TEST						0X00400000				//置检修标志
#define SETTING_SMV_RESERVE1					0X00800000				//无效的数据值SETTING_SMV_INVALID_FIELD_VAL
#define SETTING_SMV_INVALID_FIELD_VAL           SETTING_SMV_RESERVE1
#define SETTING_SMV_RESERVE2					0X01000000	
#define SETTING_SMV_RESYNCHRON 					SETTING_SMV_RESERVE2	 //同步恢复
#define SETTING_SMV_RESERVE3					0X02000000
#define SETTING_SMV_RESERVE4					0X04000000
#define SETTING_SMV_RESERVE5					0X08000000
#define SETTING_SMV_RESERVE6					0X10000000
#define SETTING_SMV_RESERVE7					0X20000000
#define SETTING_SMV_RESERVE8					0X40000000
#define SETTING_SMV_RESERVE9					0X80000000

/*************************GOOSE分析定值**********************/
#define SETTING_GOOSE_SQNUM_JUMP				0X00000001//sqNum跳变
#define SETTING_GOOSE_SQNUM_REVERSE				0X00000002//sqNum逆转
#define SETTING_GOOSE_STNUM_JUMP				0X00000004//stNum跳变		
#define SETTING_GOOSE_STNUM_REVERSE				0X00000008//stNum逆转
#define SETTING_GOOSE_SQNUM_UNRESET				0X00000010//stNum变化,sqNum未复归
#define SETTING_GOOSE_GOOSE_DOUBLE				0X00000020//重复帧
#define SETTING_GOOSE_GOOSE_REPEAT				0X00000040//内容完全重复
#define SETTING_GOOSE_STNUMCHANGE_FAKE			0X00000080//stNum虚变
#define SETTING_GOOSE_GOOSE_DELAY				0X00000100//报文延迟
#define SETTING_GOOSE_TAL_ZERO					0X00000200//TAL为零
#define SETTING_GOOSE_APPID_ZERO				0X00000400//APPID为零
#define SETTING_GOOSE_NDSCOMM_TRUE				0X00000800//控制块需要配置
#define SETTING_GOOSE_T0_T3_ERR					0X00001000//发送机制错误
#define SETTING_GOOSE_DANUM_DIFFER_DSMEMBERNUM	0X00002000//通道个数与配置不一致
#define SETTING_GOOSE_GOCBREF_DIFFER_CFG		0X00004000//gocbref与配置不一致
#define SETTING_GOOSE_GOID_DIFFER_CFG			0X00008000//goid与配置不一致
#define SETTING_GOOSE_DS_DIFFER_CFG				0X00010000//dsname与配置不一致
#define SETTING_GOOSE_CONFREV_DIFFER_CFG		0X00020000//版本号与配置不一致
#define SETTING_GOOSE_DAENTRIES_DIFFER_DANUM	0X00040000//numDataEntries与实际数据个数不一致
#define SETTING_GOOSE_DESTMAC_ERR				0X00080000//目的MAC地址错误
#define SETTING_GOOSE_GOOSE_RESTART				0X00100000//GOOSE链路重启
#define SETTING_GOOSE_STNUMCHANGE_RIGHT			0X00200000//GOOSE变位
#define SETTING_GOOSE_TEST_TRUE					0X00400000//置检修标志
#define SETTING_GOOSE_FORMAT_ERR				0X00800000//格式错误
#define SETTING_GOOSE_MAC_DIFFER_CFG			0X01000000//目的MAC地址与配置不一致
#define SETTING_GOOSE_DATYPE_DIFFER_CFG			0X02000000//数据类型与配置文件不一致
#define SETTING_GOOSE_GOOSE_DROP				0X04000000//丢帧
#define SETTING_GOOSE_GOOSE_THEMBLE				0X08000000//心跳报文抖动
#define SETTING_GOOSE_RESERVE1					0X10000000
#define SETTING_GOOSE_RESERVE2					0X20000000
#define SETTING_GOOSE_RESERVE3					0X40000000
#define SETTING_GOOSE_RESERVE4					0X80000000

#endif
