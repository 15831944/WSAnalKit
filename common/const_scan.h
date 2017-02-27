#if !defined(CONST_SCAN_H_)
#define CONST_SCAN_H_

//using namespace std;???

/*********************************线程状态定义*************************/
/**	
* @brief	线程运行。
*/
const int	THREAD_STATE_RUN							= 1;

/**	
* @brief	线程暂停。
*/	
const int	THREAD_STATE_PAUSE							= 2;	

/**	
* @brief	线程停运。
*/	
const int	THREAD_STATE_STOP							= 3;	

/**	
* @brief	线程忙。
*/
const int	THREAD_STATE_BUSY							= 4;

/**	
* @brief	线程结束。
*/
const int	THREAD_STATE_END							= 5;

/**	
* @brief	线程错误。
*/
const int	THREAD_STATE_ERFROR							= 0;



const int	MAX_PACKET_LEN								= 1492;
// const int	MAX_PACKET_LEN								= 1520;//modifed 20130316



/*********************************字符常量*************************/

/**	
* @brief	路径符号单字节。
*/
#ifdef OS_WINDOWS
const char	PCHAR_PATH									='\\';
#else
const char	PCHAR_PATH									='/';
#endif

/**	
* @brief	路径符号字符串。
*/
#ifdef OS_WINDOWS
const char	PSTR_PATH[]									="\\";
#else
const char	PSTR_PATH[]									="/";
#endif


enum ETHER_TYPE
{
	IEC61850_ETHER_TYPE_UNKOWN  =0,
	IEC61850_ETHER_TYPE_MMS     =1,
	IEC61850_ETHER_TYPE_GOOSE   =2,
	IEC61850_ETHER_TYPE_SMV     =3,
	IEC61850_ETHER_TYPE_SMV_91  =4,
	IEC61850_ETHER_TYPE_PTP_1588=5,
	ETHER_TYPE_ARP              =6,
	ETHER_TYPE_IP               =7,
	ETHER_TYPE_TCP              =8,
	ETHER_TYPE_UDP              =9,
	ETHER_TYPE_COTP             =13,
	ETHER_TYPE_TCP_FIN			=14,//释放TCP链接 
	ETHER_TYPE_TCP_SYN_REQ		=15,//请求
	ETHER_TYPE_TCP_SYN_RESP  	=16,//接受链接
	ETHER_TYPE_TCP_RST			=17,//重置链接
	ETHER_TYPE_TCP_PSH			=18,//有应用数据，接收方需要尽快处理
	ETHER_TYPE_TCP_ACK			=19,//保持连接
	ETHER_TYPE_TCP_URG			=20,//紧急数据
	ETHER_TYPE_TPKT             =21,//add by yinzhehong 20130321
	ETHER_TYPE_DROP             =22,//add by guohuawen 20151010 //链路层丢弃报文
};	

#define MAX_FILE_NAME_LEN 255


enum UNIQUE_DEFINE
{
	UNIQUE_PKT_PER_SEC_NODE = 50,			//节点帧/s的unique
	UNIQUE_BYTE_PER_SEC_NODE = 51,			//节点字节/s的unique
	UNIQUE_PKTNUM_NODE = 52,				//节点总帧数的unique
	
	UNIQUE_PKT_PER_SEC_GOOSE_NODE = 100,	//端口下总goose节点帧/s的unique
	UNIQUE_BYTE_PER_SEC_GOOSE_NODE = 101,	//端口下总goose节点字节/s的unique
	UNIQUE_PKTNUM_NODE_GOOSE = 102,			//端口下总goose节点的总帧数的unique

	UNIQUE_COMMU_NODE = 1001				//节点通讯状态unique
};


//端口下事件ID号
enum PORT_EVENT_ID_DEFINE
{
	EVENT_ID_FILE_GENERATE = 1,						//文件生成
	EVENT_ID_SMV_NODE_ADD_ABRUPTLY = 2,				//SMV节点突增
	EVENT_ID_GOOSE_NODE_ADD_ABRUPTLY = 3,			//GOOSE节点突增
	EVENT_ID_NET_NODE_ADD_ABRUPTLY = 4,				//网络节点突增
	EVENT_ID_FRAME_DROP = 5,				        //链路层丢帧

	EVENT_ID_NET_STORM =100,						//网络风暴

	EVENT_ID_NODE_OVER_FLOWUP = 101,				//节点越上限
	EVENT_ID_NODE_OVER_FLOWDOWN = 102,				//节点越下限
	EVENT_ID_NODE_OVER_FLOW_COMEBACK = 103			//节点越限恢复



};

//SMV节点下事件ID号
enum SMV_NODE_EVENT_ID_DEFINE
{
	SMV_NODE_EVENT_ID_ASYNCHRONISM = 1,					//丢失同步信号 asynchronism
	SMV_NODE_EVENT_ID_DANUM_CHANGE,						//采样值个数变化
	SMV_NODE_EVENT_ID_DOUBLE_SMV,						//双SMV
	SMV_NODE_EVENT_ID_SMPCUNT_JUMP,						//丢帧
	SMV_NODE_EVENT_ID_SMPCUNT_REVERSE,					//乱序
	SMV_NODE_EVENT_ID_DELAY,							//延迟
	SMV_NODE_EVENT_ID_DISCONNECT,						//链路中断
	SMV_NODE_EVENT_ID_DATANUM_DIFFER_CFG ,				//数据个数和SCD中数据集成员个数不同
	SMV_NODE_EVENT_ID_QUALITY_ERROR,					//数据品质异常
	SMV_NODE_EVENT_ID_APPID_ZERO,						//APPID为0
	SMV_NODE_EVENT_ID_PDU_LEN_ERROR,					//PDU长度为0
	SMV_NODE_EVENT_ID_SVID_DIFFER_CFG,					//svID与配置不同
	SMV_NODE_EVENT_ID_DS_DIFFER_CFG,					//dataset名称与配置不同
	SMV_NODE_EVENT_ID_CONFREV_DIFFER_CFG,				//confRev与配置不同
	SMV_NODE_EVENT_ID_DESTMAC_ERROR,					//目的MAC地址错误
	SMV_NODE_EVENT_ID_CONNECT,							//链路恢复
	SMV_NODE_EVENT_ID_QUALITY_CHANGE,					//数据品质变化


	SMV_NODE_EVENT_ID_DOUBLE_AD_DATA_DIFFER,			//双AD数据不一致
	SMV_NODE_EVENT_ID_RATE_UNSTABLE,					//频率不稳定
	SMV_NODE_EVENT_ID_PORTMAT_ERR,						//报文格式错误



	SMV_NODE_EVENT_ID_NET_STORM =100,					//网络风暴
		
	SMV_NODE_EVENT_ID_NODE_OVER_FLOWUP = 101,			//节点越上限
	SMV_NODE_EVENT_ID_NODE_OVER_FLOWDOWN = 102,			//节点越下限
	SMV_NODE_EVENT_ID_NODE_OVER_FLOW_COMEBACK = 103		//节点越限恢复
	

};

enum GOOSE_NODE_EVENT_ID_DEFINE
{

	GOOSE_NODE_EVENT_ID_SQNUM_JUMP = 1,				//sqNum跳变
	GOOSE_NODE_EVENT_ID_SQNUM_REVERSE,				//sqNum逆转
	GOOSE_NODE_EVENT_ID_STNUM_JUMP,					//stNum跳变
	GOOSE_NODE_EVENT_ID_STNUM_REVERSE,				//stNum逆转
	GOOSE_NODE_EVENT_ID_SQNUM_UNRESET,				//Goose新事件sqNum未复归
	GOOSE_NODE_EVENT_ID_DOUBLE_GOOSE,				//双GOOSE
	GOOSE_NODE_EVENT_ID_REPEATED_GOOSE,				//重复GOOSE
	GOOSE_NODE_EVENT_ID_STNUM_CHANGE_FAKE,			//stNum虚假变位
	GOOSE_NODE_EVENT_ID_DELAY,						//延迟
	GOOSE_NODE_EVENT_ID_DISCONNECT,					//链路中断
	GOOSE_NODE_EVENT_ID_TAL_ERROR,					//TAL为0
	GOOSE_NODE_EVENT_ID_APPID_ZERO,					//APPID为0
	GOOSE_NODE_EVENT_ID_NDSCOM_TRUE,				//ndscom为true
	GOOSE_NODE_EVENT_ID_T_ERROR,					//T0~T3错误
	GOOSE_NODE_EVENT_ID_DANUM_DIFFER_CFG,			//实际数据个数与datset的成员数不一致
	GOOSE_NODE_EVENT_ID_GOCBREF_DIFFER_CFG,			//gocbRef与配置不一致
	GOOSE_NODE_EVENT_ID_GOID_DIFFER_CFG,			//goID与配置不一致
	GOOSE_NODE_EVENT_ID_DS_DIFFER_CFG,				//datset与配置不一致
	GOOSE_NODE_EVENT_ID_CONFREV_DIFFER_CFG,			//confrev与配置不一致

	//numDatSetEntries与与datset的成员数不一致
	GOOSE_NODE_EVENT_ID_NUMDATSETENTRIES_DIFFER_CFG,
	
	GOOSE_NODE_EVENT_ID_DESTMAC_ERROR,				//目的MAC地址错误
	GOOSE_NODE_EVENT_ID_RESTART,					//链路重启
	GOOSE_NODE_EVENT_ID_CONNECT,					//链路恢复连接
	GOOSE_NODE_EVENT_ID_STNUM_CHANGE_RIGHT,			//状态变位

	GOOSE_NODE_EVENT_ID_TEST_TRUE,					//GOOSE处于运行模式
	GOOSE_NODE_EVENT_ID_TEST_FALSE,					//GOOSE处于测试模式


	GOOSE_NODE_EVENT_ID_PORMAT_ERR,					//GOOSE格式错误
	GOOSE_NODE_EVENT_ID_APPID_CFG,					//链路未配置
	

	GOOSE_NODE_EVENT_ID_NET_STORM =100,				//网络风暴
	
	GOOSE_NODE_EVENT_ID_NODE_OVER_FLOWUP = 101,			//节点越上限
	GOOSE_NODE_EVENT_ID_NODE_OVER_FLOWDOWN = 102,		//节点越下限
	GOOSE_NODE_EVENT_ID_NODE_OVER_FLOW_COMEBACK = 103	//节点越限恢复


};

enum SMV_YK_ID
{
	SMV_YK_ID_GET_ORIGINAL = 1,							//获取原始数据
	SMV_YK_ID_GET_EFFECTIVE_VAL = 2,					//获取解析后的数据 
	SMV_YK_ID_GET_INSTANTANEOUS_VAL = 101,				//获取指定通道YC连续采样值_用于绘制实时曲线
	SMV_YK_ID_GET_MULTI_SMV_VAL = 102,					//获取同一时刻多个合并单元的最新数据（瞬时值、有效值、相角）
	SMV_YK_ID_GET_DISPERSION	= 103					//获取指定YC的离散度
};

enum GOOSE_YK_ID
{
	GOOSE_YK_ID_GET_ORIGINAL = 1,						//获取原始数据
	GOOSE_YK_ID_GET_EFFECTIVE_VAL = 2					//获取解析后的数据 
};


#define MAX_MAC_LEN 17+1
#define MAX_ARV_TIME_LEN 32+1

/**********************************add on 2013/03/28 报文解析结果**************************/
//Bit31:pakcet_len异常=0, Bit30:msg_len异常=0 , Bit15:nofasdu Bit14:sv_id Bit13:smpCnt Bit12:confRev Bit11:SmpSynch都为1 Bit7:sequence of data
#define DISSECT_SMV_RESULT_OK				0x0000F880	

#define DISSECT_SMV_PKTLEN_ERROR			0x80000000
#define DISSECT_SMV_MSGLEN_ERROR			0x40000000
#define DISSECT_SMV_ASDU_NUM_ZERO			0x20000000
//#define DISSECT_ETH_DROP			        0x10000000
//#define DISSECT_SMV_ETH_DROP			    DISSECT_ETH_DROP //0x10000000

#define DISSECT_SMV_NOFASDU_OK				0x00008000
#define DISSECT_SMV_SVID_OK					0x00004000
#define DISSECT_SMV_SMPCNT_OK				0x00002000
#define DISSECT_SMV_CONFREV_OK				0x00001000
#define DISSECT_SMV_SMPSYNCH_OK				0x00000800

#define DISSECT_SMV_DATASET_OK				0x00000400
#define DISSECT_SMV_REFRTM_OK				0x00000200
#define DISSECT_SMV_SMPRATE_OK				0x00000100
#define DISSECT_SMV_SEQUENCEOFDATA_OK		0x00000080
#define DISSECT_SMV_INVALID_FIELD_VAL		0x00000040

	
//Bit31:packet_len异常=0，Bit30:msg_len异常=0
//Bit23:PDU头的tag正确=1，Bit22:gocbRef, Bit21:timeAllowed Bit20:dataSet Bit19:T Bit18:stNum Bit17:sqNum Bit16:test Bit15:confRev Bit14:ndsCom Bit13:numDataSetEntries都为1
#define DISSECT_GOOSE_RESULT_OK				0x00FFE000

#define DISSECT_GOOSE_PKTLEN_ERROR			0x80000000
#define DISSECT_GOOSE_MSGLEN_ERROR			0x40000000
//#define DISSECT_GOOSE_ETH_DROP             DISSECT_ETH_DROP			//0x10000000

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
#define DISSECT_GOOSE_GOID_OK				0x00000800
//#define DISSECT_GOOSE_INVALID_FIELD_VAL		0x00000040
/*****************************************************************************************/

/********************************PTP事件定义**********************************************///add on 2013/03/31
enum
{
	EVENT_ID_PTP_DISCONNECT			= 10000,//PTP链路中断
	EVENT_ID_PTP_CONNECT			= 10001,//PTP链路恢复
	EVENT_ID_PTP_SYNC_DELAY			= 10002,//PTP同步报文超时
	EVENT_ID_PTP_DELAY_RESP_DELAY	= 10003,//PTP的delay请求响应超时
	EVENT_ID_PTP_PDELAY_RESP_DELAY	= 10004,//PTP的pdelay请求响应超时
	EVENT_ID_PTP_CF_OVERLMT			= 10005,//PTP报文CF域差越限
	EVENT_ID_PTP_SYNC_DISC			= 10006,//PTP同步报文中断
	EVENT_ID_PTP_DELAY_RESP_DISC	= 10007,//PTP的delay请求响应中断
	EVENT_ID_PTP_PDELAY_RESP_DISC	= 10008//PTP的pdelay请求响应中断
};


#endif //CONST_SCAN_H_