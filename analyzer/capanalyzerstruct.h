#if !defined(_WSCAPANALYZERSTRUCT_H)
#define _WSCAPANALYZERSTRUCT_H

//分析文件头文件定义
//#include "tinyxml.h"
#include <map>
#include <memory.h>
//#include "AT_STRUCT.h"
//#include "AnalyzeOnline_STRUCT.h"	//在线解析报文头文件结构，用于GOOSE和采样报文在线解析
#include "Scan_Dissect_Pkt_Struct.h"//报文解析结构
/*----------------概要分析结构-----------------------------------------------*/

//结构定义 解析完成后的文件概要，一般为统计信息
typedef struct CAPPARSERINFO
{
	char cparserfilename[256];    //cap文件名称
	char crecoriedname[64];        //记录装置
	char crecorportname[64];       //记录端口名称
	int  crecordframetype;         //记录数据类型：使用同应用报文类型
	int  napppackages;             //记录总包数
	int  nappmmspackages;          //mms包数
	int  nappgoosepackages;        //goose包数
	int  napp92packages;           //9-2包数
	int  napp91packages;           //9-1包数
	int  napparppackages;          //arp包数
    int  nappbroadcastpackages;    //广播包数目
	int  nappotherpackages;        //其它应用包
	int  nconnects;                 //有效连接数：指两个ied之间存在61850报文交互，含广播
	char cstarttimestamp[64];       //录开始时间   1970年以后的秒 含毫秒
	char cendtimestamp[64];         //记录结束时间   1970年以后的秒 含毫秒
	unsigned long   lTotalCapLenth; //本文件字节数
	double ftime_lastpk_2_first;      //最后一帧报文与采样文件中第一帧的时间差
	int ntime1588packages;           //1588
	int  napptcppackages;          //TCP
	int  nappudppackages;          //UDP
	//初始化
	CAPPARSERINFO()
	{
		memset(cparserfilename,'\0',sizeof(cparserfilename));
		memset(crecoriedname,'\0',sizeof(crecoriedname));
		memset(crecorportname,'\0',sizeof(crecorportname));
		crecordframetype      = 10;//混合
		napppackages          = 0;
		nappmmspackages       = 0;
		nappgoosepackages     = 0;
		napp92packages        = 0;
		napp91packages        = 0;
		napparppackages       = 0;
		nappbroadcastpackages = 0;
		nappotherpackages     = 0;
		ntime1588packages     = 0;
		napptcppackages       = 0;
		nappudppackages       = 0;
		nconnects             = 0;
		memset(cstarttimestamp,'\0',sizeof(cstarttimestamp));
		memset(cendtimestamp,'\0',sizeof(cendtimestamp));
		lTotalCapLenth = 0;
		ftime_lastpk_2_first = 0.0;
	}
}_CAPPARSERINFO;

struct CAPMSGGININFO;

//列表定义
typedef std::map <int, CAPMSGGININFO*>	MAP_CAPMSGINFO;          //信息包包头
//结构定义 报文解析概要描述，针对每一个报文
typedef struct CAPMSGGININFO
{
	CAPMSGGININFO*               pPreCapMsg; //同一链路中的上一帧
	void*                        pcapconnect; //报文所属链路，因为报文结构没有声明，存一个void*指针

	int nseq;                           //编号，界面自用
	int nnum;                           //在文件中的记录序号
	int  nlen;					        //报文长度
	int  ncap_len;				        //报文记录长度
	char*           csourceinfo;        //原始数据
	int             nsourceinfo_length; //原始数据长度
	unsigned int    nseconds_utc_tmstamp;//报文时标戳，1970年后的秒
	unsigned int    nus_tmstamp;         //报文时标戳  nseconds_utc_tmstamp.微秒  
	double ftime_delta;            //与上一帧报文的时间差 1970年以后的秒 含毫秒
	double ftime_delta_capconnect; //本链路中与上一帧的时间差 1970年以后的秒 含毫秒
	double ftime_relative;          //与记录文件中的第一帧报文或者基准时间的时间差,单位毫秒
	double ftime_relative_capconnect;//与本链路中的第一帧报文或者基准时间的时间差,单位毫秒
	char csrc_mac[32];         //报文发送端mac地址符 00:1f:16:24:f2:0c
	char cdst_mac[32];            //报文接收端mac地址
	int nsrc_port;               //报文发送端口号
	int ndst_port;               //报文接收端口号
	int  napptype;				  //应用层报文类型 mms=1,goose=2,9-2=3,9-1=4,其它=0，在常量中预定义
	int napptpye_type;           //应用层报文细分的类型，比如MMS的服务类型等
	                              //如果值为0x88ba 择为采样
	int napp_id;			      //smv、goose的应用编号
	char csrc_ip[18];             //报文发送端ip地址符  100.100.150.103
	char cdst_ip[18];             //报文接收端ip地址
	char ccontent[128];			  //报文概要内容：待定
	int nHeadChkgood;			  //报文头校验是否正确，1：正确 0：异常
	int  nAppConetentGood;        //应用层报文是否正确 1：标识正确 0：异常
//	char ciedname[64];            //报文对应的ied的名字
	void*          pparserdstruct;          //应用数据桢解析后的详细帧
	void*           pap_analyzed_info;       //报文分析结果
	void*           pap_anlyzed_info_connect;//报文分析上下文
	bool            berroranalyzedgoose;     //GOOSE错误
	bool            beventanalyzedgoose;     //GOOSE事件、MMS中的报告
	bool            berroranalyzedsmv;       //SMV错误
	bool            berroranalyzedmms;       //MMS错误
	bool            berroranalyzed;     //GOOSE错误
	bool            beventanalyzed;     //GOOSE事件、MMS中的报告
	int             n1588seqid;			     //1588中的序号
	int             n1588portid;		      //1588中的端口号
	XJ_DISSECT_PKT* pxj_dissect_pkt;          //解析后的数据包
	bool            blastcotpunit;            //多帧传输的最后一帧  add by yinzhehong 20130315
	bool            btcppsh;                 //TCP是否有应用报文传输
	MAP_CAPMSGINFO  map_cotplist;            //多帧传输时队列
	char*           csourceinfo_cotp;        //多帧报文传输时大长帧
	int             nsourceinfo_cotp_length; //多帧报文传输时大长帧长度
	unsigned int    npkt_offset_incapfile;   //报文在文件中的位置
	//初始化
	CAPMSGGININFO()
	{
		pPreCapMsg    = NULL;
		n1588portid   = 0;
		n1588seqid    = 0;
		pcapconnect   = NULL;
		nseq          = 0;
		nnum          = -1;
		nlen          = 0;
		ncap_len      = 0;
		napp_id       = -1;
		ftime_relative = 0.0;
		ftime_relative_capconnect = 0.0;
		ftime_delta    = 0.0;
		ftime_delta_capconnect = 0.0;
		memset(csrc_mac,'\0',sizeof(csrc_mac));
		memset(cdst_mac,'\0',sizeof(cdst_mac));

		nsrc_port     = 0;
		ndst_port     = 0;
		napptype      = 0;
		napptpye_type = 0;
		memset(csrc_ip,'\0',sizeof(csrc_ip));
		memset(cdst_ip,'\0',sizeof(cdst_ip));

		memset(ccontent,'\0',sizeof(ccontent));
		nHeadChkgood         = 1;
		nAppConetentGood     = 1;
//		memset(ciedname,'\0',sizeof(ciedname));
		pparserdstruct  = NULL;
		pap_analyzed_info     = NULL;
		pap_anlyzed_info_connect = NULL;
		berroranalyzedgoose = false;
		berroranalyzedsmv	= false;
		berroranalyzedmms	= false;
		berroranalyzed      = false;
		beventanalyzed      = false;
		csourceinfo         = NULL;
		nsourceinfo_length  = 0;
		pxj_dissect_pkt     = NULL;
		blastcotpunit       = false;
		btcppsh             = false;
	    csourceinfo_cotp    = NULL;
	    nsourceinfo_cotp_length = 0;
		beventanalyzedgoose = false;
		nseconds_utc_tmstamp = 0;
		nus_tmstamp          = 0;
		npkt_offset_incapfile= 0;
	}
}_CAPMSGGININFO;


//通通道结构定义
typedef struct WS_CHANNEL
{
	int  nsys_channelseq;                 //通道编号，由本系统分配，全系统唯一编号，所有的通道需顺序编号，从1开始
	char cname[128];         //通道名称
	char cdesc[128];         //说明
	int  nsnifferport_sys_id;             //数据采集口对应的sys_id
	int  nchaneltype;                     //通道类别  0：模拟量通道 1：开关量通道

	float fa;                            //通道增益系数
	float fb;                            //偏移量
	char  cunits[12];                    //单位
	float fratio;                        //变比ct或者pt
	char ccbm[64];                       //被监视的设备
	char cphase[4];                      //相别 A、B、C、N
	float fmin;                          //最小值
	float fmax;                          //最大值
	int  nstatus;                        //状态值 通道正常状态，常开：1 常闭：0  开关量通道时常用
	//初始化
	WS_CHANNEL()
	{
		nsys_channelseq = 1;
		nsnifferport_sys_id = 0;
		fa = 1.0;
		fb = 0.0;
		fratio =1.0;
		memset(cname,0,sizeof(cname));
		memset(cunits,0,sizeof(cunits));
		memset(ccbm,0,sizeof(ccbm));
		memset(cphase,0,sizeof(cphase));
		fmin = 0.0;
		fmax = 0.0;
		nchaneltype = 0;
		nstatus = 0;
	}
}_WS_CHANNEL;//通道

typedef std::map <int, WS_CHANNEL*>	MAP_CHANNEL_INFO;      //通道链路map表 int 为通道序号 WS_CHANNEL为通道内容

//时间均匀度统计
typedef struct CH_TIME_RELATIVE_LAST_STATIC
{
	int n0us;
	int n1us;          //与标准时间250us差小于10us数据包帧数
	int n2us;          
	int n3us;
	int n4us;
	int n5us;
	int n6us;
	int n7us;
	int n8us;
	int n9us;
	int n10us;
	int nup11us;
	int neg_n1us;
	int neg_n2us;          
	int neg_n3us;
	int neg_n4us;
	int neg_n5us;
	int neg_n6us;
	int neg_n7us;
	int neg_n8us;
	int neg_n9us;
	int neg_n10us;
	int neg_nup11us;

	int n4to10us;
	int n11to25us;
	int n25tous;
	CH_TIME_RELATIVE_LAST_STATIC()
	{
		n0us        = 0;
		n1us        = 0;
		n2us        = 0;
		n3us        = 0;
		n4us        = 0;
		n5us        = 0;
		n6us        = 0;
		n7us        = 0;
		n8us        = 0;
		n9us        = 0;
		n10us        = 0;
		nup11us        = 0;
		neg_n1us        = 0;
		neg_n2us        = 0;          
		neg_n3us        = 0;
		neg_n4us        = 0;
		neg_n5us        = 0;
		neg_n6us        = 0;
		neg_n7us        = 0;
		neg_n8us        = 0;
		neg_n9us        = 0;
		neg_n10us        = 0;
		neg_nup11us        = 0;
		n4to10us    = 0;
		n11to25us    = 0;
		n25tous    = 0;
	}
}_CH_TIME_RELATIVE_LAST_STATIC;

//结构定义：连接数：描述
typedef struct CAPCONNECTINFO
{
	int  nusetype;                   //用途类型 0:各种实际连接   1：全部报文链接  2：按类型放置的链接 3：查询后形成的链接
	int  nseq;                       //连接编号
	int  ncapp_id;                   //smv、goose的应用编号,现场发现所有的合并单元的MAC地址相同,动土交换机能兼容,mac地址不能作为链路的唯一判据
	char csrc1_mac[32];              //发送端1mac地址符 00:1f:16:24:f2:0c
	char csrc1_ip[32];               //发送端1ip地址符  100.100.150.103
	char csrc2_mac[32];              //发送端2mac地址
	char csrc2_ip[32];               //发送端2ip地址
	int nsrc1_port;				     //发送端1口号	
	int nsrc2_port;				     //发送端2端口号
	int nsrc1packages;               //发送端1总发送帧数
	int nsrc2packages;               //发送端2总发送帧数
	char cstarttimestamp[64];          //帧开始时间   长时间格式
	char cendtimestamp[64];            //帧结束时间   长时间格式
	double ftime_relative_first;         //第一帧报文与采样与采样文件中第一帧的时间差
	double ftime_relative_last;         //最后一帧报文与采样文件中第一帧的时间差
	int nconnectapptype;               //连接应用类型  默认同头文件
	_CAPPARSERINFO*   pcapparserinfo;//链路所属文件概要说明
	MAP_CAPMSGINFO    map_capmsginfo;//链路所拥有的报文队列
	MAP_CHANNEL_INFO  map_channelinfo;//链路所对应的通道结构,顺序排列
	CH_TIME_RELATIVE_LAST_STATIC   m_tRelastStatic; //本链路时间均匀度统计
	unsigned long   lTotalCapLenth;                 //本连接字节数
	int nerrpackages;                               //本链路有错误的包数
	int neventpackages;                             //本链路告警总包数
	MAP_CAPMSGINFO    map_capmsginfo_error;              //本链路错误报文链路
	MAP_CAPMSGINFO    map_capmsginfo_event;              //本链路告警报文链路
//	MAP_CAPMSGINFO    map_capmsginfo_sr1_2_sr2;    //链路报文 从src1--》sr2;
//	MAP_CAPMSGINFO    map_capmsginfo_sr2_2_sr1;    //链路报文 从src2--》sr1;
	MAP_CAPMSGINFO    map_capmsginfo_filter;       //根据条件查询出来的报文
	//初始化
	CAPCONNECTINFO()
	{
		nusetype = 0;
		nseq = 0;
		ncapp_id = -1;
		memset(csrc1_mac,'\0',sizeof(csrc1_mac));
		memset(csrc1_ip,'\0',sizeof(csrc1_ip));
		memset(csrc2_mac,'\0',sizeof(csrc2_mac));
		memset(csrc2_ip,'\0',sizeof(csrc2_ip));
		nsrc1_port        = 0;
		nsrc2_port        = 0;
		nsrc1packages	  = 0;
		nsrc2packages	  = 0;
		memset(cstarttimestamp,'\0',sizeof(cstarttimestamp));
		memset(cendtimestamp,'\0',sizeof(cendtimestamp));
		nconnectapptype   = 0;
		pcapparserinfo    = NULL;
		ftime_relative_first = 0.0f;
		ftime_relative_last  = 0.0f;
		lTotalCapLenth       = 0;
		nerrpackages = 0;
		neventpackages = 0;
	}
}_CAPCONNECTINFO;
typedef std::map <int, CAPCONNECTINFO*>	MAP_CAPCONNECTINFO;      //链路map表

typedef struct PACKETQUER_FILTER
{
	int nfilter_type;               //查询类别  
									//          0: 根据发送IP地址模糊查询
									//          1: 根据目的IP地址模糊查询
									//          2: 根据发送端和目的IP地址模糊查询
	                                //          3：根据发送MAC地址模糊查询
	                                //          4: 根据目的MAC地址模糊查询
	                                //          5: 根据发送以及目的MAC地址模糊查询
	                                //          6：根据MMS报文的应用类型查询，比如：报告，关联，等等
    int nfliter_apptype;            //报文应用类型：根据报文查询条件设定对应的报文应用值
	char c_filter_appword[128];     //文字查询条件，用于模糊匹配
	PACKETQUER_FILTER()
	{
		nfliter_apptype = 1;
		memset(c_filter_appword,0,128);
	}
}_PACKETQUER_FILTER;
/*--------------------------------------------------------------------------------------*/


#endif
