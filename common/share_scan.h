#ifndef SHARE_SCAN_H
#define SHARE_SCAN_H

#include "define_scan.h"
#include "const_scan.h"

typedef struct _PORT_ATTRIBUTE_STRUCT
{
	int n_port;//端口号

	int n_max_flow;//网络流量最大值

	int n_min_fow;//网络流量最小值

	_PORT_ATTRIBUTE_STRUCT()
	{
		n_port = 0;
		n_max_flow = 0;
		n_min_fow = 0;
	}

}PORT_ATTRIBUTE_STRUCT;

typedef struct _ANALYZEONLINE_RUN_PARAM_STRUCT
{
	//端口属性结构数组首地址
	PORT_ATTRIBUTE_STRUCT *p_port_attribute;

	//端口个数
	int n_port_nums;

	//日志路径
	char cLogPath[256];

	//日志级别
	int nLogLevel;

	//日志文件的最大长度：单位K
	int nLogMaxLen;

	//采样值报文延迟的时间间隔
	double dTimeSmvdelay;

	//采样值断链的时间间隔
	double dTimeSmvLinkDisconnected;

	//流量统计的时间间隔
	int nNetstatTimeInterval;

	//在线分析类型，1表示只分析GOOSE，2表示只分析SMV，3表示只分析MMS，4表示分析GOOSE和SMV，5表示分析GOOSE和MMS，6表示分析SMV和MMS，7表示分析GOOSE、SMV、MMS
	int n_ao_type;

	//保留报文的数据类型
	int n_reserve_da_type;

	_ANALYZEONLINE_RUN_PARAM_STRUCT()
	{
		n_port_nums = 0;
		p_port_attribute = NULL;
		memset(&cLogPath,0,256);
		nLogLevel = 0;
		nLogMaxLen = 0;
		dTimeSmvdelay = 60;
		dTimeSmvLinkDisconnected = 300;
		nNetstatTimeInterval = 3;
		n_ao_type = 0;
		n_reserve_da_type = 0;
	}
	

}ANALYZEONLINE_RUN_PARAM_STRUCT;

//原始报文用char数组表示的结构
typedef struct _PACKET_CHAR_STRUCT
{
	char c_pacekt[MAX_PACKET_LEN+1];

	//单帧实际报文长度
	int nLen;

	_PACKET_CHAR_STRUCT()
	{
		memset(&c_pacekt,0,sizeof(c_pacekt));
		nLen = 0;
	}

}PACKET_CHAR_STRUCT;


typedef struct _LOG_STRUCT
{
	//日志路径
	char cLogPath[256];

	//日志级别
	int nLogLevel;

	//日志文件的最大长度：单位K
	int nLogMaxLen;

	_LOG_STRUCT()
	{
		memset(&cLogPath,0,256);
		nLogLevel = 0;
		nLogMaxLen = 0;
	}

}LOG_STRUCT;

typedef struct _TCP_STRUCT
{
	//源端口
	int n_srcport;

	//目的端口
	int n_dstport;

	//序号
	unsigned int n_seq;

	//确认好
	unsigned int n_ack;

	unsigned char c_flag;

	_TCP_STRUCT()
	{
		n_srcport=0;
		n_dstport=0;
		n_seq=0;
		n_ack=0;
		c_flag=0;
	}
}TCP_STRUCT;

//IP报文结构
typedef struct _IP_STRUCT
{
	//IP包头长度
	int n_headerlen;

	//源IP
	char c_srcip[20];

	//目的IP
	char c_dstip[20];

	TCP_STRUCT tcp_info;

	_IP_STRUCT()
	{
		n_headerlen=0;
		memset(c_srcip, 0, sizeof(c_srcip));
		memset(c_dstip, 0, sizeof(c_dstip));
	}

}IP_STRUCT;

#endif //SHARE_SCAN_H