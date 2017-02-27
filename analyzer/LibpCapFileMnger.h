#pragma once
#include <map>
#include <string>
using  std::string;

#define	PCAP_MAGIC			0xa1b2c3d4
#define	PCAP_SWAPPED_MAGIC		0xd4c3b2a1
#define	PCAP_MODIFIED_MAGIC		0xa1b2cd34
#define	PCAP_SWAPPED_MODIFIED_MAGIC	0x34cdb2a1
#define	PCAP_NSEC_MAGIC			0xa1b23c4d
#define	PCAP_SWAPPED_NSEC_MAGIC		0x4d3cb2a1
/* "libpcap" 文件头 */
typedef struct _TS_PCAP_HEADER {
	unsigned int    Magic;
	unsigned short	MajorVersion;	/* 主版本号 */
	unsigned short	MinorVersion;	/* 副版本号 */
	unsigned int	ThisZone;	    /* 区域时间，32位，未用，默认为0 */
	unsigned int	Sigfigs;	    /*精确时间戳，32位 ，未用，默认为0值*/
	unsigned int	SnapLen;	    /* 所抓获的数据包最大长度*/
	unsigned int	Network;	    /* 链路层类型 */
	_TS_PCAP_HEADER()
	{
		Magic = PCAP_MAGIC;
		MajorVersion = 2;
		MinorVersion = 4;
		ThisZone = 0;
		Sigfigs = 0;
		SnapLen = 0x00010000;
		Network = 1;
	}
}TS_PCAP_HEADER;
/**********时间戳***********/
typedef struct _TS_TIMEVAL
{
	unsigned int GmtTime;//秒计时 1970年后的秒
	unsigned int us;     //微秒计时 可受头结构中的Sigfigs限制，精度为微秒或者纳秒
	_TS_TIMEVAL()
	{
		GmtTime = 0;
		us      = 0;
	}

}TS_TIMEVAL;
/**********包头****************/
typedef struct _TS_PCAP_PKTHDR{
	TS_TIMEVAL ts;	/* time stamp */
	unsigned int caplen;	/* length of portion present */
	unsigned int len;	    /* length this packet (off wire) */
	_TS_PCAP_PKTHDR()
	{
		caplen = 0;
		len    = 0;
	}
}TS_PCAP_PKTHDR;
//文件定义
typedef struct _TS_LIBCAP_FILE
{
    string strfilepathname;//文件路径
    string strfilename;    //文件名称
    int n_filesize;       //文件大小
	int n_filecreatetime; //文件生成时间
	_TS_LIBCAP_FILE()
	{
		n_filesize = 0;
		n_filecreatetime = 0;
	}
}TS_LIBCAP_FILE;
//
typedef std::map <int, TS_LIBCAP_FILE*>	MAP_TS_LIBCAP_FILE;          //信息包包头

/********************************************************************
*	filename: 	CLibpCapFileMnger
*	author:		yinzhehong
*	created:	2013/03/18
*	purpose:  	CLibpCapFile文件管理工具      
*   version:    1.0
*********************************************************************/
#include "CapPackagesMnger.h"
class CLibpCapFileMnger
{
public:
	CLibpCapFileMnger(void);
	~CLibpCapFileMnger(void);
private:
	int SavePacketList2File(const char* c_savepath,MAP_CAPMSGINFO map_capmsginfo);
public:
	//将指定链接报文保存到指定路径的pcap文件
	int SaveCapConnetion2File(CAPCONNECTINFO * pCapconnectinfo,const char* c_savepath);
	//清空输出队列
	int  RetPacketList();
	//增加报文
	void AddPacket2ListBuff(CAPMSGGININFO* pCapMsgGinInfo);
	//
	int SaveBufferPacketList2File(const char* c_savepath);
private:
	MAP_CAPMSGINFO    m_map_capmsginfo;//链路所拥有的报文队列
public:
	/************打开pcap文件*******************/
	int Libpcap_open_offline(const char * c_filefullpathname, char* c_error);
	/***********读取下一帧，返回值为本帧报文在全部队列中开始的位置******/
	char* Libpcap_next_cap(TS_PCAP_PKTHDR* pkthdr, unsigned int& npos);
	/***********关闭pcap文件**********************/
	int Libpcap_close();
	/************打开pcap文件LIST*******************/
	int Libpcap_mergerfilelist(MAP_TS_LIBCAP_FILE map_tslibcapfilelist,TS_LIBCAP_FILE* pfilelist_dst);
	int getLinkType(){
		return m_ts_pcapfile_header.Network;
	}
private:
	char*          m_plibpCapFileContent; //文件全部内容，文件打开时一把加载进来
    unsigned int   m_nlibpCapFileSize;    //文件大小
	unsigned int   m_nlibcurpos;          //当前位置，一帧一帧读取
	TS_PCAP_HEADER m_ts_pcapfile_header;  //文件头
	bool  m_bRevByte;
};

