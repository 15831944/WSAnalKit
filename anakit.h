#ifndef ANAKIT_H
#define ANAKIT_H

#include "LibpCapFileMnger.h"
#include "PackageCovertWrapper.h"

class AnaKit
{
public:
    AnaKit();
	~AnaKit();

    void Initialize();

    string m_capFileName;

    //pcap文件操作类
    CLibpCapFileMnger m_libpcapfilemnger;

    //解析包数据管理类
    CCapPackagesMnger m_cappackagesmnger;

	//原始报文存储
    PACKET_STRUCT m_pPacket;

	//tcp及以下层次协议解析
    CPackageCovertWrapper m_pkgConvertWrp;

    //打开pcap文件并解析
    bool OpenCapFileAndParse(string fileName);

    //解析一帧报文，返回报文解析结果
    //nseq  该帧报文在报文包中的序号
    CAPMSGGININFO * LoadePacketMsg(int nseq, TS_PCAP_PKTHDR* pkthdr,char *pkt);

};

#endif // ANAKIT_H
