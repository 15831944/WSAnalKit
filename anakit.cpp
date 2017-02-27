#pragma execution_character_set("UTF-8")
#include "time.h"
#include "stdio.h"

#include "const_scan.h"
#include "anakit.h"
#include "CapPackageStatic.h"

#include "CapTransformer.h"
#include "ScanDissectPacketer.h"

CCapTransformer  *g_capTransformer = NULL;  //cap文件生成的txt文件解析器
//CZipcWrapper              m_zicpWrapper;              //解压缩动态库封装
CScanDissectPacketer   *g_ScanDissectPacketer =NULL;      //用于数据包的解析

AnaKit::AnaKit()
{


}

AnaKit::~AnaKit()
{
    //做一些释放资源的动作 todo
}
void AnaKit::Initialize()
{
	if (g_capTransformer == NULL)
	{
		g_capTransformer = new CCapTransformer();
		g_capTransformer->Initialize("./lib/analyzetxt.dll"); //临时，实际名称可能需要根据运行环境确定
	}

	if (g_ScanDissectPacketer == NULL)
	{
		g_ScanDissectPacketer = new CScanDissectPacketer();
		g_ScanDissectPacketer->Initialize("./lib/scandissectpkt.dll");
	}
}

CAPMSGGININFO * AnaKit::LoadePacketMsg(int nseq,TS_PCAP_PKTHDR* pkthdr,char *pkt)
{
    CAPMSGGININFO * pCapPackage = new CAPMSGGININFO;
    pCapPackage->nseq = nseq;                     //序号，从1开始编写

    //记录长度
    m_pPacket.nLen = pkthdr->caplen +sizeof(TS_PCAP_PKTHDR);
    //记忆起始指针
    m_pPacket.pPacket  = pkt;

    //记录原始报文
    pCapPackage->ncap_len = pkthdr->caplen;
    pCapPackage->nlen     = pkthdr->len;
    pCapPackage->nsourceinfo_length = m_pPacket.nLen;
    pCapPackage->csourceinfo = pkt; //直接赋指针，减少一次复制

    //制作结构, TCP报文链路分析、过程层的报文(SMV,GOOSE,1588)制作
    m_pkgConvertWrp.Make61850Struct_Pack2Msg(pCapPackage,&m_pPacket);

    //时标戳
    pCapPackage->nseconds_utc_tmstamp = pkthdr->ts.GmtTime;
    pCapPackage->nus_tmstamp          = pkthdr->ts.us;
    return pCapPackage;
}


/*
 * 返回 true 成功  false 失败
 * 本函数参考CapAnalyzerDoc.cpp中LoadCapFileByLibpCapFileMnger()函数
 */
bool AnaKit::OpenCapFileAndParse(string fileName)
{
    m_capFileName.append(fileName);

    TS_PCAP_PKTHDR pktheader;//报文头
    char           *pkt_data;//含报文头
    int nseq = 1;   //顺序编号
    CAPMSGGININFO  * pCapPackage = NULL;
    CCapPackageStatic    cappackagestic; //链路统计

    double   fFirstPackageT = 0.0f; //第一帧时间
    double   fPrePackageT = 0.0f;   //上一帧时间
    double   fPackageT =0.0f;

    char errbuf[500];
    int fileSize = m_libpcapfilemnger.Libpcap_open_offline(fileName.c_str(), errbuf);
    if(fileSize == 0)
        return false;

    unsigned int npktoffset = 0; //
    unsigned int nmmscount = 0;//MMS报文级数

    //开始逐帧读取数据
    while((pkt_data = m_libpcapfilemnger.Libpcap_next_cap(&pktheader,npktoffset))!= NULL)
    {
        //制作报文，TCP报文链路分析、过程层的报文(SMV,GOOSE,1588)制作
        pCapPackage = LoadePacketMsg(nseq, &pktheader, pkt_data);
        pCapPackage->npkt_offset_incapfile = npktoffset;

        //加入到总的报文队列
        m_cappackagesmnger.AddPacket2MnGrList(pCapPackage);

        //报文采样时间获取
        fPackageT = pktheader.ts.GmtTime + pktheader.ts.us/1000000.0;
        if(nseq == 1)//第一帧
        {
            fFirstPackageT = fPackageT;
            fPrePackageT   = fPackageT;//0.0f;
        }
        pCapPackage->ftime_delta = fPackageT - fPrePackageT;     //与上一帧的时间差
        pCapPackage->ftime_relative = fPackageT - fFirstPackageT;//与第一帧报文的时间差

        //制作界面显示用的结构-，只解析102端口报文,且心跳报文不解析
        if(pCapPackage->napptype == ETHER_TYPE_TCP  && (pCapPackage->ndst_port == 102 || pCapPackage->nsrc_port == 102)
            /*&& (pCapPackage->ncap_len > 90)*/)//关闭文件请求仅86字节，应答仅82字节 //66仅心跳 +7 COPT+TPKT的头
        {
            nmmscount ++;
            g_ScanDissectPacketer->I_XJ_DISSECT_MMS_PACKET(pCapPackage,nmmscount);
            //MMS报文分析
            if (pCapPackage->napptype == IEC61850_ETHER_TYPE_MMS || pCapPackage->napptype == ETHER_TYPE_COTP || pCapPackage->napptype == ETHER_TYPE_TPKT)//设定为MMS报文
            {
                g_capTransformer->I_XJ_PKT_STRUCT_MAKE_MMS_INFO_STRUCT(pCapPackage,TRUE);//制作MMS报文,格式错误报文不显示
                //释放资源
                //pApp->m_pcatransformer->I_ReleaseMMSInfoStruct((MMS_INFO_STRUCT *)pCapPackage->pparserdstruct);
                //pCapPackage->pparserdstruct = NULL;
            }
            g_ScanDissectPacketer->I_XJ_CLEANUP_PACKET(pCapPackage->pxj_dissect_pkt);//释放资源
            pCapPackage->pxj_dissect_pkt = NULL;
        }
        //统计一次
        cappackagestic.StaticPackageLink(&m_cappackagesmnger.m_capparserninfo,pCapPackage,&m_cappackagesmnger.m_mapcapconnectionfo);
        nseq++;//序号+1
        fPrePackageT = fPackageT;//记录上一帧时间
    }
    m_cappackagesmnger.m_capparserninfo.napppackages = nseq-1;//总帧数

    //文件的开始时间和结束时间
    int nsize = m_cappackagesmnger.m_pcapconnectinfoTotal.map_capmsginfo.size();
    if(nsize  > 1)
    {
        time_to_string(m_cappackagesmnger.m_pcapconnectinfoTotal.map_capmsginfo[0]->nseconds_utc_tmstamp,
                m_cappackagesmnger.m_pcapconnectinfoTotal.map_capmsginfo[0]->nus_tmstamp,
                m_cappackagesmnger.m_capparserninfo.cstarttimestamp);
        time_to_string(m_cappackagesmnger.m_pcapconnectinfoTotal.map_capmsginfo[nsize -1]->nseconds_utc_tmstamp,
                m_cappackagesmnger.m_pcapconnectinfoTotal.map_capmsginfo[nsize -1]->nus_tmstamp,
                m_cappackagesmnger.m_capparserninfo.cendtimestamp);
    }
    return true;
}


