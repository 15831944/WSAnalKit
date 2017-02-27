#pragma once
#include "../capanalyzer/CapPackagesMnger.h"
//#include "../capanalyzer/CapXmlAnalyzer.h"	//解析xml格式
#include "../capanalyzer/CapTxtAnalyzer.h"	//解析txt文本
#include "../capanalyzer/CapPackageStatic.h"//包统计
#include <fstream>
#include <io.h>//用于检查路径是否存在
//#include <pcap.h>//wpcap解析库
#include "DlgProgressShow.h"
#include "CapAnalyzerView.h"
#include "MsgBrifListView.h"
#include "PktMsgDetailFormView.h"
#include "PktLinkBriefView.h"
#include "LibpCapFileMnger.h"
/**
 * @brief       class name: CCapAnalyzerDoc
 * @use			pcap文件加载、解析、统计
					 1、调用封装wireshark接口解析pcap文件，生成解析文件
					 2、逐项加载解析文件中的数据
					 3、加载过程中逐项进行统计，生成简要统计信息
 * @author      尹浙洪
 * @version     ver1.0
 * @date        2010/8/23
 * example
 * @code
 *
 *
 *
 * @endcode
 */
class CCapAnalyzerDoc : public CDocument
{
	DECLARE_DYNCREATE(CCapAnalyzerDoc)

public:
	CCapAnalyzerDoc();
	virtual ~CCapAnalyzerDoc();
#ifndef _WIN32_WCE
	virtual void Serialize(CArchive& ar);   // overridden for document i/o
#endif
#ifdef _DEBUG
	virtual void AssertValid() const;
#ifndef _WIN32_WCE
	virtual void Dump(CDumpContext& dc) const;
#endif
#endif

protected:
	virtual BOOL OnNewDocument();
	DECLARE_MESSAGE_MAP()
public:
	virtual void OnCloseDocument();
	virtual BOOL OnOpenDocument(LPCTSTR lpszPathName);
//	virtual void SetTitle(LPCTSTR lpszTitle);
/************************************************************************/
/* 以下为扩展函数部分                                  */
/************************************************************************/            
public:
	// 打开解析文件
	int OpenPcapFile(LPCTSTR lpszPathName);	
	//开始文件解析线程
	int Start_Thread_ParserRecordFile(); 
	//解析记录文件
	int ParserRecordFile();	
	//链路分析
//	int PackagesConnectAnalyze();
	//通知界面更新
	int TellViewCapLoaded(int nType);
	// 得到文件加载全路经
	CString GetCapFileFullPathName(void);
	//得到概要数据列表视图
	CMsgBrifListView*       GetMsgBriefListView();
	//得到连接数据视图
	CPktLinkBriefView*      GetPktLinkBriefView();
//	CCapAnalyzerDetailView* GetCapAnalyzerDetailView();
	//得到概要数据视图
	CCapAnalyzerView* GetCCapAnalyzerView();
	//
	CPktMsgDetailFormView* GetPktMsgDetailFormView();

	//刷新连接
	int RefreshConnectDetail(CAPCONNECTINFO* pcapconnectinfo,int nDataShowtype,int npcapconnectType);
	//刷新连接，并设为焦点
	int RefreshConnectDetail_SetFocus(CAPCONNECTINFO* pcapconnectinfo,int nDataShowtype,int ncapconnectType);
	//刷新波形游标选定的位置
	int RefreshWaveCoursorPosition(WPARAM wParam, LPARAM lParam);
	//分析所有链接
	int AnalyzeAllConnections();
	//分析ACSI链路
	int AnalyzeAllConnections_Mms(CAPCONNECTINFO* pConnection);
	//分析Gs链路
	int AnalyzeAllConnections_Gs(CAPCONNECTINFO* pConnection);
	//分析Gs链路
	int AnalyzeAllConnection_Ptp(CAPCONNECTINFO* pConnection);
	//分析smv链路
	int AnalyzeAllConnections_Smv(CAPCONNECTINFO* pConnection);
	/*******获取链接的描述信息******/
	CString GetLinkDesc(CAPCONNECTINFO* pCurConnectInfo);
	/************根据报文查询条件从队列中查询出对应报文****************/
	int GetNewFilterConnectionByCondition(MAP_CAPMSGINFO map_capmsginfo_src,MAP_CAPMSGINFO* pmap_capmsginfo_dst,PACKETQUER_FILTER *pQuery_Filter);
private:
	//直接通过wcap加载文件
//	int LoadCapFileDirectByWpcap();
	//********直接加载通过自己的pcap文件加载器************/
	int LoadCapFileByLibpCapFileMnger();
	CAPMSGGININFO * LoadePacketMsg(int nseq,TS_PCAP_PKTHDR* pkthdr,char *pkt);
	//****加载数据包****//
//	CAPMSGGININFO * LoadePacketMsg(int nseq,pcap_pkthdr *header,const u_char *pkt_data);

//	int Adjust_Timestamp(char *c_frame);

/************************************************************************/
/*以下为属性部分                                  */
/************************************************************************/
public:
	//对应的pcap文件全路经名，不带后缀
	CString m_strCapFileFullPathName;
	//对应的pcap文件名
	CString m_strCapFileName;           
	//对应的cap文件解析文件名
	CString m_strCapTransformedFileName;
	//数据包解析模式
	bool m_bLoadPackageByPackage;//是否是逐包加载
	int  m_nLoadPackages;        //一次加载的数据包包数
	//本文档是否退出
	BOOL m_bEndDoc;
	//解析线程是否结束
	BOOL m_bEndParseThread;
	CLibpCapFileMnger m_libpcapfilemnger;
private:
	std::ifstream  m_txtifstream;//打开txt解析结果的文本指针
//	PACKET_CHAR_STRUCT* m_pPacket;//加载数据时的变量
	PACKET_STRUCT*      m_pPacket;//加载数据时的变量
public:
	//解析包数据管理类
	CCapPackagesMnger m_cappackagesmnger;
	//文本解析结构
//	CCapTxtAnalyzer   m_captxtanalyzer;
private:
	CDlgProgressShow* m_pDlgprogressShow;//进度指示器
public:
//	afx_msg void OnToolbarMsgdtailShowsrc();
public: //用于定位告警目标帧
	double	m_fTargetTime; //time.ms

};
