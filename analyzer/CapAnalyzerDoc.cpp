// CapAnalyzerDoc.cpp : implementation file
//

#include "stdafx.h"
#include "WSAnalyzer.h"
#include "CapAnalyzerDoc.h"
#include "MainFrm.h"



// CCapAnalyzerDoc

/**
* @brief	Thread_ParserRecordFile 	解析记录文件线程
* @param 	LPVOID lParam	            CCapAnalyzerDoc 指针        
* @param 	
* @return	UINT
* @notes	无
* @sample	无
*/
static UINT Thread_ParserRecordFile(LPVOID lParam)
{
	CCapAnalyzerDoc* pDoc = (CCapAnalyzerDoc*)lParam;
	//加载文件
	pDoc->ParserRecordFile();//解析记录文件
	return 1;

}

IMPLEMENT_DYNCREATE(CCapAnalyzerDoc, CDocument)

CCapAnalyzerDoc::CCapAnalyzerDoc()
{
	m_bLoadPackageByPackage = true; //默认是逐帧加载方式
	m_nLoadPackages         = 1;    //默认为1
	CWSAnalyzerApp * pApp = (CWSAnalyzerApp *) AfxGetApp();
//	m_captxtanalyzer.m_pcaptransformer = pApp->m_pcatransformer;
	m_bEndDoc = FALSE;
	m_pPacket = new PACKET_STRUCT;
	m_pDlgprogressShow = new CDlgProgressShow;
	m_pDlgprogressShow->Create(IDD_DLG_SHOW_PROGRESS,NULL);
	m_pDlgprogressShow->ShowWindow(SW_HIDE);

	m_bEndParseThread = TRUE;

	m_fTargetTime = 0.0; //time.ms
}

BOOL CCapAnalyzerDoc::OnNewDocument()
{
	if (!CDocument::OnNewDocument())
		return FALSE;
	return TRUE;
}

CCapAnalyzerDoc::~CCapAnalyzerDoc()
{
	m_pDlgprogressShow->EndShow();
	delete m_pPacket;
	m_cappackagesmnger.FreeSource();//释放资源
	m_libpcapfilemnger.Libpcap_close();
}

BEGIN_MESSAGE_MAP(CCapAnalyzerDoc, CDocument)
//	ON_COMMAND(ID_TOOLBAR_MSGDTAIL_SHOWSRC, &CCapAnalyzerDoc::OnToolbarMsgdtailShowsrc)
END_MESSAGE_MAP()


// CCapAnalyzerDoc diagnostics

#ifdef _DEBUG
void CCapAnalyzerDoc::AssertValid() const
{
	CDocument::AssertValid();
}

#ifndef _WIN32_WCE
void CCapAnalyzerDoc::Dump(CDumpContext& dc) const
{
	CDocument::Dump(dc);
}
#endif
#endif //_DEBUG

#ifndef _WIN32_WCE
// CCapAnalyzerDoc serialization

void CCapAnalyzerDoc::Serialize(CArchive& ar)
{
	if (ar.IsStoring())
	{
		// TODO: add storing code here
	}
	else
	{
		// TODO: add loading code here
	}
}
#endif


// CCapAnalyzerDoc commands
void CCapAnalyzerDoc::OnCloseDocument()
{
	// TODO: Add your specialized code here and/or call the base class
	//通知波形界面
	CMainFrame * pMain = (CMainFrame*) AfxGetMainWnd();
	if(pMain != NULL)
		pMain->PostMessage(WM_NotifyUpdateWave, 0, NULL);
	CPktMsgDetailFormView* pView = GetPktMsgDetailFormView();
	if(pView != NULL)
	{
		pView->PostMessage(WM_NotifyUpdateWave, 0, NULL);
	}
	m_bEndDoc = TRUE;//给加载线程一个关闭标志
	while(!m_bEndParseThread)//等待退出
	{
		Sleep(1000);
	}
	CDocument::OnCloseDocument();
}

/**
* @brief	OnOpenDocument 	            打开新文件消息响应函数，文件名称检查
* @param 	LPCTSTR lpszPathName	    文件全路径字符串     
* @param 	
* @return	UINT
* @notes	无
* @sample	无
*/
BOOL CCapAnalyzerDoc::OnOpenDocument(LPCTSTR lpszPathName)
{
	CString targetTime = ((CWSAnalyzerApp*)AfxGetApp())->m_sCmdLine;

	m_fTargetTime = atof(targetTime);
	if (!CDocument::OnOpenDocument(lpszPathName))
		return FALSE;
	//检查该文件是否存在
	if(_access(lpszPathName,0) == -1)//主要是考虑命令行传输错误的情况
	{
		CString strError;
		strError.Format("文件%s不存在,请检查！",lpszPathName);
		AfxMessageBox(strError);
		return FALSE;
	}
	m_strCapFileFullPathName = lpszPathName;//全路径
	strcpy_s(m_cappackagesmnger.m_capparserninfo.cparserfilename,m_strCapFileFullPathName);//记录到结构
	//打开cap文件
	if(OpenPcapFile(lpszPathName) != 0)
	{
		return FALSE;
	}
	return TRUE;
}
/**
* @brief	OpenPcapFile 	            打开pcap文件,记录文件路径，启动文件解析线程
* @param 	LPCTSTR lpszPathName	    文件全路径字符串   
* @param 	
* @return	int                         正常情况下为0
* @notes	无
* @sample	无
*/
int CCapAnalyzerDoc::OpenPcapFile(LPCTSTR lpszPathName)
{
	//启动文件翻译数据
	if(Start_Thread_ParserRecordFile() != 0)
	{
		return -1;
	}
	return 0;
}
//开始文件解析线程
/**
* @brief	Start_Thread_ParserRecordFile   开始文件解析线程
* @param 	  
* @param 	
* @return	int
* @notes	无
* @sample	无
*/
int CCapAnalyzerDoc::Start_Thread_ParserRecordFile()
{
	//加载...
	AfxBeginThread(Thread_ParserRecordFile, this);
	return 0;
}
//解析记录数据
/**
* @brief	ParserRecordFile   解析记录数据，数据解析总函数，数据内容加载、数据格式转换、错误分析
* @param 	  
* @param 	
* @return	int
* @notes	无
* @sample	无
*/
int CCapAnalyzerDoc::ParserRecordFile()
{
	CString strPort,strLog;

	CWSAnalyzerApp * pApp = (CWSAnalyzerApp *) AfxGetApp();
	char    chDrive[MAX_PATH], chDir[MAX_PATH*2];
	char    chFilename[MAX_PATH]; 
	char    chExt[6];
	_splitpath_s( m_strCapFileFullPathName, chDrive, chDir, chFilename, chExt );
	//根据后缀
	if(StrCmp(chExt,".zip") == 0 ||StrCmp(chExt,".tzip")==0 ||StrCmp(chExt,".zipx")==0)//压缩过的文件
	{
		//进度条
#ifdef _DEBUG
#else
		strLog.Format("记录文件正在解压中......");
		m_pDlgprogressShow->SetContent(strLog);
		m_pDlgprogressShow->ShowWindow(SW_SHOW);
#endif
		//pApp->m_zicpWrapper.UnZip_MINILZO_I(m_strCapFileFullPathName,NULL);
		m_strCapFileFullPathName.Format("%s%s%s%s",chDrive,chDir,chFilename,".pcap");
	}
#ifdef _DEBUG
#else
	strLog.Format("记录文件正在加载中......");
	m_pDlgprogressShow->SetContent(strLog);
	m_pDlgprogressShow->ShowWindow(SW_SHOW);
#endif

	//填充采集端口，采集装置名称
	int nPortUseType = 0;
	strPort.Format("%s",chFilename);
	int nPort = atoi(strPort);
	SNIFFER* pSniffer = pApp->m_wssysConfiguration.I_GET_SNIFFER(nPort);
	if(pSniffer != NULL)
		strcpy_s(m_cappackagesmnger.m_capparserninfo.crecoriedname,pSniffer->csniffername);
	SNIFFER_PORT* pPort = pApp->m_wssysConfiguration.I_GET_SNIFFERPORT(nPort);
	if(pPort != NULL)
	{
		strcpy_s(m_cappackagesmnger.m_capparserninfo.crecorportname,pPort->cportname);
		nPortUseType = pPort->nusetype;
	}
	m_bEndParseThread = FALSE;
	LoadCapFileByLibpCapFileMnger();
	//LoadCapFileDirectByWpcap();
	//分析所有链路
#ifdef _DEBUG
#else
	strLog.Format("记录文件已加载，正在分析中......");
	m_pDlgprogressShow->SetContent(strLog);
	m_pDlgprogressShow->ShowWindow(SW_SHOW);
#endif
 	AnalyzeAllConnections();
	m_bEndParseThread = TRUE;
	//通知列表界面更新树
	CCapAnalyzerView*       pCapAnalyzerView = GetCCapAnalyzerView();
	pCapAnalyzerView->UpdateShowContent(CAPLOAD_PARSERFILE_ANALYZER_NET_OK, NULL);
	//更新列表界面更新列表
	RefreshConnectDetail(NULL,CAPSHOW_DATATYE_ALL,PROTOAPPTYPE_TOTAL);
#ifdef _DEBUG
#else
	m_pDlgprogressShow->ShowWindow(SW_HIDE);
#endif
	return 0;
}
//直接解析记录数据，调用wpcap读取文件
/**
* @brief	LoadCapFileByLibpCapFileMnger   直接解析pcap文件，然后再调用packagecovert动态库直接解析，本函数适用于解析goose报文或者采样报文文件
* @param 	  
* @param 	
* @return	 0：成功，其它：失败
* @notes	无
* @sample	无
*/
int CCapAnalyzerDoc::LoadCapFileByLibpCapFileMnger()
{
	TS_PCAP_PKTHDR pktheader;//报文头
	char           *pkt_data;//含报文头
	char errbuf[500];
	int nresult = 0;
	int nseq = 1;   //顺序编号
	CWSAnalyzerApp * pApp = (CWSAnalyzerApp *) AfxGetApp();
	CAPMSGGININFO  * pCapPackage = NULL;
	CCapPackageStatic    cappackagestic; //链路统计

	double   fFirstPackageT = 0.0f; //第一帧时间
	double   fPrePackageT = 0.0f;   //上一帧时间
	double   fPackageT =0.0f;
	//打开文件
	if(m_libpcapfilemnger.Libpcap_open_offline(m_strCapFileFullPathName.GetBuffer(),errbuf) == 0)
	{
		CString strLog;
		strLog.Format("打开解析文件:%s失败",m_strCapTransformedFileName);
		AfxMessageBox(strLog);
		return RES_FAIL;
	}

	pApp->m_pPackageCovertWrapper->setLinkType(m_libpcapfilemnger.getLinkType());
	unsigned int npktoffset = 0;
	unsigned int nmmscount = 0;//MMS报文级数
	//开始逐帧读取数据
	while((pkt_data = m_libpcapfilemnger.Libpcap_next_cap(&pktheader,npktoffset))!= NULL && !m_bEndDoc)
	{
		pCapPackage = LoadePacketMsg(nseq,&pktheader,pkt_data);//制作报文，TCP报文链路分析、过程层的报文(SMV,GOOSE,1588)制作
		pCapPackage->npkt_offset_incapfile = npktoffset;
		//加入到总的报文队列
		m_cappackagesmnger.AddPacket2MnGrList(pCapPackage);

		fPackageT = pktheader.ts.GmtTime + pktheader.ts.us/1000000.0;
		if(nseq == 1)//第一帧
		{
			fFirstPackageT = fPackageT;
			fPrePackageT   = fPackageT;//0.0f;
		}

#ifdef _DEBUG
		TRACE("nseq:%d\r\n",nseq);
#endif
		pCapPackage->ftime_delta = fPackageT - fPrePackageT;     //与上一帧的时间差
		pCapPackage->ftime_relative = fPackageT - fFirstPackageT;//与第一帧报文的时间差
		//制作界面显示用的结构-，只解析102端口报文,且心跳报文不解析
		if(pCapPackage->napptype == ETHER_TYPE_TCP  && (pCapPackage->ndst_port == 102 || pCapPackage->nsrc_port == 102) 
			/*&& (pCapPackage->ncap_len > 90)*/)//关闭文件请求仅86字节，应答仅82字节 //66仅心跳 +7 COPT+TPKT的头
		{
			nmmscount ++;
			pApp->m_ScanDissectPacketer.I_XJ_DISSECT_MMS_PACKET(pCapPackage,nmmscount);
			//MMS报文分析
			if (pCapPackage->napptype == IEC61850_ETHER_TYPE_MMS || pCapPackage->napptype == ETHER_TYPE_COTP || pCapPackage->napptype == ETHER_TYPE_TPKT)//设定为MMS报文
			{
				pApp->m_pcatransformer->I_XJ_PKT_STRUCT_MAKE_MMS_INFO_STRUCT(pCapPackage,TRUE);//制作MMS报文,格式错误报文不显示
				//释放资源	
				//pApp->m_pcatransformer->I_ReleaseMMSInfoStruct((MMS_INFO_STRUCT *)pCapPackage->pparserdstruct);
				//pCapPackage->pparserdstruct = NULL;
			}
			pApp->m_ScanDissectPacketer.I_XJ_CLEANUP_PACKET(pCapPackage->pxj_dissect_pkt);//释放资源
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
		CTime t1(m_cappackagesmnger.m_pcapconnectinfoTotal.map_capmsginfo[0]->nseconds_utc_tmstamp);
		sprintf_s(m_cappackagesmnger.m_capparserninfo.cstarttimestamp,
			"%04d-%02d-%02d %02d:%02d:%02d.%06d",t1.GetYear(),t1.GetMonth(),t1.GetDay(),t1.GetHour(),t1.GetMinute(),t1.GetSecond(),m_cappackagesmnger.m_pcapconnectinfoTotal.map_capmsginfo[0]->nus_tmstamp);
//		strcpy_s(m_cappackagesmnger.m_capparserninfo.cstarttimestamp,m_cappackagesmnger.m_pcapconnectinfoTotal.map_capmsginfo[0]->ctimestamp);
		CTime t2(m_cappackagesmnger.m_pcapconnectinfoTotal.map_capmsginfo[nsize -1]->nseconds_utc_tmstamp);
		sprintf_s(m_cappackagesmnger.m_capparserninfo.cendtimestamp,
			"%04d-%02d-%02d %02d:%02d:%02d.%06d",t2.GetYear(),t2.GetMonth(),t2.GetDay(),t2.GetHour(),t2.GetMinute(),t2.GetSecond(),m_cappackagesmnger.m_pcapconnectinfoTotal.map_capmsginfo[nsize -1]->nus_tmstamp);
//		strcpy_s(m_cappackagesmnger.m_capparserninfo.cendtimestamp,m_cappackagesmnger.m_pcapconnectinfoTotal.map_capmsginfo[nsize -1]->ctimestamp);
	}
	return 0;
}
CAPMSGGININFO * CCapAnalyzerDoc::LoadePacketMsg(int nseq,TS_PCAP_PKTHDR* pkthdr,char *pkt)
{
	CWSAnalyzerApp * pApp = (CWSAnalyzerApp *) AfxGetApp();
	CAPMSGGININFO * pCapPackage = new CAPMSGGININFO;
	pCapPackage->nseq = nseq;                     //序号，从1开始编写
//	memset(m_pPacket,0,sizeof(PACKET_CHAR_STRUCT));
	//记录长度
	m_pPacket->nLen = pkthdr->caplen +sizeof(TS_PCAP_PKTHDR);
	m_pPacket->pPacket  = pkt;//记忆起始指针
	//记录原始报文
	pCapPackage->ncap_len = pkthdr->caplen;
	pCapPackage->nlen     = pkthdr->len;
	pCapPackage->nsourceinfo_length = m_pPacket->nLen;
	pCapPackage->csourceinfo = pkt; //直接赋指针，减少一次复制
//	pCapPackage->csourceinfo = new char[pCapPackage->nsourceinfo_length];
//	memcpy(pCapPackage->csourceinfo,pkt,pCapPackage->nsourceinfo_length);
	//制作结构
	pApp->m_pPackageCovertWrapper->Make61850Struct_Pack2Msg(pCapPackage,m_pPacket);//TCP报文链路分析、过程层的报文(SMV,GOOSE,1588)制作
	//时标戳
	pCapPackage->nseconds_utc_tmstamp = pkthdr->ts.GmtTime;
	pCapPackage->nus_tmstamp          = pkthdr->ts.us;
	return pCapPackage;
}
//各种分析结果视图通知
/**
* @brief	PackagesConnectAnalyze   视图通知，由于本函数在多线程中被调用不能用消息通知机制实现，直接调用试图函数
* @param 	  
* @param 	
* @return	int
* @notes	无
* @sample	无
*/
//int CCapAnalyzerDoc::TellViewCapLoaded(int nType)
//{
////加载完成，通知界面
////	UpdateAllViews(NULL,nType,NULL);//参数为1，表示文件解析成功完毕,改函数无法在多线程中调用
//	CView* pView;
//	CMsgBrifListView*      pMsgBrifListView;
//	CCapAnalyzerView*      pCapAnalyzerView;
//	POSITION pos=GetFirstViewPosition();
//	while(pos!=NULL)
//	{
//		pView = GetNextView(pos);
//		if(pView->IsKindOf(RUNTIME_CLASS(CMsgBrifListView)))//详细视图
//		{
//			pMsgBrifListView = (CMsgBrifListView*) pView;
//			pMsgBrifListView->UpdateShowContent(nType,NULL,CAPSHOW_DATATYE_ALL,m_fTargetTime);
//		}
//		else if(pView->IsKindOf(RUNTIME_CLASS(CCapAnalyzerView)))//概要视图
//		{
//			pCapAnalyzerView = (CCapAnalyzerView *) pView;
//			pCapAnalyzerView->UpdateShowContent(nType,NULL);
//		}
//	}
//	return 0;
//}

//各种分析结果视图通知
/**
* @brief	GetCapFileFullPathName   得到文件加载的全路径及文件名
* @param 	
* @param 	
* @return	CString                  文件加载的全路径及文件名
* @notes	无
* @sample	无
*/
CString CCapAnalyzerDoc::GetCapFileFullPathName(void)
{
	return m_strCapFileFullPathName;
}
//得到详细分析视图
/**
* @brief	GetMsgBriefListView   得到详细分析视图
* @param 	
* @param 	
* @return
* @notes	无
* @sample	无
*/
CMsgBrifListView* CCapAnalyzerDoc::GetMsgBriefListView()
{
	CView* pView;
	CMsgBrifListView* pMsgBrifListView = NULL;
	POSITION pos = GetFirstViewPosition();
	while(pos!=NULL)
	{
		pView = GetNextView(pos);
		if(pView->IsKindOf(RUNTIME_CLASS(CMsgBrifListView)))//得到详细视图
		{
			pMsgBrifListView = (CMsgBrifListView*) pView;
			break;
		}
	}
	return pMsgBrifListView;
}
CPktLinkBriefView* CCapAnalyzerDoc::GetPktLinkBriefView()
{
	CView* pView;
	CPktLinkBriefView* pPktLinkBriefView = NULL;
	POSITION pos = GetFirstViewPosition();
	while(pos!=NULL)
	{
		pView = GetNextView(pos);
		if(pView->IsKindOf(RUNTIME_CLASS(CPktLinkBriefView)))//得到详细视图
		{
			pPktLinkBriefView = (CPktLinkBriefView*) pView;
			pPktLinkBriefView->m_targetTime = m_fTargetTime;
			break;
		}
	}
	return pPktLinkBriefView;
}
CPktMsgDetailFormView* CCapAnalyzerDoc::GetPktMsgDetailFormView()
{
	CView* pView;
	CPktMsgDetailFormView* pMsgMsgDtailFormView = NULL;
	POSITION pos = GetFirstViewPosition();
	while(pos!=NULL)
	{
		pView = GetNextView(pos);
		if(pView->IsKindOf(RUNTIME_CLASS(CPktMsgDetailFormView)))//得到详细视图
		{
			pMsgMsgDtailFormView = (CPktMsgDetailFormView*) pView;
			break;
		}
	}
	return pMsgMsgDtailFormView;
}
//得到概要分析视图
/**
* @brief	GetCCapAnalyzerView   得到概要分析视图
* @param 	
* @param 	
* @return
* @notes	无
* @sample	无
*/
CCapAnalyzerView* CCapAnalyzerDoc::GetCCapAnalyzerView()
{
	CView* pView;
	CCapAnalyzerView*       pCapAnalyzerView = NULL;;
	POSITION pos = GetFirstViewPosition();
	while(pos!=NULL)
	{
		pView = GetNextView(pos);
		if(pView->IsKindOf(RUNTIME_CLASS(CCapAnalyzerView)))//得到概要视图
		{
			pCapAnalyzerView = (CCapAnalyzerView *) pView;
			break;
		}
	}
	return pCapAnalyzerView;
}
//刷新连接
//* @param 	int nDataShowtype         1：异常报文 2：事件报文  其它值：所有报文 
int CCapAnalyzerDoc::RefreshConnectDetail(CAPCONNECTINFO* pcapconnectinfo,int nDataShowtype,int npcapconnectType)
{
	//获取链接
	if(pcapconnectinfo == NULL )
	{
		pcapconnectinfo = m_cappackagesmnger.GetPcapconnetInfo(npcapconnectType);//获取报文链接
	}
	if(pcapconnectinfo == NULL)//没有获取到对应的节点
		return -1;
	//通知概要列表及波形界面
	CPktLinkBriefView* pPktLinkBriefView = GetPktLinkBriefView();
	if(pPktLinkBriefView)
	{
		pPktLinkBriefView->PostMessage(WM_NotifyUpdateWave, WPARAM(nDataShowtype), (LPARAM)pcapconnectinfo);
	}
	//通知详细分析界面
	CPktMsgDetailFormView* pPktMsgDetailFormView = GetPktMsgDetailFormView();
	if(pPktMsgDetailFormView != NULL)
	{
		if(nDataShowtype == CAPSHOW_DATATYE_ALL && pcapconnectinfo->nusetype == 0 )
		{
			pPktMsgDetailFormView->PostMessage(WM_NotifyUpdateWave, 0, (LPARAM)pcapconnectinfo);
		}
		else
		{
			pPktMsgDetailFormView->PostMessage(WM_NotifyUpdateWave, 0, 0);
			pPktMsgDetailFormView->FillFileStatic(&m_cappackagesmnger);
		}
	}
	return 0;
}
//* @param 	int nDataShowtype         1：异常报文 2：事件报文  其它值：所有报文 
int CCapAnalyzerDoc::RefreshConnectDetail_SetFocus(CAPCONNECTINFO* pcapconnectinfo,int nDataShowtype,int ncapconnectType)
{
	CMsgBrifListView* pView = GetMsgBriefListView();
	if(pView == NULL)
		return -1;
	CFrameWnd * pWnd = pView->GetParentFrame();
	if(pWnd != NULL)
		pWnd->SetActiveView(pView);
	RefreshConnectDetail(pcapconnectinfo,nDataShowtype,ncapconnectType);
	return 0;
}
//刷新波形窗口对应的游标位置对应的采样点位置
int CCapAnalyzerDoc::RefreshWaveCoursorPosition(WPARAM wParam, LPARAM lParam)
{
	int  nPosition = (int) lParam;
	if(nPosition < 0)
		return -1;
	CMsgBrifListView* pView = GetMsgBriefListView();
	if(pView == NULL)
		return -1;
//	pView->SetFocus();
	return pView->SelectMsg(nPosition);
}
//分析所有链接
int CCapAnalyzerDoc::AnalyzeAllConnections()
{
	CMsgBrifListView* pView = GetMsgBriefListView();
	std::map <int, CAPCONNECTINFO* >::iterator iter;
	CAPCONNECTINFO* pConnection;
	for (iter = m_cappackagesmnger.m_mapcapconnectionfo.begin(); iter != m_cappackagesmnger.m_mapcapconnectionfo.end(); iter ++ )
	{
		pConnection = iter->second;
		if(pConnection == NULL)
			continue;
		if(pConnection->nconnectapptype == PROTOAPPTYPE_SMV92)
		{
			AnalyzeAllConnections_Smv(pConnection);
		}
		else if(pConnection->nconnectapptype == PROTOAPPTYPE_GOOSE)
		{
			AnalyzeAllConnections_Gs(pConnection);
		}
		else if(pConnection->nconnectapptype == PROTOAPPTYPE_MMS)//mms
		{
			CWSAnalyzerApp *pApp = (CWSAnalyzerApp*) AfxGetApp();
			//COPT list分析 add by yinzhehong 20120319
			pApp->m_pPackageCovertWrapper->COTP_LIST_ANALYZE(pConnection);
			//上下文分析
			AnalyzeAllConnections_Mms(pConnection);
		}
		else if(pConnection->nconnectapptype == PROTOAPPTYPE_TIME1588)
		{
			AnalyzeAllConnection_Ptp(pConnection);
		}
		m_cappackagesmnger.m_pcapconnectinfoTotal.nerrpackages += pConnection->nerrpackages;//总的错误包
	}
	//pView->InvalidateListCtrl();
	return 0;
}
//分析Gs链路
int CCapAnalyzerDoc::AnalyzeAllConnections_Gs(CAPCONNECTINFO* pConnection)
{
	CWSAnalyzerApp* pApp = (CWSAnalyzerApp*) AfxGetApp();
	CString strLog;
	strLog.Format("开始0X%xGOOSE链路错误分析",pConnection->ncapp_id);
	pApp->WriteLog(strLog);
	std::map <int, CAPMSGGININFO* >::iterator iter;
	CAPMSGGININFO* pCapMsgGinInfo;
	MESSAGE_ERROR_INFO_ARRAY_STRUCT* pArrayStruct;
	int nAnaCount = 0;
	GOOSE_INFO_STRUCT* gStructTemp;
	for(iter = pConnection->map_capmsginfo.begin(); iter != pConnection->map_capmsginfo.end(); iter ++ )
	{
		pCapMsgGinInfo = iter->second;
		if(pCapMsgGinInfo == NULL)
			continue;
		if(pCapMsgGinInfo->pparserdstruct == NULL)//尚未解析出来
			continue;
		if(pCapMsgGinInfo->napptype != PROTOAPPTYPE_GOOSE)//不是GOOSE报文
			continue;
		if(pCapMsgGinInfo->berroranalyzedgoose)//已经进行过错误分析了
			continue;
		gStructTemp = (GOOSE_INFO_STRUCT*) pCapMsgGinInfo->pparserdstruct;
		//if((gStructTemp->u_result  &DISSECT_GOOSE_RESULT_OK)!=DISSECT_GOOSE_RESULT_OK)//格式异常 add by yzh 20130331
		if(gStructTemp->u_result&DISSECT_GOOSE_PKTLEN_ERROR)
			continue;
		if(nAnaCount == 0)//重置链路
		{
			SNIFFER_APP* pSnifferApp = pApp->m_wssysConfiguration.I_GET_IED_BYAPPID(pCapMsgGinInfo->napp_id);
			if(pSnifferApp == NULL || pSnifferApp->napptype!=PROTOAPPTYPE_GOOSE)
			{
				SNIFFER_APP* pSnifferApp_Temp = new SNIFFER_APP;
				gStructTemp = (GOOSE_INFO_STRUCT*) pCapMsgGinInfo->pparserdstruct;
				pSnifferApp_Temp->nappid = gStructTemp->n_app_id;
				memcpy(pSnifferApp_Temp->cmacaddress,pCapMsgGinInfo->cdst_mac,strlen(pCapMsgGinInfo->cdst_mac));//gStructTemp->c_dest_mac,strlen(gStructTemp->c_dest_mac));
				memcpy(pSnifferApp_Temp->cgoid,gStructTemp->c_goID,strlen(gStructTemp->c_goID));
				memcpy(pSnifferApp_Temp->cdsname,gStructTemp->c_dataSet,strlen(gStructTemp->c_dataSet));
				memcpy(pSnifferApp_Temp->ccbname,gStructTemp->c_gocbRef,strlen(gStructTemp->c_gocbRef));//cbname	
				pSnifferApp_Temp->nconfrev = gStructTemp->n_confRev;
				pSnifferApp_Temp->ndssize = gStructTemp->n_numDatSetEntries;
				pApp->m_piec61850Analyzer->m_gooseAnalyzer.I_SET_SNIFFER_APP(pSnifferApp_Temp);
				delete pSnifferApp_Temp;
			}
			else
			{
				pApp->m_piec61850Analyzer->m_gooseAnalyzer.I_SET_SNIFFER_APP(pSnifferApp);
			}
		}
		pCapMsgGinInfo->pap_analyzed_info = (void*)pApp->m_piec61850Analyzer->m_gooseAnalyzer.I_GOOSEANALYZE((GOOSE_INFO_STRUCT*) pCapMsgGinInfo->pparserdstruct,1);
		pCapMsgGinInfo->berroranalyzedgoose = true;//置位
		if(pCapMsgGinInfo->pap_analyzed_info != NULL)
		{
			pArrayStruct = (MESSAGE_ERROR_INFO_ARRAY_STRUCT*) pCapMsgGinInfo->pap_analyzed_info;
			if(pArrayStruct->n_msg_err >= 1 && pCapMsgGinInfo->nAppConetentGood )//有分析错误事件（且未出现格式错误，最初格式错误后不进行分析，所以不会产生新的n_msg_err,现在允许格式错误继续分析，所以避免重复加入）
			{
				pCapMsgGinInfo->nAppConetentGood = 0;//错误报文
				//事件报文
				BOOL bEventPackage = FALSE;
				for(int i = 0; i< pArrayStruct->n_msg_err; i++)
				{
					for(int j = 0; j < pArrayStruct->p_msg_err[i].n_num_asduerr; j++)//统计asdu中的错误
					{
						for(int k = 0; k < pArrayStruct->p_msg_err[i].p_asduerr[j].n_num_errcode; k++)
						{
							if(pArrayStruct->p_msg_err[i].p_asduerr[j].p_errcode[k] == 24)//GOOSE变位事件下文特殊处理
							{
								bEventPackage = TRUE;
								pCapMsgGinInfo->beventanalyzedgoose = true;//goose变位事件
								 break;
							}
						}
					}
				}
				if(!bEventPackage)
				{
					//将错误报文增加到队列中
					pConnection->map_capmsginfo_error.insert(std::map <int, CAPMSGGININFO*> :: value_type(pConnection->nerrpackages, pCapMsgGinInfo));
					pConnection->nerrpackages ++;//错误报文增加
				}
				else
				{
					pConnection->map_capmsginfo_event.insert(std::map <int, CAPMSGGININFO*> :: value_type(pConnection->neventpackages, pCapMsgGinInfo));
					pConnection->neventpackages ++;	//事件报文增加)
				}
			}
		}
		nAnaCount ++;
	}
	strLog.Format("结束0X%xGOOSE链路错误分析,共有%d项错误",pConnection->ncapp_id,pConnection->nerrpackages);
	pApp->WriteLog(strLog);
	return 0;
}
//单个链路分析
int CCapAnalyzerDoc::AnalyzeAllConnection_Ptp(CAPCONNECTINFO* pConnection)
{
	//CPTPAO Ao(0, NULL);
	CWSAnalyzerApp* pApp = (CWSAnalyzerApp*) AfxGetApp();
	CString strLog;
	strLog.Format("开始%s PTP链路错误分析",pConnection->csrc1_mac);
	pApp->WriteLog(strLog);
	std::map <int, CAPMSGGININFO* >::iterator iter;
	CAPMSGGININFO* pCapMsgGinInfo;
	MESSAGE_ERROR_INFO_ARRAY_STRUCT* pArrayStruct;
	int nAnaCount = 0;
	PTP_INFO_STRUCT* gStructTemp;
	for(iter = pConnection->map_capmsginfo.begin(); iter != pConnection->map_capmsginfo.end(); iter ++ )
	{
		pCapMsgGinInfo = iter->second;
		if(pCapMsgGinInfo == NULL)
			continue;
		if(pCapMsgGinInfo->pparserdstruct == NULL)//尚未解析出来
			continue;
		if(pCapMsgGinInfo->napptype != PROTOAPPTYPE_TIME1588)//不是GOOSE报文
			continue;
		if(pCapMsgGinInfo->berroranalyzed)//已经进行过错误分析了
			continue;
		gStructTemp = (PTP_INFO_STRUCT*) pCapMsgGinInfo->pparserdstruct;


		if(nAnaCount == 0)//重置链路
		{
			SNIFFER_APP* pSnifferApp = pApp->m_wssysConfiguration.I_GET_IED_BYNETIDADDR(pCapMsgGinInfo->csrc_mac);
			if(pSnifferApp == NULL || pSnifferApp->napptype!=PROTOAPPTYPE_TIME1588)
			{
				SNIFFER_APP* pSnifferApp_Temp = new SNIFFER_APP;
				gStructTemp = (PTP_INFO_STRUCT*) pCapMsgGinInfo->pparserdstruct;
				pSnifferApp_Temp->nappid = 0;
				memcpy(pSnifferApp_Temp->cmacaddress,pCapMsgGinInfo->cdst_mac,strlen(pCapMsgGinInfo->cdst_mac));//gStructTemp->c_dest_mac,strlen(gStructTemp->c_dest_mac));
				//memcpy(pSnifferApp_Temp->cgoid,gStructTemp->c_goID,strlen(gStructTemp->c_goID));
				//memcpy(pSnifferApp_Temp->cdsname,gStructTemp->c_dataSet,strlen(gStructTemp->c_dataSet));
				//memcpy(pSnifferApp_Temp->ccbname,gStructTemp->c_gocbRef,strlen(gStructTemp->c_gocbRef));//cbname	
				//pSnifferApp_Temp->nconfrev = gStructTemp->n_confRev;
				//pSnifferApp_Temp->ndssize = gStructTemp->n_numDatSetEntries;
				//pApp->m_piec61850Analyzer->m_ptpAnalyzer.I_SET_SNIFFER_APP(pSnifferApp_Temp);
				pApp->m_piec61850Analyzer->m_ptpv2Analyzer->I_SET_SNIFFER_APP(pSnifferApp_Temp);
				delete pSnifferApp_Temp;
			}
			else
			{
				//pApp->m_piec61850Analyzer->m_ptpAnalyzer.I_SET_SNIFFER_APP(pSnifferApp);
				pApp->m_piec61850Analyzer->m_ptpv2Analyzer->I_SET_SNIFFER_APP(pSnifferApp);
			}
			struct timeval sttm;
			sttm.tv_sec=pCapMsgGinInfo->nseconds_utc_tmstamp;
			sttm.tv_usec=pCapMsgGinInfo->nus_tmstamp;
			pApp->m_piec61850Analyzer->m_ptpv2Analyzer->reset_all(&sttm);
		}
		//if((gStructTemp->u_result  &DISSECT_GOOSE_RESULT_OK)!=DISSECT_GOOSE_RESULT_OK)//格式异常 add by yzh 20130331
		//if(gStructTemp->u_result&DISSECT_GOOSE_PKTLEN_ERROR)
		//	continue;
		//pCapMsgGinInfo->pap_analyzed_info = (void*)pApp->m_piec61850Analyzer->m_ptpAnalyzer.I_PTPANALYZE((PTP_INFO_STRUCT*) pCapMsgGinInfo->pparserdstruct,1);
		pCapMsgGinInfo->pap_analyzed_info = (void*)pApp->m_piec61850Analyzer->m_ptpv2Analyzer->analyze_offline( pCapMsgGinInfo->pparserdstruct);
		pCapMsgGinInfo->berroranalyzed = true;//置位
		if(pCapMsgGinInfo->pap_analyzed_info != NULL)
		{
			pArrayStruct = (MESSAGE_ERROR_INFO_ARRAY_STRUCT*) pCapMsgGinInfo->pap_analyzed_info;
			if(pArrayStruct->n_msg_err >= 1 && pCapMsgGinInfo->nAppConetentGood)//有错误内容
			{
				if (((PTP_INFO_STRUCT*)(pCapMsgGinInfo->pparserdstruct))->u_result>0)
				{
					pConnection->map_capmsginfo_error.insert(std::map <int, CAPMSGGININFO*> :: value_type(pConnection->nerrpackages, pCapMsgGinInfo));
					pCapMsgGinInfo->nAppConetentGood = 0;//错误报文
					pConnection->nerrpackages ++;
				}
				else
				{
					pConnection->map_capmsginfo_event.insert(std::map <int, CAPMSGGININFO*> :: value_type(pConnection->neventpackages, pCapMsgGinInfo));
					pConnection->neventpackages ++;	//事件报文增加)
				}
				//将错误报文增加到队列中
				//pConnection->map_capmsginfo_error.insert(std::map <int, CAPMSGGININFO*> :: value_type(pConnection->nerrpackages, pCapMsgGinInfo));
				//pCapMsgGinInfo->nAppConetentGood = 0;//错误报文
				//pConnection->nerrpackages ++;
			}
		}
		nAnaCount ++;
	}
	strLog.Format("结束0X%xPTP链路错误分析,共有%d项错误",pConnection->csrc1_mac,pConnection->nerrpackages);
	pApp->WriteLog(strLog);
	return 0;
}
//分析smv链路
int CCapAnalyzerDoc::AnalyzeAllConnections_Smv(CAPCONNECTINFO* pConnection)
{
	CWSAnalyzerApp* pApp = (CWSAnalyzerApp*) AfxGetApp();
	CString strLog;
	strLog.Format("开始0X%xSMV链路错误分析",pConnection->ncapp_id);
	pApp->WriteLog(strLog);
	std::map <int, CAPMSGGININFO* >::iterator iter;
	CAPMSGGININFO* pCapMsgGinInfo;
	MESSAGE_ERROR_INFO_ARRAY_STRUCT* pArrayStruct;
	int nAnaCount = 0;
	SMV_INFO_STRUCT* gStructTemp;
	for(iter = pConnection->map_capmsginfo.begin(); iter != pConnection->map_capmsginfo.end(); iter ++ )
	{
		pCapMsgGinInfo = iter->second;
		if(pCapMsgGinInfo == NULL)
			continue;
		if(pCapMsgGinInfo->pparserdstruct == NULL)//尚未解析出来
			continue;
		if(pCapMsgGinInfo->napptype != PROTOAPPTYPE_SMV92)//不是采样报文
			continue;
		if(pCapMsgGinInfo->berroranalyzedsmv)//已经进行过错误分析了
			continue;
		gStructTemp = (SMV_INFO_STRUCT*) pCapMsgGinInfo->pparserdstruct;//错误报文
		//if((gStructTemp->u_result & DISSECT_SMV_RESULT_OK)!=DISSECT_SMV_RESULT_OK)
		if((gStructTemp->u_result & DISSECT_SMV_PKTLEN_ERROR))
			continue;
		if(nAnaCount == 0)//重置链路
		{
			SNIFFER_APP* pSnifferApp = pApp->m_wssysConfiguration.I_GET_IED_BYAPPID(pCapMsgGinInfo->napp_id);
			if(pSnifferApp == NULL || pSnifferApp->napptype!=PROTOAPPTYPE_SMV92)
			{
				SNIFFER_APP* pSnifferApp_Temp = new SNIFFER_APP;
				pSnifferApp_Temp->nappid = pCapMsgGinInfo->napp_id;
				memcpy(pSnifferApp_Temp->cmacaddress,pCapMsgGinInfo->csrc_mac,strlen(pCapMsgGinInfo->csrc_mac));
				gStructTemp = (SMV_INFO_STRUCT*) pCapMsgGinInfo->pparserdstruct;
				pSnifferApp_Temp->nappid = gStructTemp->n_app_id;//app_id
				//memcpy(pSnifferApp_Temp->cipaddress,pCapMsgGinInfo->csrc_ip,strlen(pCapMsgGinInfo->csrc_ip));
				if (gStructTemp->p_asdu_info_struct)
				{
					memcpy(pSnifferApp_Temp->csvid,gStructTemp->p_asdu_info_struct->c_svID,strlen(gStructTemp->p_asdu_info_struct->c_svID));
					memcpy(pSnifferApp_Temp->cdsname,gStructTemp->p_asdu_info_struct->c_dataset,strlen(gStructTemp->p_asdu_info_struct->c_dataset));
					pSnifferApp_Temp->nconfrev = gStructTemp->p_asdu_info_struct->n_confRev;
					pSnifferApp_Temp->ndssize = gStructTemp->p_asdu_info_struct->n_data_num;
				}

				pApp->m_piec61850Analyzer->m_smvAnalyzer.I_SET_SNIFFER_APP(pSnifferApp_Temp);//
				delete pSnifferApp_Temp;
			}
			else
			{
				pApp->m_piec61850Analyzer->m_smvAnalyzer.I_SET_SNIFFER_APP(pSnifferApp);
			}
		}
		pCapMsgGinInfo->pap_analyzed_info = (void*)pApp->m_piec61850Analyzer->m_smvAnalyzer.I_SMVANALYZE((SMV_INFO_STRUCT*) pCapMsgGinInfo->pparserdstruct,1);
		pCapMsgGinInfo->berroranalyzedsmv = true;//置位
		if(pCapMsgGinInfo->pap_analyzed_info != NULL)
		{
			pArrayStruct = (MESSAGE_ERROR_INFO_ARRAY_STRUCT*) pCapMsgGinInfo->pap_analyzed_info;
			if(pArrayStruct->n_msg_err >= 1 && pCapMsgGinInfo->nAppConetentGood)//有错误内容
			{
				//将错误报文增加到队列中
				pConnection->map_capmsginfo_error.insert(std::map <int, CAPMSGGININFO*> :: value_type(pConnection->nerrpackages, pCapMsgGinInfo));
				pCapMsgGinInfo->nAppConetentGood = 0;//错误报文
				pConnection->nerrpackages ++;
			}
		}
		nAnaCount ++;
	}
	strLog.Format("结束0X%x采样链路错误分析,共有%d项错误",pConnection->ncapp_id,pConnection->nerrpackages);
	pApp->WriteLog(strLog);
	return 0;
}
//分析MMS链路
int CCapAnalyzerDoc::AnalyzeAllConnections_Mms(CAPCONNECTINFO* pConnection)
{
	CWSAnalyzerApp* pApp = (CWSAnalyzerApp*) AfxGetApp();

	std::map <int, CAPMSGGININFO* >::iterator iter,iter2;
	CAPMSGGININFO* pCapMsgGinInfo;
	CAPMSGGININFO* pCapMsgGinInfo_Connect;
	int nUpdateView = 0;
	MMS_INFO_STRUCT* pMMs_Info_struct,*pMMs_Info_struct_connect;
	for(iter = pConnection->map_capmsginfo.begin(); iter != pConnection->map_capmsginfo.end(); iter ++ )
	{
		pCapMsgGinInfo = iter->second;
		nUpdateView++;
		if(pCapMsgGinInfo == NULL)
			continue;
		if(pCapMsgGinInfo->berroranalyzedmms)//是否已经分析过
			continue;
		if(pCapMsgGinInfo->pparserdstruct == NULL)//尚未解析出来
			continue;
		if(pCapMsgGinInfo->napptype != PROTOAPPTYPE_MMS)//非MMS报文
			continue;
		pCapMsgGinInfo->berroranalyzedmms = true;

		pMMs_Info_struct = (MMS_INFO_STRUCT*) pCapMsgGinInfo->pparserdstruct;

		if(strstr(pMMs_Info_struct->c_pdu_type,"Response") > 0)//回复，需要找关联的报文
		{
			pMMs_Info_struct_connect = NULL;
			for(int i=nUpdateView -2;i>=0; i--)//如果是结果，需根据invokeid追溯MMS报文服务类型
			{
				pCapMsgGinInfo_Connect = pConnection->map_capmsginfo[i];
				if(pCapMsgGinInfo_Connect == NULL)
					continue;
				if(pCapMsgGinInfo_Connect->pparserdstruct == NULL)
					continue;
				pMMs_Info_struct_connect = (MMS_INFO_STRUCT*)pCapMsgGinInfo_Connect->pparserdstruct;
				if (pMMs_Info_struct_connect->c_service_type)
				{
				}
				if(strstr(pMMs_Info_struct_connect->c_pdu_type,"Response") >0)//重复报文关联排除
				{
					continue;
				}
				if(pMMs_Info_struct_connect->n_invoke_id == pMMs_Info_struct->n_invoke_id)
				{
					pCapMsgGinInfo->pap_anlyzed_info_connect = pCapMsgGinInfo_Connect;
					pCapMsgGinInfo_Connect->pap_anlyzed_info_connect = pCapMsgGinInfo;
					//pCapMsgGinInfo->napptpye_type = pCapMsgGinInfo_Connect->napptpye_type +1;//最初invokeid相同，消息类型假设应答==请求+1。
					 
					strcpy_s(pCapMsgGinInfo->ccontent,pApp->m_pcatransformer->Get_MMS_PKT_DESC(pMMs_Info_struct,pCapMsgGinInfo->nAppConetentGood,pCapMsgGinInfo->napptpye_type));

					break;
				}
			}

		}
	}
	return 0;
}
			/*pAp_Acsi_Info = (AP_ACSI_INFO*) pCapMsgGinInfo->pap_analyzed_info;
			if(pAp_Acsi_Info->pdu_type == 2)//回复报文，需追溯报文结果
			{
				for(int i=nUpdateView -2;i>=0; i--)//如果是结果，需根据invokeid追溯MMS报文服务类型
				{
					pCapMsgGinInfo_Connect = pConnection->map_capmsginfo[i];
					if(pCapMsgGinInfo_Connect == NULL)
						continue;
					if(pCapMsgGinInfo_Connect->pap_analyzed_info == NULL)
						continue;
					pAp_Acsi_Info_Connect = (AP_ACSI_INFO*) pCapMsgGinInfo_Connect->pap_analyzed_info;
					if(pAp_Acsi_Info_Connect->invoke_id == pAp_Acsi_Info->invoke_id)
					{
						pCapMsgGinInfo->pap_anlyzed_info_connect = pAp_Acsi_Info_Connect;
						pCapMsgGinInfo_Connect->pap_anlyzed_info_connect = pAp_Acsi_Info;
						pAp_Acsi_Info->srvc_type = pAp_Acsi_Info_Connect->srvc_type;//服务类型
						break;
					}
				}
			}
			//修改MMS描述
		    CString strTempContent;
		    MMS_INFO_STRUCT* pMMsInfo = (MMS_INFO_STRUCT*)pCapMsgGinInfo->pparserdstruct;
			if(pAp_Acsi_Info->srvc_type == 12)//报告
			{
				strTempContent.Format("%s%s ",pApp->m_KeyWords61850tranformer.Get_Acsi_Type_Desc(pAp_Acsi_Info->srvc_type),
					pApp->m_KeyWords61850tranformer.Get_PduType_ChineseDesc(pMMsInfo->c_pdu_type));//*pAp_Acsi_Info->rpt_reasons报告原因：%s
			}
			else
			{
				strTempContent.Format("InvokeId:%d %s%s",pAp_Acsi_Info->invoke_id,pApp->m_KeyWords61850tranformer.Get_Acsi_Type_Desc(pAp_Acsi_Info->srvc_type),
					pApp->m_KeyWords61850tranformer.Get_PduType_ChineseDesc(pMMsInfo->c_pdu_type));
			}
			strcpy(pCapMsgGinInfo->ccontent,strTempContent);*/

CString CCapAnalyzerDoc::GetLinkDesc(CAPCONNECTINFO* pCurConnectInfo)
{
	CString strStatic,strStatic1,strTemp1,strTemp2;
	//
	if(pCurConnectInfo == &m_cappackagesmnger.m_pcapconnectinfoTotal)
	{
		strStatic.Format("全部报文[%d]帧",pCurConnectInfo->map_capmsginfo.size());		
		return strStatic;
	}
	CWSAnalyzerApp * pApp = (CWSAnalyzerApp*) AfxGetApp();
	SNIFFER_APP* pIED = NULL;

	if(pCurConnectInfo->ncapp_id >= 0)
	{
		pIED = pApp->m_wssysConfiguration.I_GET_IED_BYAPPID(pCurConnectInfo->ncapp_id);
		if(pIED != NULL)
		{
			strTemp1.Format("%s(%s)",pIED->cdesc,pIED->ciedname);
		}
	}
	if(pIED == NULL)
	{
		if(strlen(pCurConnectInfo->csrc1_ip) > 0)
		{
			strTemp1.Format("%s",pCurConnectInfo->csrc1_ip);
		}
		else
		{
			strTemp1.Format("%s",pCurConnectInfo->csrc1_mac);
		}
		pIED = pApp->m_wssysConfiguration.I_GET_IED_BYNETIDADDR(strTemp1.GetBuffer());
		strTemp1.ReleaseBuffer();
		if(pIED != NULL)
		{
			strTemp1.Format("%s(%s)",pIED->cdesc,pIED->ciedname);
		}
	}
	if(strlen(pCurConnectInfo->csrc2_ip) > 0)
	{
		strTemp2.Format("%s",pCurConnectInfo->csrc2_ip);
	}
	else
	{
		strTemp2.Format("%s",pCurConnectInfo->csrc2_mac);
	}
	pIED = pApp->m_wssysConfiguration.I_GET_IED_BYNETIDADDR(strTemp2.GetBuffer());
	strTemp2.ReleaseBuffer();
	if(pIED != NULL)
	{
		strTemp2.Format("%s(%s)",pIED->cdesc,pIED->ciedname);
	}

	if(pCurConnectInfo->ncapp_id >= 0)
	{
		if(pCurConnectInfo->nconnectapptype == PROTOAPPTYPE_SMV92)
		{
			strStatic.Format("SMV 0x%x",pCurConnectInfo->ncapp_id);
		}
		else if(pCurConnectInfo->nconnectapptype == PROTOAPPTYPE_GOOSE)
		{
			strStatic.Format("GOOSE 0x%x",pCurConnectInfo->ncapp_id);
		}
		else
		{
			;//strStatic.Format("连接%d",pCurConnectInfo->nseq);
		}
	}
	else
	{
		if(pCurConnectInfo->nconnectapptype == PROTOAPPTYPE_MMS)
		{
			strStatic.Format("MMS",pCurConnectInfo->nseq);
		}
		else
		{
			//strStatic.Format("连接%d",pCurConnectInfo->nseq);
		}
	}
	if(pCurConnectInfo->nconnectapptype == PROTOAPPTYPE_SMV92)
	{
		strStatic1.Format("%s",strTemp1);
	}
	else
	{
		strStatic1.Format("%s<-->%s",strTemp1,strTemp2);
	}

	CString strTemp;//pCurConnectInfo->m
	strTemp.Format("%s:%s",strStatic,strStatic1);
	return strTemp;
}
/************根据报文查询条件从队列中查询出对应报文****************/
int CCapAnalyzerDoc::GetNewFilterConnectionByCondition(MAP_CAPMSGINFO map_capmsginfo_src,MAP_CAPMSGINFO* pmap_capmsginfo_dst,PACKETQUER_FILTER *pQuery_Filter)
{
	return m_cappackagesmnger.GetNewFilterConnectionByCondition(map_capmsginfo_src,pmap_capmsginfo_dst,pQuery_Filter);
}

//void CCapAnalyzerDoc::OnToolbarMsgdtailShowsrc()
//{
//	// TODO: Add your command handler code here
//	CPktMsgDetailFormView* pPktMsgDetailFormView = GetPktMsgDetailFormView();
//	if(pPktMsgDetailFormView != NULL)
//	{
//		pPktMsgDetailFormView->SendMessage(ID_TOOLBAR_MSGDTAIL_SHOWSRC);
//	}
//}
//直接解析记录数据，调用wpcap读取文件
/**
* @brief	LoadCapFileDirectByWpcap   直接解析记录数据，调用wpcap读取文件，然后再调用packagecovert动态库直接解析，本函数适用于解析goose报文或者采样报文文件
* @param 	  
* @param 	
* @return	int  大于0为正常
* @notes	无
* @sample	无
*/
/*int CCapAnalyzerDoc::LoadCapFileDirectByWpcap()
{
	pcap_t* fp = NULL;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	char errbuf[PCAP_ERRBUF_SIZE];
	int nresult = 0;
	int nseq = 1;   //顺序编号
	CWSAnalyzerApp * pApp = (CWSAnalyzerApp *) AfxGetApp();
	CAPMSGGININFO  * pCapPackage = NULL;
	CMsgBrifListView*    pMsgbrifListView = GetMsgBriefListView();
	CCapPackageStatic    cappackagestic; //链路统计

    double   fFirstPackageT = 0.0f; //第一帧时间
	double   fPrePackageT = 0.0f;   //上一帧时间
	double   fPackageT =0.0f;
	CString strLog;
	strLog.Format("开始加载解析文件:%s",m_strCapFileFullPathName);
	pApp->WriteLog(strLog);
	//打开文件失败
	if ((fp = pcap_open_offline(m_strCapFileFullPathName.GetBuffer(),errbuf)) == NULL)
	{
		strLog.Format("打开解析文件:%s失败...%s",m_strCapTransformedFileName,errbuf);
		pApp->WriteLog(strLog);
		AfxMessageBox(strLog);
		return -1;
	}
	//开始逐帧读取数据
	while((nresult = pcap_next_ex(fp, &header, &pkt_data)) >= 0 && !m_bEndDoc)
	{
		//时间补偿  add by yzh 20130327
		if(header->ts.tv_usec >= pApp->m_wssysConfiguration.m_wsIec61850AnaCfg.n_smpdevdelay_tus)
		{
			header->ts.tv_usec -=pApp->m_wssysConfiguration.m_wsIec61850AnaCfg.n_smpdevdelay_tus;
		}
		else
		{
			header->ts.tv_usec = 1000000 + header->ts.tv_usec - pApp->m_wssysConfiguration.m_wsIec61850AnaCfg.n_smpdevdelay_tus;
			header->ts.tv_sec -=1;
		}
		//
		pCapPackage = LoadePacketMsg(nseq,header,pkt_data);//制作报文，TCP报文链路分析、过程层的报文(SMV,GOOSE,1588)制作
		//加入到总的报文队列
		m_cappackagesmnger.AddPacket2MnGrList(pCapPackage);

		fPackageT = header->ts.tv_sec + header->ts.tv_usec/1000000.0;
		if(nseq == 1)//第一帧
		{
			fFirstPackageT = fPackageT;
			fPrePackageT   = fPackageT;//0.0f;
		}
		pCapPackage->ftime_delta = fPackageT - fPrePackageT;     //与上一帧的时间差
		pCapPackage->ftime_relative = fPackageT - fFirstPackageT;//与第一帧报文的时间差
		//制作界面显示用的结构-，只解析102端口报文
		if(pCapPackage->napptype == ETHER_TYPE_TCP  && (pCapPackage->ndst_port == 102 || pCapPackage->nsrc_port == 102))
		{
			pApp->m_ScanDissectPacketer.I_XJ_DISSECT_PACKET(pCapPackage);
		}
		//MMS报文分析
		if (pCapPackage->napptype == IEC61850_ETHER_TYPE_MMS || pCapPackage->napptype == ETHER_TYPE_COTP || pCapPackage->napptype == ETHER_TYPE_TPKT)//设定为MMS报文
		{
			pApp->m_pcatransformer->I_XJ_PKT_STRUCT_MAKE_MMS_INFO_STRUCT(pCapPackage,TRUE);//制作MMS报文,格式错误报文也显示
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
		strcpy_s(m_cappackagesmnger.m_capparserninfo.cstarttimestamp,m_cappackagesmnger.m_pcapconnectinfoTotal.map_capmsginfo[0]->ctimestamp);
		strcpy_s(m_cappackagesmnger.m_capparserninfo.cendtimestamp,m_cappackagesmnger.m_pcapconnectinfoTotal.map_capmsginfo[nsize -1]->ctimestamp);
	}
	//关闭文件
	pcap_close(fp);
	strLog.Format("文件:%s解析完成",m_strCapFileFullPathName);
	pApp->WriteLog(strLog);

	return 0;
}*/
//加载数据包
/**
* @brief	LoadePacketMsg   加载数据包，TCP报文链路分析、过程层的报文(SMV,GOOSE,1588)制作
* @param 	  
* @param 	
* @return	int
* @notes	无
* @sample	无
*/
/*CAPMSGGININFO * CCapAnalyzerDoc::LoadePacketMsg(int nseq,pcap_pkthdr *header,const u_char *pkt_data)
{
	CWSAnalyzerApp * pApp = (CWSAnalyzerApp *) AfxGetApp();
	CAPMSGGININFO * pCapPackage = new CAPMSGGININFO;
	pCapPackage->nseq = nseq;                     //序号，从1开始编写
	memset(m_pPacket,0,sizeof(PACKET_CHAR_STRUCT));
//拷贝报文头
	memcpy(m_pPacket->c_pacekt,&header->ts.tv_sec, 4);//sec
	memcpy(m_pPacket->c_pacekt+4, &header->ts.tv_usec, 4);//usec
	memcpy(m_pPacket->c_pacekt+8, &header->caplen, 4);
	memcpy(m_pPacket->c_pacekt+12, &header->len, 4);

//	Adjust_Timestamp(m_pPacket->c_pacekt);
//拷贝报文内容
	memcpy(m_pPacket->c_pacekt+16,pkt_data,header->caplen);
	m_pPacket->nLen = header->caplen +16;
//记录原始报文
	pCapPackage->ncap_len = header->caplen;
	pCapPackage->nlen     = header->len;
//	pCapPackage->nsourceinfo_length = m_pPacket->nLen;
	pCapPackage->csourceinfo = new char[m_pPacket->nLen];
	memcpy(pCapPackage->csourceinfo,m_pPacket->c_pacekt,m_pPacket->nLen);//记录原始报文
//制作结构
//	 pApp->m_pPackageCovertWrapper->Make61850Struct_Pack2Msg(pCapPackage,m_pPacket);//TCP报文链路分析、过程层的报文(SMV,GOOSE,1588)制作
//时标戳
	CTime t(header->ts.tv_sec);
	sprintf_s(pCapPackage->ctimestamp,"%04d-%02d-%02d %02d:%02d:%02d.%06d",t.GetYear(),t.GetMonth(),t.GetDay(),t.GetHour(),t.GetMinute(),t.GetSecond(),header->ts.tv_usec);

	return pCapPackage;
}*/
/****采集装置有固定9个微秒左右的延迟，需往前调整设定时间t个微秒 yinzhehong 20130326*****/
/*int CCapAnalyzerDoc::Adjust_Timestamp(char *c_frame)
{
	CWSAnalyzerApp * pApp = (CWSAnalyzerApp *) AfxGetApp();
	//c_frame的帧格式即为标准pcap包格式
	//0-3 gmttime 抓包时间秒计时，采用小端格式
	//4-7 us      抓包时间微秒计时，自gmttime的偏移量
	unsigned int n_secs = 0;
	unsigned int n_usecs = 0;
	memcpy((char*)&n_secs,c_frame,4);
	memcpy((char*)&n_usecs,c_frame+4,4);
	if(n_usecs >= pApp->m_wssysConfiguration.m_wsIec61850AnaCfg.n_smpdevdelay_tus)
	{
		n_usecs -=pApp->m_wssysConfiguration.m_wsIec61850AnaCfg.n_smpdevdelay_tus;
		memcpy(c_frame+4,(char*)&n_usecs,4);
	}
	else
	{
		n_secs -=1;
		memcpy(c_frame,(char*)&n_secs,4);
		n_usecs = 1000000+n_usecs -pApp->m_wssysConfiguration.m_wsIec61850AnaCfg.n_smpdevdelay_tus;
		memcpy(c_frame+4,(char*)&n_usecs,4);	
	}
	return 0;
}*/
//链路分析
/**
* @brief	PackagesConnectAnalyze   链路分析
* @param 	  
* @param 	
* @return	int
* @notes	无
* @sample	无
*/
/*int CCapAnalyzerDoc::PackagesConnectAnalyze()
{
	try
	{
		//调用连接统计
		CWSAnalyzerApp * pApp = (CWSAnalyzerApp *) AfxGetApp();
		CString StrLog;
		StrLog.Format("开始链路统计");
		pApp->WriteLog(StrLog);
		//调用链路统计对象
		CCapPackageStatic capPackageStatic;
		if(capPackageStatic.StaticAllPakcageLinks(&m_cappackagesmnger.m_capparserninfo,&m_cappackagesmnger.m_pcapconnectinfoTotal.map_capmsginfo,&m_cappackagesmnger.m_mapcapconnectionfo) == 0)
		{
			StrLog.Format("完成链路统计");
			pApp->WriteLog(StrLog);
			TellViewCapLoaded(CAPLOAD_PARSERFILE_LOAD_DETAIL_OK);//告诉视图，链路分析成功，刷新概要界面
			return 0;
		}
		else
		{
			StrLog.Format("链路统计失败");
			pApp->WriteLog(StrLog);
			TellViewCapLoaded(CAPLOAD_PARSERFILE_LOAD_DETAIL_FAIL);//告诉视图，链路分析失败
			return -1;
		}
	}
	catch (CMemoryException* e)
	{
		e->Delete();
	}
	catch (CFileException* e)
	{
		e->Delete();
	}
	catch (CException* e)
	{
		e->Delete();
	}
	return -1;
}*/