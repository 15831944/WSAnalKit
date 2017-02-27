// CapAnalyzerDoc.cpp : implementation file
//

#include "stdafx.h"
#include "WSAnalyzer.h"
#include "CapAnalyzerDoc.h"
#include "MainFrm.h"



// CCapAnalyzerDoc

/**
* @brief	Thread_ParserRecordFile 	������¼�ļ��߳�
* @param 	LPVOID lParam	            CCapAnalyzerDoc ָ��        
* @param 	
* @return	UINT
* @notes	��
* @sample	��
*/
static UINT Thread_ParserRecordFile(LPVOID lParam)
{
	CCapAnalyzerDoc* pDoc = (CCapAnalyzerDoc*)lParam;
	//�����ļ�
	pDoc->ParserRecordFile();//������¼�ļ�
	return 1;

}

IMPLEMENT_DYNCREATE(CCapAnalyzerDoc, CDocument)

CCapAnalyzerDoc::CCapAnalyzerDoc()
{
	m_bLoadPackageByPackage = true; //Ĭ������֡���ط�ʽ
	m_nLoadPackages         = 1;    //Ĭ��Ϊ1
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
	m_cappackagesmnger.FreeSource();//�ͷ���Դ
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
	//֪ͨ���ν���
	CMainFrame * pMain = (CMainFrame*) AfxGetMainWnd();
	if(pMain != NULL)
		pMain->PostMessage(WM_NotifyUpdateWave, 0, NULL);
	CPktMsgDetailFormView* pView = GetPktMsgDetailFormView();
	if(pView != NULL)
	{
		pView->PostMessage(WM_NotifyUpdateWave, 0, NULL);
	}
	m_bEndDoc = TRUE;//�������߳�һ���رձ�־
	while(!m_bEndParseThread)//�ȴ��˳�
	{
		Sleep(1000);
	}
	CDocument::OnCloseDocument();
}

/**
* @brief	OnOpenDocument 	            �����ļ���Ϣ��Ӧ�������ļ����Ƽ��
* @param 	LPCTSTR lpszPathName	    �ļ�ȫ·���ַ���     
* @param 	
* @return	UINT
* @notes	��
* @sample	��
*/
BOOL CCapAnalyzerDoc::OnOpenDocument(LPCTSTR lpszPathName)
{
	CString targetTime = ((CWSAnalyzerApp*)AfxGetApp())->m_sCmdLine;

	m_fTargetTime = atof(targetTime);
	if (!CDocument::OnOpenDocument(lpszPathName))
		return FALSE;
	//�����ļ��Ƿ����
	if(_access(lpszPathName,0) == -1)//��Ҫ�ǿ��������д����������
	{
		CString strError;
		strError.Format("�ļ�%s������,���飡",lpszPathName);
		AfxMessageBox(strError);
		return FALSE;
	}
	m_strCapFileFullPathName = lpszPathName;//ȫ·��
	strcpy_s(m_cappackagesmnger.m_capparserninfo.cparserfilename,m_strCapFileFullPathName);//��¼���ṹ
	//��cap�ļ�
	if(OpenPcapFile(lpszPathName) != 0)
	{
		return FALSE;
	}
	return TRUE;
}
/**
* @brief	OpenPcapFile 	            ��pcap�ļ�,��¼�ļ�·���������ļ������߳�
* @param 	LPCTSTR lpszPathName	    �ļ�ȫ·���ַ���   
* @param 	
* @return	int                         ���������Ϊ0
* @notes	��
* @sample	��
*/
int CCapAnalyzerDoc::OpenPcapFile(LPCTSTR lpszPathName)
{
	//�����ļ���������
	if(Start_Thread_ParserRecordFile() != 0)
	{
		return -1;
	}
	return 0;
}
//��ʼ�ļ������߳�
/**
* @brief	Start_Thread_ParserRecordFile   ��ʼ�ļ������߳�
* @param 	  
* @param 	
* @return	int
* @notes	��
* @sample	��
*/
int CCapAnalyzerDoc::Start_Thread_ParserRecordFile()
{
	//����...
	AfxBeginThread(Thread_ParserRecordFile, this);
	return 0;
}
//������¼����
/**
* @brief	ParserRecordFile   ������¼���ݣ����ݽ����ܺ������������ݼ��ء����ݸ�ʽת�����������
* @param 	  
* @param 	
* @return	int
* @notes	��
* @sample	��
*/
int CCapAnalyzerDoc::ParserRecordFile()
{
	CString strPort,strLog;

	CWSAnalyzerApp * pApp = (CWSAnalyzerApp *) AfxGetApp();
	char    chDrive[MAX_PATH], chDir[MAX_PATH*2];
	char    chFilename[MAX_PATH]; 
	char    chExt[6];
	_splitpath_s( m_strCapFileFullPathName, chDrive, chDir, chFilename, chExt );
	//���ݺ�׺
	if(StrCmp(chExt,".zip") == 0 ||StrCmp(chExt,".tzip")==0 ||StrCmp(chExt,".zipx")==0)//ѹ�������ļ�
	{
		//������
#ifdef _DEBUG
#else
		strLog.Format("��¼�ļ����ڽ�ѹ��......");
		m_pDlgprogressShow->SetContent(strLog);
		m_pDlgprogressShow->ShowWindow(SW_SHOW);
#endif
		//pApp->m_zicpWrapper.UnZip_MINILZO_I(m_strCapFileFullPathName,NULL);
		m_strCapFileFullPathName.Format("%s%s%s%s",chDrive,chDir,chFilename,".pcap");
	}
#ifdef _DEBUG
#else
	strLog.Format("��¼�ļ����ڼ�����......");
	m_pDlgprogressShow->SetContent(strLog);
	m_pDlgprogressShow->ShowWindow(SW_SHOW);
#endif

	//���ɼ��˿ڣ��ɼ�װ������
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
	//����������·
#ifdef _DEBUG
#else
	strLog.Format("��¼�ļ��Ѽ��أ����ڷ�����......");
	m_pDlgprogressShow->SetContent(strLog);
	m_pDlgprogressShow->ShowWindow(SW_SHOW);
#endif
 	AnalyzeAllConnections();
	m_bEndParseThread = TRUE;
	//֪ͨ�б���������
	CCapAnalyzerView*       pCapAnalyzerView = GetCCapAnalyzerView();
	pCapAnalyzerView->UpdateShowContent(CAPLOAD_PARSERFILE_ANALYZER_NET_OK, NULL);
	//�����б��������б�
	RefreshConnectDetail(NULL,CAPSHOW_DATATYE_ALL,PROTOAPPTYPE_TOTAL);
#ifdef _DEBUG
#else
	m_pDlgprogressShow->ShowWindow(SW_HIDE);
#endif
	return 0;
}
//ֱ�ӽ�����¼���ݣ�����wpcap��ȡ�ļ�
/**
* @brief	LoadCapFileByLibpCapFileMnger   ֱ�ӽ���pcap�ļ���Ȼ���ٵ���packagecovert��̬��ֱ�ӽ����������������ڽ���goose���Ļ��߲��������ļ�
* @param 	  
* @param 	
* @return	 0���ɹ���������ʧ��
* @notes	��
* @sample	��
*/
int CCapAnalyzerDoc::LoadCapFileByLibpCapFileMnger()
{
	TS_PCAP_PKTHDR pktheader;//����ͷ
	char           *pkt_data;//������ͷ
	char errbuf[500];
	int nresult = 0;
	int nseq = 1;   //˳����
	CWSAnalyzerApp * pApp = (CWSAnalyzerApp *) AfxGetApp();
	CAPMSGGININFO  * pCapPackage = NULL;
	CCapPackageStatic    cappackagestic; //��·ͳ��

	double   fFirstPackageT = 0.0f; //��һ֡ʱ��
	double   fPrePackageT = 0.0f;   //��һ֡ʱ��
	double   fPackageT =0.0f;
	//���ļ�
	if(m_libpcapfilemnger.Libpcap_open_offline(m_strCapFileFullPathName.GetBuffer(),errbuf) == 0)
	{
		CString strLog;
		strLog.Format("�򿪽����ļ�:%sʧ��",m_strCapTransformedFileName);
		AfxMessageBox(strLog);
		return RES_FAIL;
	}

	pApp->m_pPackageCovertWrapper->setLinkType(m_libpcapfilemnger.getLinkType());
	unsigned int npktoffset = 0;
	unsigned int nmmscount = 0;//MMS���ļ���
	//��ʼ��֡��ȡ����
	while((pkt_data = m_libpcapfilemnger.Libpcap_next_cap(&pktheader,npktoffset))!= NULL && !m_bEndDoc)
	{
		pCapPackage = LoadePacketMsg(nseq,&pktheader,pkt_data);//�������ģ�TCP������·���������̲�ı���(SMV,GOOSE,1588)����
		pCapPackage->npkt_offset_incapfile = npktoffset;
		//���뵽�ܵı��Ķ���
		m_cappackagesmnger.AddPacket2MnGrList(pCapPackage);

		fPackageT = pktheader.ts.GmtTime + pktheader.ts.us/1000000.0;
		if(nseq == 1)//��һ֡
		{
			fFirstPackageT = fPackageT;
			fPrePackageT   = fPackageT;//0.0f;
		}

#ifdef _DEBUG
		TRACE("nseq:%d\r\n",nseq);
#endif
		pCapPackage->ftime_delta = fPackageT - fPrePackageT;     //����һ֡��ʱ���
		pCapPackage->ftime_relative = fPackageT - fFirstPackageT;//���һ֡���ĵ�ʱ���
		//����������ʾ�õĽṹ-��ֻ����102�˿ڱ���,���������Ĳ�����
		if(pCapPackage->napptype == ETHER_TYPE_TCP  && (pCapPackage->ndst_port == 102 || pCapPackage->nsrc_port == 102) 
			/*&& (pCapPackage->ncap_len > 90)*/)//�ر��ļ������86�ֽڣ�Ӧ���82�ֽ� //66������ +7 COPT+TPKT��ͷ
		{
			nmmscount ++;
			pApp->m_ScanDissectPacketer.I_XJ_DISSECT_MMS_PACKET(pCapPackage,nmmscount);
			//MMS���ķ���
			if (pCapPackage->napptype == IEC61850_ETHER_TYPE_MMS || pCapPackage->napptype == ETHER_TYPE_COTP || pCapPackage->napptype == ETHER_TYPE_TPKT)//�趨ΪMMS����
			{
				pApp->m_pcatransformer->I_XJ_PKT_STRUCT_MAKE_MMS_INFO_STRUCT(pCapPackage,TRUE);//����MMS����,��ʽ�����Ĳ���ʾ
				//�ͷ���Դ	
				//pApp->m_pcatransformer->I_ReleaseMMSInfoStruct((MMS_INFO_STRUCT *)pCapPackage->pparserdstruct);
				//pCapPackage->pparserdstruct = NULL;
			}
			pApp->m_ScanDissectPacketer.I_XJ_CLEANUP_PACKET(pCapPackage->pxj_dissect_pkt);//�ͷ���Դ
			pCapPackage->pxj_dissect_pkt = NULL;
		}
		//ͳ��һ��
		cappackagestic.StaticPackageLink(&m_cappackagesmnger.m_capparserninfo,pCapPackage,&m_cappackagesmnger.m_mapcapconnectionfo);
		nseq++;//���+1
		fPrePackageT = fPackageT;//��¼��һ֡ʱ��
	}
	m_cappackagesmnger.m_capparserninfo.napppackages = nseq-1;//��֡��
	//�ļ��Ŀ�ʼʱ��ͽ���ʱ��
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
	pCapPackage->nseq = nseq;                     //��ţ���1��ʼ��д
//	memset(m_pPacket,0,sizeof(PACKET_CHAR_STRUCT));
	//��¼����
	m_pPacket->nLen = pkthdr->caplen +sizeof(TS_PCAP_PKTHDR);
	m_pPacket->pPacket  = pkt;//������ʼָ��
	//��¼ԭʼ����
	pCapPackage->ncap_len = pkthdr->caplen;
	pCapPackage->nlen     = pkthdr->len;
	pCapPackage->nsourceinfo_length = m_pPacket->nLen;
	pCapPackage->csourceinfo = pkt; //ֱ�Ӹ�ָ�룬����һ�θ���
//	pCapPackage->csourceinfo = new char[pCapPackage->nsourceinfo_length];
//	memcpy(pCapPackage->csourceinfo,pkt,pCapPackage->nsourceinfo_length);
	//�����ṹ
	pApp->m_pPackageCovertWrapper->Make61850Struct_Pack2Msg(pCapPackage,m_pPacket);//TCP������·���������̲�ı���(SMV,GOOSE,1588)����
	//ʱ���
	pCapPackage->nseconds_utc_tmstamp = pkthdr->ts.GmtTime;
	pCapPackage->nus_tmstamp          = pkthdr->ts.us;
	return pCapPackage;
}
//���ַ��������ͼ֪ͨ
/**
* @brief	PackagesConnectAnalyze   ��ͼ֪ͨ�����ڱ������ڶ��߳��б����ò�������Ϣ֪ͨ����ʵ�֣�ֱ�ӵ�����ͼ����
* @param 	  
* @param 	
* @return	int
* @notes	��
* @sample	��
*/
//int CCapAnalyzerDoc::TellViewCapLoaded(int nType)
//{
////������ɣ�֪ͨ����
////	UpdateAllViews(NULL,nType,NULL);//����Ϊ1����ʾ�ļ������ɹ����,�ĺ����޷��ڶ��߳��е���
//	CView* pView;
//	CMsgBrifListView*      pMsgBrifListView;
//	CCapAnalyzerView*      pCapAnalyzerView;
//	POSITION pos=GetFirstViewPosition();
//	while(pos!=NULL)
//	{
//		pView = GetNextView(pos);
//		if(pView->IsKindOf(RUNTIME_CLASS(CMsgBrifListView)))//��ϸ��ͼ
//		{
//			pMsgBrifListView = (CMsgBrifListView*) pView;
//			pMsgBrifListView->UpdateShowContent(nType,NULL,CAPSHOW_DATATYE_ALL,m_fTargetTime);
//		}
//		else if(pView->IsKindOf(RUNTIME_CLASS(CCapAnalyzerView)))//��Ҫ��ͼ
//		{
//			pCapAnalyzerView = (CCapAnalyzerView *) pView;
//			pCapAnalyzerView->UpdateShowContent(nType,NULL);
//		}
//	}
//	return 0;
//}

//���ַ��������ͼ֪ͨ
/**
* @brief	GetCapFileFullPathName   �õ��ļ����ص�ȫ·�����ļ���
* @param 	
* @param 	
* @return	CString                  �ļ����ص�ȫ·�����ļ���
* @notes	��
* @sample	��
*/
CString CCapAnalyzerDoc::GetCapFileFullPathName(void)
{
	return m_strCapFileFullPathName;
}
//�õ���ϸ������ͼ
/**
* @brief	GetMsgBriefListView   �õ���ϸ������ͼ
* @param 	
* @param 	
* @return
* @notes	��
* @sample	��
*/
CMsgBrifListView* CCapAnalyzerDoc::GetMsgBriefListView()
{
	CView* pView;
	CMsgBrifListView* pMsgBrifListView = NULL;
	POSITION pos = GetFirstViewPosition();
	while(pos!=NULL)
	{
		pView = GetNextView(pos);
		if(pView->IsKindOf(RUNTIME_CLASS(CMsgBrifListView)))//�õ���ϸ��ͼ
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
		if(pView->IsKindOf(RUNTIME_CLASS(CPktLinkBriefView)))//�õ���ϸ��ͼ
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
		if(pView->IsKindOf(RUNTIME_CLASS(CPktMsgDetailFormView)))//�õ���ϸ��ͼ
		{
			pMsgMsgDtailFormView = (CPktMsgDetailFormView*) pView;
			break;
		}
	}
	return pMsgMsgDtailFormView;
}
//�õ���Ҫ������ͼ
/**
* @brief	GetCCapAnalyzerView   �õ���Ҫ������ͼ
* @param 	
* @param 	
* @return
* @notes	��
* @sample	��
*/
CCapAnalyzerView* CCapAnalyzerDoc::GetCCapAnalyzerView()
{
	CView* pView;
	CCapAnalyzerView*       pCapAnalyzerView = NULL;;
	POSITION pos = GetFirstViewPosition();
	while(pos!=NULL)
	{
		pView = GetNextView(pos);
		if(pView->IsKindOf(RUNTIME_CLASS(CCapAnalyzerView)))//�õ���Ҫ��ͼ
		{
			pCapAnalyzerView = (CCapAnalyzerView *) pView;
			break;
		}
	}
	return pCapAnalyzerView;
}
//ˢ������
//* @param 	int nDataShowtype         1���쳣���� 2���¼�����  ����ֵ�����б��� 
int CCapAnalyzerDoc::RefreshConnectDetail(CAPCONNECTINFO* pcapconnectinfo,int nDataShowtype,int npcapconnectType)
{
	//��ȡ����
	if(pcapconnectinfo == NULL )
	{
		pcapconnectinfo = m_cappackagesmnger.GetPcapconnetInfo(npcapconnectType);//��ȡ��������
	}
	if(pcapconnectinfo == NULL)//û�л�ȡ����Ӧ�Ľڵ�
		return -1;
	//֪ͨ��Ҫ�б����ν���
	CPktLinkBriefView* pPktLinkBriefView = GetPktLinkBriefView();
	if(pPktLinkBriefView)
	{
		pPktLinkBriefView->PostMessage(WM_NotifyUpdateWave, WPARAM(nDataShowtype), (LPARAM)pcapconnectinfo);
	}
	//֪ͨ��ϸ��������
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
//* @param 	int nDataShowtype         1���쳣���� 2���¼�����  ����ֵ�����б��� 
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
//ˢ�²��δ��ڶ�Ӧ���α�λ�ö�Ӧ�Ĳ�����λ��
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
//������������
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
			//COPT list���� add by yinzhehong 20120319
			pApp->m_pPackageCovertWrapper->COTP_LIST_ANALYZE(pConnection);
			//�����ķ���
			AnalyzeAllConnections_Mms(pConnection);
		}
		else if(pConnection->nconnectapptype == PROTOAPPTYPE_TIME1588)
		{
			AnalyzeAllConnection_Ptp(pConnection);
		}
		m_cappackagesmnger.m_pcapconnectinfoTotal.nerrpackages += pConnection->nerrpackages;//�ܵĴ����
	}
	//pView->InvalidateListCtrl();
	return 0;
}
//����Gs��·
int CCapAnalyzerDoc::AnalyzeAllConnections_Gs(CAPCONNECTINFO* pConnection)
{
	CWSAnalyzerApp* pApp = (CWSAnalyzerApp*) AfxGetApp();
	CString strLog;
	strLog.Format("��ʼ0X%xGOOSE��·�������",pConnection->ncapp_id);
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
		if(pCapMsgGinInfo->pparserdstruct == NULL)//��δ��������
			continue;
		if(pCapMsgGinInfo->napptype != PROTOAPPTYPE_GOOSE)//����GOOSE����
			continue;
		if(pCapMsgGinInfo->berroranalyzedgoose)//�Ѿ����й����������
			continue;
		gStructTemp = (GOOSE_INFO_STRUCT*) pCapMsgGinInfo->pparserdstruct;
		//if((gStructTemp->u_result  &DISSECT_GOOSE_RESULT_OK)!=DISSECT_GOOSE_RESULT_OK)//��ʽ�쳣 add by yzh 20130331
		if(gStructTemp->u_result&DISSECT_GOOSE_PKTLEN_ERROR)
			continue;
		if(nAnaCount == 0)//������·
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
		pCapMsgGinInfo->berroranalyzedgoose = true;//��λ
		if(pCapMsgGinInfo->pap_analyzed_info != NULL)
		{
			pArrayStruct = (MESSAGE_ERROR_INFO_ARRAY_STRUCT*) pCapMsgGinInfo->pap_analyzed_info;
			if(pArrayStruct->n_msg_err >= 1 && pCapMsgGinInfo->nAppConetentGood )//�з��������¼�����δ���ָ�ʽ���������ʽ����󲻽��з��������Բ�������µ�n_msg_err,���������ʽ����������������Ա����ظ����룩
			{
				pCapMsgGinInfo->nAppConetentGood = 0;//������
				//�¼�����
				BOOL bEventPackage = FALSE;
				for(int i = 0; i< pArrayStruct->n_msg_err; i++)
				{
					for(int j = 0; j < pArrayStruct->p_msg_err[i].n_num_asduerr; j++)//ͳ��asdu�еĴ���
					{
						for(int k = 0; k < pArrayStruct->p_msg_err[i].p_asduerr[j].n_num_errcode; k++)
						{
							if(pArrayStruct->p_msg_err[i].p_asduerr[j].p_errcode[k] == 24)//GOOSE��λ�¼��������⴦��
							{
								bEventPackage = TRUE;
								pCapMsgGinInfo->beventanalyzedgoose = true;//goose��λ�¼�
								 break;
							}
						}
					}
				}
				if(!bEventPackage)
				{
					//�����������ӵ�������
					pConnection->map_capmsginfo_error.insert(std::map <int, CAPMSGGININFO*> :: value_type(pConnection->nerrpackages, pCapMsgGinInfo));
					pConnection->nerrpackages ++;//����������
				}
				else
				{
					pConnection->map_capmsginfo_event.insert(std::map <int, CAPMSGGININFO*> :: value_type(pConnection->neventpackages, pCapMsgGinInfo));
					pConnection->neventpackages ++;	//�¼���������)
				}
			}
		}
		nAnaCount ++;
	}
	strLog.Format("����0X%xGOOSE��·�������,����%d�����",pConnection->ncapp_id,pConnection->nerrpackages);
	pApp->WriteLog(strLog);
	return 0;
}
//������·����
int CCapAnalyzerDoc::AnalyzeAllConnection_Ptp(CAPCONNECTINFO* pConnection)
{
	//CPTPAO Ao(0, NULL);
	CWSAnalyzerApp* pApp = (CWSAnalyzerApp*) AfxGetApp();
	CString strLog;
	strLog.Format("��ʼ%s PTP��·�������",pConnection->csrc1_mac);
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
		if(pCapMsgGinInfo->pparserdstruct == NULL)//��δ��������
			continue;
		if(pCapMsgGinInfo->napptype != PROTOAPPTYPE_TIME1588)//����GOOSE����
			continue;
		if(pCapMsgGinInfo->berroranalyzed)//�Ѿ����й����������
			continue;
		gStructTemp = (PTP_INFO_STRUCT*) pCapMsgGinInfo->pparserdstruct;


		if(nAnaCount == 0)//������·
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
		//if((gStructTemp->u_result  &DISSECT_GOOSE_RESULT_OK)!=DISSECT_GOOSE_RESULT_OK)//��ʽ�쳣 add by yzh 20130331
		//if(gStructTemp->u_result&DISSECT_GOOSE_PKTLEN_ERROR)
		//	continue;
		//pCapMsgGinInfo->pap_analyzed_info = (void*)pApp->m_piec61850Analyzer->m_ptpAnalyzer.I_PTPANALYZE((PTP_INFO_STRUCT*) pCapMsgGinInfo->pparserdstruct,1);
		pCapMsgGinInfo->pap_analyzed_info = (void*)pApp->m_piec61850Analyzer->m_ptpv2Analyzer->analyze_offline( pCapMsgGinInfo->pparserdstruct);
		pCapMsgGinInfo->berroranalyzed = true;//��λ
		if(pCapMsgGinInfo->pap_analyzed_info != NULL)
		{
			pArrayStruct = (MESSAGE_ERROR_INFO_ARRAY_STRUCT*) pCapMsgGinInfo->pap_analyzed_info;
			if(pArrayStruct->n_msg_err >= 1 && pCapMsgGinInfo->nAppConetentGood)//�д�������
			{
				if (((PTP_INFO_STRUCT*)(pCapMsgGinInfo->pparserdstruct))->u_result>0)
				{
					pConnection->map_capmsginfo_error.insert(std::map <int, CAPMSGGININFO*> :: value_type(pConnection->nerrpackages, pCapMsgGinInfo));
					pCapMsgGinInfo->nAppConetentGood = 0;//������
					pConnection->nerrpackages ++;
				}
				else
				{
					pConnection->map_capmsginfo_event.insert(std::map <int, CAPMSGGININFO*> :: value_type(pConnection->neventpackages, pCapMsgGinInfo));
					pConnection->neventpackages ++;	//�¼���������)
				}
				//�����������ӵ�������
				//pConnection->map_capmsginfo_error.insert(std::map <int, CAPMSGGININFO*> :: value_type(pConnection->nerrpackages, pCapMsgGinInfo));
				//pCapMsgGinInfo->nAppConetentGood = 0;//������
				//pConnection->nerrpackages ++;
			}
		}
		nAnaCount ++;
	}
	strLog.Format("����0X%xPTP��·�������,����%d�����",pConnection->csrc1_mac,pConnection->nerrpackages);
	pApp->WriteLog(strLog);
	return 0;
}
//����smv��·
int CCapAnalyzerDoc::AnalyzeAllConnections_Smv(CAPCONNECTINFO* pConnection)
{
	CWSAnalyzerApp* pApp = (CWSAnalyzerApp*) AfxGetApp();
	CString strLog;
	strLog.Format("��ʼ0X%xSMV��·�������",pConnection->ncapp_id);
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
		if(pCapMsgGinInfo->pparserdstruct == NULL)//��δ��������
			continue;
		if(pCapMsgGinInfo->napptype != PROTOAPPTYPE_SMV92)//���ǲ�������
			continue;
		if(pCapMsgGinInfo->berroranalyzedsmv)//�Ѿ����й����������
			continue;
		gStructTemp = (SMV_INFO_STRUCT*) pCapMsgGinInfo->pparserdstruct;//������
		//if((gStructTemp->u_result & DISSECT_SMV_RESULT_OK)!=DISSECT_SMV_RESULT_OK)
		if((gStructTemp->u_result & DISSECT_SMV_PKTLEN_ERROR))
			continue;
		if(nAnaCount == 0)//������·
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
		pCapMsgGinInfo->berroranalyzedsmv = true;//��λ
		if(pCapMsgGinInfo->pap_analyzed_info != NULL)
		{
			pArrayStruct = (MESSAGE_ERROR_INFO_ARRAY_STRUCT*) pCapMsgGinInfo->pap_analyzed_info;
			if(pArrayStruct->n_msg_err >= 1 && pCapMsgGinInfo->nAppConetentGood)//�д�������
			{
				//�����������ӵ�������
				pConnection->map_capmsginfo_error.insert(std::map <int, CAPMSGGININFO*> :: value_type(pConnection->nerrpackages, pCapMsgGinInfo));
				pCapMsgGinInfo->nAppConetentGood = 0;//������
				pConnection->nerrpackages ++;
			}
		}
		nAnaCount ++;
	}
	strLog.Format("����0X%x������·�������,����%d�����",pConnection->ncapp_id,pConnection->nerrpackages);
	pApp->WriteLog(strLog);
	return 0;
}
//����MMS��·
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
		if(pCapMsgGinInfo->berroranalyzedmms)//�Ƿ��Ѿ�������
			continue;
		if(pCapMsgGinInfo->pparserdstruct == NULL)//��δ��������
			continue;
		if(pCapMsgGinInfo->napptype != PROTOAPPTYPE_MMS)//��MMS����
			continue;
		pCapMsgGinInfo->berroranalyzedmms = true;

		pMMs_Info_struct = (MMS_INFO_STRUCT*) pCapMsgGinInfo->pparserdstruct;

		if(strstr(pMMs_Info_struct->c_pdu_type,"Response") > 0)//�ظ�����Ҫ�ҹ����ı���
		{
			pMMs_Info_struct_connect = NULL;
			for(int i=nUpdateView -2;i>=0; i--)//����ǽ���������invokeid׷��MMS���ķ�������
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
				if(strstr(pMMs_Info_struct_connect->c_pdu_type,"Response") >0)//�ظ����Ĺ����ų�
				{
					continue;
				}
				if(pMMs_Info_struct_connect->n_invoke_id == pMMs_Info_struct->n_invoke_id)
				{
					pCapMsgGinInfo->pap_anlyzed_info_connect = pCapMsgGinInfo_Connect;
					pCapMsgGinInfo_Connect->pap_anlyzed_info_connect = pCapMsgGinInfo;
					//pCapMsgGinInfo->napptpye_type = pCapMsgGinInfo_Connect->napptpye_type +1;//���invokeid��ͬ����Ϣ���ͼ���Ӧ��==����+1��
					 
					strcpy_s(pCapMsgGinInfo->ccontent,pApp->m_pcatransformer->Get_MMS_PKT_DESC(pMMs_Info_struct,pCapMsgGinInfo->nAppConetentGood,pCapMsgGinInfo->napptpye_type));

					break;
				}
			}

		}
	}
	return 0;
}
			/*pAp_Acsi_Info = (AP_ACSI_INFO*) pCapMsgGinInfo->pap_analyzed_info;
			if(pAp_Acsi_Info->pdu_type == 2)//�ظ����ģ���׷�ݱ��Ľ��
			{
				for(int i=nUpdateView -2;i>=0; i--)//����ǽ���������invokeid׷��MMS���ķ�������
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
						pAp_Acsi_Info->srvc_type = pAp_Acsi_Info_Connect->srvc_type;//��������
						break;
					}
				}
			}
			//�޸�MMS����
		    CString strTempContent;
		    MMS_INFO_STRUCT* pMMsInfo = (MMS_INFO_STRUCT*)pCapMsgGinInfo->pparserdstruct;
			if(pAp_Acsi_Info->srvc_type == 12)//����
			{
				strTempContent.Format("%s%s ",pApp->m_KeyWords61850tranformer.Get_Acsi_Type_Desc(pAp_Acsi_Info->srvc_type),
					pApp->m_KeyWords61850tranformer.Get_PduType_ChineseDesc(pMMsInfo->c_pdu_type));//*pAp_Acsi_Info->rpt_reasons����ԭ��%s
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
		strStatic.Format("ȫ������[%d]֡",pCurConnectInfo->map_capmsginfo.size());		
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
			;//strStatic.Format("����%d",pCurConnectInfo->nseq);
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
			//strStatic.Format("����%d",pCurConnectInfo->nseq);
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
/************���ݱ��Ĳ�ѯ�����Ӷ����в�ѯ����Ӧ����****************/
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
//ֱ�ӽ�����¼���ݣ�����wpcap��ȡ�ļ�
/**
* @brief	LoadCapFileDirectByWpcap   ֱ�ӽ�����¼���ݣ�����wpcap��ȡ�ļ���Ȼ���ٵ���packagecovert��̬��ֱ�ӽ����������������ڽ���goose���Ļ��߲��������ļ�
* @param 	  
* @param 	
* @return	int  ����0Ϊ����
* @notes	��
* @sample	��
*/
/*int CCapAnalyzerDoc::LoadCapFileDirectByWpcap()
{
	pcap_t* fp = NULL;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	char errbuf[PCAP_ERRBUF_SIZE];
	int nresult = 0;
	int nseq = 1;   //˳����
	CWSAnalyzerApp * pApp = (CWSAnalyzerApp *) AfxGetApp();
	CAPMSGGININFO  * pCapPackage = NULL;
	CMsgBrifListView*    pMsgbrifListView = GetMsgBriefListView();
	CCapPackageStatic    cappackagestic; //��·ͳ��

    double   fFirstPackageT = 0.0f; //��һ֡ʱ��
	double   fPrePackageT = 0.0f;   //��һ֡ʱ��
	double   fPackageT =0.0f;
	CString strLog;
	strLog.Format("��ʼ���ؽ����ļ�:%s",m_strCapFileFullPathName);
	pApp->WriteLog(strLog);
	//���ļ�ʧ��
	if ((fp = pcap_open_offline(m_strCapFileFullPathName.GetBuffer(),errbuf)) == NULL)
	{
		strLog.Format("�򿪽����ļ�:%sʧ��...%s",m_strCapTransformedFileName,errbuf);
		pApp->WriteLog(strLog);
		AfxMessageBox(strLog);
		return -1;
	}
	//��ʼ��֡��ȡ����
	while((nresult = pcap_next_ex(fp, &header, &pkt_data)) >= 0 && !m_bEndDoc)
	{
		//ʱ�䲹��  add by yzh 20130327
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
		pCapPackage = LoadePacketMsg(nseq,header,pkt_data);//�������ģ�TCP������·���������̲�ı���(SMV,GOOSE,1588)����
		//���뵽�ܵı��Ķ���
		m_cappackagesmnger.AddPacket2MnGrList(pCapPackage);

		fPackageT = header->ts.tv_sec + header->ts.tv_usec/1000000.0;
		if(nseq == 1)//��һ֡
		{
			fFirstPackageT = fPackageT;
			fPrePackageT   = fPackageT;//0.0f;
		}
		pCapPackage->ftime_delta = fPackageT - fPrePackageT;     //����һ֡��ʱ���
		pCapPackage->ftime_relative = fPackageT - fFirstPackageT;//���һ֡���ĵ�ʱ���
		//����������ʾ�õĽṹ-��ֻ����102�˿ڱ���
		if(pCapPackage->napptype == ETHER_TYPE_TCP  && (pCapPackage->ndst_port == 102 || pCapPackage->nsrc_port == 102))
		{
			pApp->m_ScanDissectPacketer.I_XJ_DISSECT_PACKET(pCapPackage);
		}
		//MMS���ķ���
		if (pCapPackage->napptype == IEC61850_ETHER_TYPE_MMS || pCapPackage->napptype == ETHER_TYPE_COTP || pCapPackage->napptype == ETHER_TYPE_TPKT)//�趨ΪMMS����
		{
			pApp->m_pcatransformer->I_XJ_PKT_STRUCT_MAKE_MMS_INFO_STRUCT(pCapPackage,TRUE);//����MMS����,��ʽ������Ҳ��ʾ
		}
		//ͳ��һ��
		cappackagestic.StaticPackageLink(&m_cappackagesmnger.m_capparserninfo,pCapPackage,&m_cappackagesmnger.m_mapcapconnectionfo);
		nseq++;//���+1
		fPrePackageT = fPackageT;//��¼��һ֡ʱ��
	}
	m_cappackagesmnger.m_capparserninfo.napppackages = nseq-1;//��֡��
	//�ļ��Ŀ�ʼʱ��ͽ���ʱ��
	int nsize = m_cappackagesmnger.m_pcapconnectinfoTotal.map_capmsginfo.size();
	if(nsize  > 1)
	{
		strcpy_s(m_cappackagesmnger.m_capparserninfo.cstarttimestamp,m_cappackagesmnger.m_pcapconnectinfoTotal.map_capmsginfo[0]->ctimestamp);
		strcpy_s(m_cappackagesmnger.m_capparserninfo.cendtimestamp,m_cappackagesmnger.m_pcapconnectinfoTotal.map_capmsginfo[nsize -1]->ctimestamp);
	}
	//�ر��ļ�
	pcap_close(fp);
	strLog.Format("�ļ�:%s�������",m_strCapFileFullPathName);
	pApp->WriteLog(strLog);

	return 0;
}*/
//�������ݰ�
/**
* @brief	LoadePacketMsg   �������ݰ���TCP������·���������̲�ı���(SMV,GOOSE,1588)����
* @param 	  
* @param 	
* @return	int
* @notes	��
* @sample	��
*/
/*CAPMSGGININFO * CCapAnalyzerDoc::LoadePacketMsg(int nseq,pcap_pkthdr *header,const u_char *pkt_data)
{
	CWSAnalyzerApp * pApp = (CWSAnalyzerApp *) AfxGetApp();
	CAPMSGGININFO * pCapPackage = new CAPMSGGININFO;
	pCapPackage->nseq = nseq;                     //��ţ���1��ʼ��д
	memset(m_pPacket,0,sizeof(PACKET_CHAR_STRUCT));
//��������ͷ
	memcpy(m_pPacket->c_pacekt,&header->ts.tv_sec, 4);//sec
	memcpy(m_pPacket->c_pacekt+4, &header->ts.tv_usec, 4);//usec
	memcpy(m_pPacket->c_pacekt+8, &header->caplen, 4);
	memcpy(m_pPacket->c_pacekt+12, &header->len, 4);

//	Adjust_Timestamp(m_pPacket->c_pacekt);
//������������
	memcpy(m_pPacket->c_pacekt+16,pkt_data,header->caplen);
	m_pPacket->nLen = header->caplen +16;
//��¼ԭʼ����
	pCapPackage->ncap_len = header->caplen;
	pCapPackage->nlen     = header->len;
//	pCapPackage->nsourceinfo_length = m_pPacket->nLen;
	pCapPackage->csourceinfo = new char[m_pPacket->nLen];
	memcpy(pCapPackage->csourceinfo,m_pPacket->c_pacekt,m_pPacket->nLen);//��¼ԭʼ����
//�����ṹ
//	 pApp->m_pPackageCovertWrapper->Make61850Struct_Pack2Msg(pCapPackage,m_pPacket);//TCP������·���������̲�ı���(SMV,GOOSE,1588)����
//ʱ���
	CTime t(header->ts.tv_sec);
	sprintf_s(pCapPackage->ctimestamp,"%04d-%02d-%02d %02d:%02d:%02d.%06d",t.GetYear(),t.GetMonth(),t.GetDay(),t.GetHour(),t.GetMinute(),t.GetSecond(),header->ts.tv_usec);

	return pCapPackage;
}*/
/****�ɼ�װ���й̶�9��΢�����ҵ��ӳ٣�����ǰ�����趨ʱ��t��΢�� yinzhehong 20130326*****/
/*int CCapAnalyzerDoc::Adjust_Timestamp(char *c_frame)
{
	CWSAnalyzerApp * pApp = (CWSAnalyzerApp *) AfxGetApp();
	//c_frame��֡��ʽ��Ϊ��׼pcap����ʽ
	//0-3 gmttime ץ��ʱ�����ʱ������С�˸�ʽ
	//4-7 us      ץ��ʱ��΢���ʱ����gmttime��ƫ����
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
//��·����
/**
* @brief	PackagesConnectAnalyze   ��·����
* @param 	  
* @param 	
* @return	int
* @notes	��
* @sample	��
*/
/*int CCapAnalyzerDoc::PackagesConnectAnalyze()
{
	try
	{
		//��������ͳ��
		CWSAnalyzerApp * pApp = (CWSAnalyzerApp *) AfxGetApp();
		CString StrLog;
		StrLog.Format("��ʼ��·ͳ��");
		pApp->WriteLog(StrLog);
		//������·ͳ�ƶ���
		CCapPackageStatic capPackageStatic;
		if(capPackageStatic.StaticAllPakcageLinks(&m_cappackagesmnger.m_capparserninfo,&m_cappackagesmnger.m_pcapconnectinfoTotal.map_capmsginfo,&m_cappackagesmnger.m_mapcapconnectionfo) == 0)
		{
			StrLog.Format("�����·ͳ��");
			pApp->WriteLog(StrLog);
			TellViewCapLoaded(CAPLOAD_PARSERFILE_LOAD_DETAIL_OK);//������ͼ����·�����ɹ���ˢ�¸�Ҫ����
			return 0;
		}
		else
		{
			StrLog.Format("��·ͳ��ʧ��");
			pApp->WriteLog(StrLog);
			TellViewCapLoaded(CAPLOAD_PARSERFILE_LOAD_DETAIL_FAIL);//������ͼ����·����ʧ��
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