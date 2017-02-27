#pragma once
#include "../capanalyzer/CapPackagesMnger.h"
//#include "../capanalyzer/CapXmlAnalyzer.h"	//����xml��ʽ
#include "../capanalyzer/CapTxtAnalyzer.h"	//����txt�ı�
#include "../capanalyzer/CapPackageStatic.h"//��ͳ��
#include <fstream>
#include <io.h>//���ڼ��·���Ƿ����
//#include <pcap.h>//wpcap������
#include "DlgProgressShow.h"
#include "CapAnalyzerView.h"
#include "MsgBrifListView.h"
#include "PktMsgDetailFormView.h"
#include "PktLinkBriefView.h"
#include "LibpCapFileMnger.h"
/**
 * @brief       class name: CCapAnalyzerDoc
 * @use			pcap�ļ����ء�������ͳ��
					 1�����÷�װwireshark�ӿڽ���pcap�ļ������ɽ����ļ�
					 2��������ؽ����ļ��е�����
					 3�����ع������������ͳ�ƣ����ɼ�Ҫͳ����Ϣ
 * @author      �����
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
/* ����Ϊ��չ��������                                  */
/************************************************************************/            
public:
	// �򿪽����ļ�
	int OpenPcapFile(LPCTSTR lpszPathName);	
	//��ʼ�ļ������߳�
	int Start_Thread_ParserRecordFile(); 
	//������¼�ļ�
	int ParserRecordFile();	
	//��·����
//	int PackagesConnectAnalyze();
	//֪ͨ�������
	int TellViewCapLoaded(int nType);
	// �õ��ļ�����ȫ·��
	CString GetCapFileFullPathName(void);
	//�õ���Ҫ�����б���ͼ
	CMsgBrifListView*       GetMsgBriefListView();
	//�õ�����������ͼ
	CPktLinkBriefView*      GetPktLinkBriefView();
//	CCapAnalyzerDetailView* GetCapAnalyzerDetailView();
	//�õ���Ҫ������ͼ
	CCapAnalyzerView* GetCCapAnalyzerView();
	//
	CPktMsgDetailFormView* GetPktMsgDetailFormView();

	//ˢ������
	int RefreshConnectDetail(CAPCONNECTINFO* pcapconnectinfo,int nDataShowtype,int npcapconnectType);
	//ˢ�����ӣ�����Ϊ����
	int RefreshConnectDetail_SetFocus(CAPCONNECTINFO* pcapconnectinfo,int nDataShowtype,int ncapconnectType);
	//ˢ�²����α�ѡ����λ��
	int RefreshWaveCoursorPosition(WPARAM wParam, LPARAM lParam);
	//������������
	int AnalyzeAllConnections();
	//����ACSI��·
	int AnalyzeAllConnections_Mms(CAPCONNECTINFO* pConnection);
	//����Gs��·
	int AnalyzeAllConnections_Gs(CAPCONNECTINFO* pConnection);
	//����Gs��·
	int AnalyzeAllConnection_Ptp(CAPCONNECTINFO* pConnection);
	//����smv��·
	int AnalyzeAllConnections_Smv(CAPCONNECTINFO* pConnection);
	/*******��ȡ���ӵ�������Ϣ******/
	CString GetLinkDesc(CAPCONNECTINFO* pCurConnectInfo);
	/************���ݱ��Ĳ�ѯ�����Ӷ����в�ѯ����Ӧ����****************/
	int GetNewFilterConnectionByCondition(MAP_CAPMSGINFO map_capmsginfo_src,MAP_CAPMSGINFO* pmap_capmsginfo_dst,PACKETQUER_FILTER *pQuery_Filter);
private:
	//ֱ��ͨ��wcap�����ļ�
//	int LoadCapFileDirectByWpcap();
	//********ֱ�Ӽ���ͨ���Լ���pcap�ļ�������************/
	int LoadCapFileByLibpCapFileMnger();
	CAPMSGGININFO * LoadePacketMsg(int nseq,TS_PCAP_PKTHDR* pkthdr,char *pkt);
	//****�������ݰ�****//
//	CAPMSGGININFO * LoadePacketMsg(int nseq,pcap_pkthdr *header,const u_char *pkt_data);

//	int Adjust_Timestamp(char *c_frame);

/************************************************************************/
/*����Ϊ���Բ���                                  */
/************************************************************************/
public:
	//��Ӧ��pcap�ļ�ȫ·������������׺
	CString m_strCapFileFullPathName;
	//��Ӧ��pcap�ļ���
	CString m_strCapFileName;           
	//��Ӧ��cap�ļ������ļ���
	CString m_strCapTransformedFileName;
	//���ݰ�����ģʽ
	bool m_bLoadPackageByPackage;//�Ƿ����������
	int  m_nLoadPackages;        //һ�μ��ص����ݰ�����
	//���ĵ��Ƿ��˳�
	BOOL m_bEndDoc;
	//�����߳��Ƿ����
	BOOL m_bEndParseThread;
	CLibpCapFileMnger m_libpcapfilemnger;
private:
	std::ifstream  m_txtifstream;//��txt����������ı�ָ��
//	PACKET_CHAR_STRUCT* m_pPacket;//��������ʱ�ı���
	PACKET_STRUCT*      m_pPacket;//��������ʱ�ı���
public:
	//���������ݹ�����
	CCapPackagesMnger m_cappackagesmnger;
	//�ı������ṹ
//	CCapTxtAnalyzer   m_captxtanalyzer;
private:
	CDlgProgressShow* m_pDlgprogressShow;//����ָʾ��
public:
//	afx_msg void OnToolbarMsgdtailShowsrc();
public: //���ڶ�λ�澯Ŀ��֡
	double	m_fTargetTime; //time.ms

};
