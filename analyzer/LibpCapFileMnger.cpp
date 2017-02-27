#pragma execution_character_set("UTF-8")
#include "LibpCapFileMnger.h"
#include "define_scan.h"
#include "XJFile.h"


CLibpCapFileMnger::CLibpCapFileMnger(void)
{
	m_plibpCapFileContent = 0;
	m_nlibpCapFileSize    = 0;
}

CLibpCapFileMnger::~CLibpCapFileMnger(void)
{
	m_map_capmsginfo.clear();
	Libpcap_close();
}
/**
* @brief	~CCapTransformer         对象析构,如果动态库未释放,自动释放动态库
* @param 	
* @return	
* @notes	无
* @sample	无
*/
//将指定链接报文保存到指定路径的pcap文件
int CLibpCapFileMnger::SaveCapConnetion2File(CAPCONNECTINFO * pCapconnectinfo,const char* c_savepath)
{
	if(c_savepath == NULL || pCapconnectinfo == NULL)
	{
		return RES_FAIL;
	}
	if(pCapconnectinfo->map_capmsginfo.size() == 0)
		return RES_FAIL;
	return SavePacketList2File(c_savepath,pCapconnectinfo->map_capmsginfo);
}
//清空输出队列
int  CLibpCapFileMnger::RetPacketList()
{
	m_map_capmsginfo.clear();
	return RES_SUCCESS;
}
//增加报文
void CLibpCapFileMnger::AddPacket2ListBuff(CAPMSGGININFO* pCapMsgGinInfo)
{
	if(pCapMsgGinInfo == NULL)
		return;
	m_map_capmsginfo.insert(std::map <int, CAPMSGGININFO*> :: value_type(pCapMsgGinInfo->nseq, pCapMsgGinInfo));
}
//将缓冲队列中的报文保存到文件
int CLibpCapFileMnger::SaveBufferPacketList2File(const char* c_savepath)
{
	if(c_savepath == NULL || m_map_capmsginfo.size() == 0)
		return RES_FAIL;
	return SavePacketList2File(c_savepath,m_map_capmsginfo);
}
/**将报文保存到文件*/

int CLibpCapFileMnger::SavePacketList2File(const char* c_savepath,MAP_CAPMSGINFO map_capmsginfo)
{
    CXJFile pcapfile;
	// open file
    if (!pcapfile.Open(c_savepath,CXJFile::modeWrite|CXJFile::modeCreate))
	{	
		return RES_FAIL;
	}
	//写入头
	TS_PCAP_HEADER PcapHeader;
	pcapfile.Write(&PcapHeader,sizeof(TS_PCAP_HEADER));
	std::map <int, CAPMSGGININFO* >::iterator iter;
	CAPMSGGININFO* pCapMsgGinInfo;
	for(iter = map_capmsginfo.begin(); iter != map_capmsginfo.end(); iter ++ )
	{
		pCapMsgGinInfo = iter->second;
		if(pCapMsgGinInfo == NULL)
			continue;
		pcapfile.Write(pCapMsgGinInfo->csourceinfo , pCapMsgGinInfo->nsourceinfo_length);
	}
	pcapfile.Flush();
	pcapfile.Close();
	return RES_SUCCESS;
}

/************打开pcap文件*******************/
/**********返回文件的长度************/

static void ReverseBytes(void *vbuf,int nNum)
{
	char *buf=(char*)vbuf;
	for (int i=0;i<nNum/2;i++)
	{
		buf[i]^=buf[nNum-1-i]^=buf[i]^=buf[nNum-1-i];
	}
}

int CLibpCapFileMnger::Libpcap_open_offline(const char * c_filefullpathname, char* c_error)
{
	if(c_filefullpathname == NULL || c_error == NULL)
		return 0;
	Libpcap_close();
// djf must cfile --> xjfile

	//打开文件，获取文件长度
    CXJFile cfile;
	//打开文件
    if(!cfile.Open(c_filefullpathname,CXJFile::shareDenyNone))
	{
		return 0;
	}
	m_nlibpCapFileSize = cfile.GetLength();
	if(m_nlibpCapFileSize < sizeof(TS_PCAP_HEADER) + sizeof(TS_PCAP_PKTHDR))//文件长度检查
	{
		m_nlibpCapFileSize = 0;
		cfile.Close();
		return 0;
	}
	m_plibpCapFileContent = new char[m_nlibpCapFileSize];//申请内存
	//读入文件/
	int nReadSize = cfile.Read(m_plibpCapFileContent,m_nlibpCapFileSize);
	//读入头
	m_nlibcurpos = sizeof(TS_PCAP_HEADER);
	memcpy(&m_ts_pcapfile_header,m_plibpCapFileContent,m_nlibcurpos);
	m_bRevByte=m_ts_pcapfile_header.Magic!=PCAP_MAGIC;
	if(m_bRevByte)ReverseBytes(&m_ts_pcapfile_header.Network,sizeof(int));
	//关闭文件
    cfile.Close();

	return m_nlibpCapFileSize;
}

/***********读取下一帧，返回值为本帧报文文件中的位置******/
char* CLibpCapFileMnger::Libpcap_next_cap(TS_PCAP_PKTHDR* pkthdr, unsigned int& npos)
{
	if(pkthdr == NULL || m_plibpCapFileContent == NULL)
		return 0;
	int ntemp = m_nlibcurpos;
	npos = m_nlibcurpos;    //本帧报文起始处
	//报文结束了
	if( m_nlibcurpos + sizeof(TS_PCAP_PKTHDR) >= m_nlibpCapFileSize)//下一帧报文已不够读
	{
		return NULL;
	}
	//读入头
	if (m_bRevByte)
	{
		TS_PCAP_PKTHDR *pkthdr1=(TS_PCAP_PKTHDR*)((char*)m_plibpCapFileContent+m_nlibcurpos);
		ReverseBytes(&pkthdr1->caplen,sizeof(pkthdr1->caplen));
		ReverseBytes(&pkthdr1->len,sizeof(pkthdr1->len));
		ReverseBytes(&pkthdr1->ts.GmtTime,sizeof(pkthdr1->ts.GmtTime));
		ReverseBytes(&pkthdr1->ts.us,sizeof(pkthdr1->ts.us));
	}
	memcpy(pkthdr,m_plibpCapFileContent+m_nlibcurpos, sizeof(TS_PCAP_PKTHDR));//先修正字节序后memcpy

	m_nlibcurpos = m_nlibcurpos + pkthdr->caplen + sizeof(TS_PCAP_PKTHDR);//当前位置下移动到下一帧开始位置
	if(m_nlibcurpos > m_nlibpCapFileSize)//
	{
		m_nlibcurpos = m_nlibpCapFileSize;
		return NULL;
	}
	//读入BODY
	return m_plibpCapFileContent + ntemp;//返回本帧开始位置处
}
/***********关闭pcap文件**********************/
int CLibpCapFileMnger::Libpcap_close()
{
	delete []m_plibpCapFileContent;
	m_plibpCapFileContent = NULL;
	m_nlibpCapFileSize    = 0;
	m_nlibcurpos          = 0;
	return 0;
}
/***********关闭pcap文件**********************/
//根据输入的列表重新输出内容
int CLibpCapFileMnger::Libpcap_mergerfilelist(MAP_TS_LIBCAP_FILE map_tslibcapfilelist,TS_LIBCAP_FILE* pfilelist_dst)
{
	if(pfilelist_dst == NULL || map_tslibcapfilelist.size() == 0)
		return -1;
	DWORD nfilesize_max = 0;
	std::map<int, TS_LIBCAP_FILE*>::iterator iter;
	TS_LIBCAP_FILE* ptscapfile_src;
	for(iter = map_tslibcapfilelist.begin(); iter != map_tslibcapfilelist.end(); iter ++ )
	{
		ptscapfile_src = iter->second;
		if(ptscapfile_src->n_filesize > nfilesize_max)
		{
			nfilesize_max = ptscapfile_src->n_filesize;
		}
	}

	//打开文件，获取文件长度
    CXJFile cfile_src,cfile_dst;
	//打开目的
    string strfilefullpathname = pfilelist_dst->strfilepathname + pfilelist_dst->strfilename;
    if (!cfile_dst.Open(strfilefullpathname.c_str(),CXJFile::modeWrite|CXJFile::modeCreate))
	{	
		return -1;
	}
	//写入文件头
	TS_PCAP_HEADER PcapHeader;
	cfile_dst.Write(&PcapHeader,sizeof(TS_PCAP_HEADER));
	char* c_filecontent = new char[nfilesize_max];
	for(iter = map_tslibcapfilelist.begin(); iter != map_tslibcapfilelist.end(); iter ++ )
	{
		ptscapfile_src = iter->second;
		//打开文件
		strfilefullpathname = ptscapfile_src->strfilepathname + ptscapfile_src->strfilename;
        if(!cfile_src.Open(strfilefullpathname.c_str(),CXJFile::modeRead))
		{
			continue;
		}
		cfile_src.Read(c_filecontent,ptscapfile_src->n_filesize);//读入源
		cfile_dst.Write(c_filecontent+sizeof(TS_PCAP_HEADER),ptscapfile_src->n_filesize - sizeof(TS_PCAP_HEADER));//写入sorce
		cfile_src.Close();
	}
	cfile_dst.Close();

	return 0;
}
