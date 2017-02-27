#pragma execution_character_set("UTF-8")
#include "CapTransformer.h"
#include "wsconstant.h"
//#include "../wsanalyzer/WSAnalyzer.h"
//#include "../wsconfig/ChineseCode.h"
/**
* @brief	CCapTransformer          对象声成,初始化各种指针
* @param 	
* @return	
* @notes	无
* @sample	无
*/
CCapTransformer::CCapTransformer(void)
{
	m_hTxAnaInst          = NULL;

	/******根据MMS结构获取ACSI服务类型****/
	m_p_mms_service_type_2_acsi = NULL;
	/******获取ACSI服务错误号****/
	m_p_get_acsi_error_code = NULL;
	/******获取ACSI服务_REJECT错误号****/
	m_p_get_acsi_error_reject = NULL;
	/******获取ACSI服务_数据访问错误号****/
	m_p_get_acsi_error_code_data_access = NULL;

	m_pPkt_struct_make_mmsinfo = NULL;
	m_pAnalyzeTxt         = NULL;
	m_pRelaseAtStruct     = NULL;

	m_pGetChildStruct     = NULL;
	m_pGetPacketContent   = NULL;
	m_pGetStructByKeyDes  = NULL;
	m_pAnalyzeTxt_Step    = NULL;
	m_pReleaseAtStructStep = NULL;
	m_pMakeMmsInfoStruct    = NULL;
	m_pReleaseMmsInfoStruct = NULL;

	m_pMakeSmvInfoStruct_Txt = NULL;
	m_pSmvInfoStruct_MsgBuf  = NULL;
	m_pReleaseSmvInfoStruct   = NULL;
}
/**
* @brief	~CCapTransformer         对象析构,如果动态库未释放,自动释放动态库
* @param 	
* @return	
* @notes	无
* @sample	无
*/
CCapTransformer::~CCapTransformer(void)
{
		UnInitialize();
}

/**
* @brief	Initialize         初始化，加载动态库，导出库函数,需被外部显性调用
* @param 	const char * cLibPathName  动态库所在路径,需相对路径+动态库名称
* @return	int 0表示成功
* @notes	无
* @sample	无
*/
int CCapTransformer::Initialize(const char * cLibPathName)
{
	if(NULL == cLibPathName)
	{
		return -1;
	}
	try
	{
		//加载库
        m_hTxAnaInst = xj_load_library(cLibPathName);
		if(NULL == m_hTxAnaInst)
		{
			return -1;
		}
		//导入库函数
		/******根据MMS结构获取ACSI服务类型****/
        m_p_mms_service_type_2_acsi = (MMS_SERVICE_TYPE_2_ACIS) xj_get_addr(m_hTxAnaInst,"mms_service_type_2_acsi");
		/******获取ACSI服务错误号****/
        m_p_get_acsi_error_code = (GET_ACSI_ERROR_CODE) xj_get_addr(m_hTxAnaInst,"get_acsi_error_code");
		/******获取ACSI服务_REJECT错误号****/
        m_p_get_acsi_error_reject = (GET_ACSI_ERROR_CODE_REJECT) xj_get_addr(m_hTxAnaInst,"get_acsi_error_code_reject");;
		/******获取ACSI服务_数据访问错误号****/
        m_p_get_acsi_error_code_data_access = (GET_ACSI_ERROR_CODE_DATA_ACCESS) xj_get_addr(m_hTxAnaInst,"get_acsi_error_code_data_access");
		;
        m_pPkt_struct_make_mmsinfo = (XJ_PKT_STRUCT_MAKE_MMS_INFO_STRUCT) xj_get_addr(m_hTxAnaInst,"xj_pkt_struct_make_mms_info_struct");
        m_pAnalyzeTxt         = (ANALYZETXT)        xj_get_addr(m_hTxAnaInst,"at_analyzetxt");
        m_pRelaseAtStruct     = (RELEASE_AT_STRUCT) xj_get_addr(m_hTxAnaInst, "at_release_at_struct");

        m_pAnalyzeTxt_Step    = (ANALYZETXT_STEP)   xj_get_addr(m_hTxAnaInst,"at_analyzetxt_step");
        m_pReleaseAtStructStep = (RELEASE_AT_STRUCT_STEP) xj_get_addr(m_hTxAnaInst,"at_release_at_struct_step");

        m_pGetChildStruct     = (GETCHILDSTRUCT)    xj_get_addr(m_hTxAnaInst, "at_get_childstruct");
        m_pGetPacketContent   = (GETPACKETCONTENT)  xj_get_addr(m_hTxAnaInst, "at_get_packet_content");
        m_pGetStructByKeyDes  = (GETSTRUCTBYKEYDES) xj_get_addr(m_hTxAnaInst, "at_get_struct_by_keydes");

        m_pMakeMmsInfoStruct    = (MAKEMMSINFOSTRUCT)       xj_get_addr(m_hTxAnaInst, "at_make_mms_info_struct");
        m_pReleaseMmsInfoStruct = (RELEASE_MMS_INFO_STRUCT) xj_get_addr(m_hTxAnaInst, "at_release_mms_info_struct");

        m_pMakeSmvInfoStruct_Txt = (MAKESMVIINFOSTRUCT_TXT)   xj_get_addr(m_hTxAnaInst, "at_make_smv_info_struct_txt_exe");
        m_pSmvInfoStruct_MsgBuf  = (MAKESMVINfOSTRUCT_MSGBUF) xj_get_addr(m_hTxAnaInst,"at_make_smv_info_struct_msgbuf");
        m_pReleaseSmvInfoStruct   = (RELEASE_SMV_INFO_STRUCT)  xj_get_addr(m_hTxAnaInst,"at_release_smv_info_struct");

        m_pMakeGooseInfoStruct_Txt = (MAKEGOOSEINFOSTRUCT_TXT)  xj_get_addr(m_hTxAnaInst,"at_make_goose_info_struct_txt");
        m_pRelealseGooseInfoStruct = (RELEASE_GOOSE_INFO_STRUCT)xj_get_addr(m_hTxAnaInst,"at_release_goose_info_struct");
		if(m_pAnalyzeTxt == NULL || m_pRelaseAtStruct == NULL || m_pAnalyzeTxt_Step == NULL || m_pReleaseAtStructStep == NULL||m_pGetChildStruct == NULL || m_pGetPacketContent == NULL||
			m_pGetStructByKeyDes == NULL || m_pMakeMmsInfoStruct == NULL || m_pReleaseMmsInfoStruct == NULL || m_pMakeSmvInfoStruct_Txt == NULL
	         || m_pSmvInfoStruct_MsgBuf == NULL || m_pReleaseSmvInfoStruct == NULL || m_pMakeGooseInfoStruct_Txt == NULL || m_pRelealseGooseInfoStruct == NULL
			 || m_p_mms_service_type_2_acsi == NULL || m_p_get_acsi_error_code == NULL || m_p_get_acsi_error_reject == NULL || m_p_get_acsi_error_code_data_access == NULL)
		{
			return -1;
		}
		return 0;
	}
    catch (string e)
	{
        //输出相关错误日志
	}
    catch (...)
    {
        //do something
    }

	
	return -1;
}

/*
* @brief	UnInitialize         释放动态库
* @param 	
* @return	int 0表示成功
* @notes	无
* @sample	无
*/
int CCapTransformer::UnInitialize()
{
	if(m_hTxAnaInst != NULL)
	{
        xj_free_library(m_hTxAnaInst);
		m_hTxAnaInst = NULL;
	}
	return 0;
}

/*
* @brief	I_AnalyzeTxt              解析txt文件到at_struct结构
* @param 	const char * c_file_name  文件全路径名+文件名称,不带后缀
* @return	AT_STRUCT *               一次性全部解析好的数据目录式结构
* @notes	大文件耗时较长,适合小文件方式解析
* @sample	无
*/
AT_STRUCT* CCapTransformer::I_AnalyzeTxt(const char * c_file_name)
{
	try
	{
		if(NULL == c_file_name || NULL == m_pAnalyzeTxt)
		{
			return NULL;
		}
		return m_pAnalyzeTxt(c_file_name);
	}
    catch (...)
	{
        //do something
	}

	return NULL;
}

/**
* @brief	I_AnalyzeTxt_STEP             指定数据包个数解析txt文件到at_struct结构
* @param 	cp_fin                        文件指针，需在外部打开
* @param 	&n_num                        返回实际的个数
* @return	AT_STRUCT_STEP *              解析后的数据返回首地址，个数在
* @notes	                              大文件方式使用，建议n_num参数为1，逐包调取，方便界面连续显示
* @sample	无
*/
AT_STRUCT_STEP* CCapTransformer::I_AnalyzeTxt_STEP(void *p_fin,int &n_num)
{
	try
	{
		if(NULL == p_fin || n_num <= 0 || NULL == m_pAnalyzeTxt_Step)
		{
			return NULL;
		}
		return m_pAnalyzeTxt_Step(p_fin,n_num);//m_pAnalyzeTxt(c_file_name);
	}
    catch (...)
	{
        //do something
	}

	return NULL;
}

/*
* @brief	I_ReleaseATStruct         释放AT_Struct结构
* @param 	AT_STRUCT * p_at_struct
* @return	int 0表示成功
* @notes	无
* @sample	无
*/
int CCapTransformer::I_ReleaseATStruct(AT_STRUCT * p_at_struct)
{
	try
	{
		if(NULL == p_at_struct || NULL == m_pRelaseAtStruct)
		{
			return NULL;
		}
		return m_pRelaseAtStruct(p_at_struct);
	}
    catch (...)
	{
        //
	}

	return 0;
}

/*
* @brief	I_GetChildStruct          根据描述获得子节点，仅遍历一层
* @param 	AT_STRUCT *p_layer_struct 需要查找的子节点
* @param 	const char *c_child_des   子节点需对应的描述
* @return	AT_STRUCT *
* @notes	无
* @sample	无
*/
AT_STRUCT* CCapTransformer::I_GetChildStruct(AT_STRUCT *p_layer_struct,const char *c_child_des)
{
	try
	{
		if(NULL == p_layer_struct || NULL == c_child_des || NULL == m_pGetChildStruct)
		{
			return NULL;
		}
		return m_pGetChildStruct(p_layer_struct,c_child_des);//调用动态库接口
	}
    catch (...)
	{
        //
	}

	return NULL;
}

/*
* @brief	I_GetChildStruct          根据关键字得到某个子包，针对该包遍历
* @param 	AT_STRUCT *p_layer_struct 需要查找的子节点
* @param 	const char *c_child_des   子节点需对应的描述
* @return	AT_STRUCT *
* @notes	无
* @sample	无
*/
AT_STRUCT* CCapTransformer::I_GetStructByKeyDes(AT_STRUCT *p_layer_struct,const char *c_key_des)
{
	try
	{
		if(NULL == p_layer_struct || NULL == c_key_des || NULL == m_pGetStructByKeyDes)
		{
			return NULL;
		}
		return m_pGetStructByKeyDes(p_layer_struct,c_key_des);//调用动态库接口
	}
    catch (...)
    {
        //
    }

	return NULL;
}

/*
* @brief	I_GetPacketContent          从结构中得到指定协议、指定属性的值
* @param 	AT_STRUCT *p_layer_struct 需要查找的节点，需是顶层结构
* @param 	const char * c_protocol   协议名称，对应第二层子节点
* @param 	const char *c_des         协议名称，对应第三层子节点
* @return	AT_STRUCT *
* @notes	一般用于获取数据包的信息，比如Frame Number的值等
* @sample	无
*/
const char* CCapTransformer::I_GetPacketContent(AT_STRUCT *p_packet_struct,const char * c_protocol,const char *c_des)
{
	try
	{
		if(NULL == p_packet_struct || NULL == c_protocol || NULL == c_des || NULL == m_pGetPacketContent)
		{
			return NULL;
		}
		return m_pGetPacketContent(p_packet_struct,c_protocol,c_des);//调用动态库接口
	}
    catch (...)
    {
        //
    }

	return NULL;
}

/*
* @brief	I_MakeMMSInfoStruct       转换成MMS结构
* @param 	AT_STRUCT *p_at_struct    待转换的结构
* @return	MMS_INFO_STRUCT *         MMS结构
* @notes	无
* @sample	无
*/
MMS_INFO_STRUCT* CCapTransformer::I_MakeMMSInfoStruct(AT_STRUCT *p_at_struct)
{
	try
	{
		if(NULL == p_at_struct || NULL == m_pMakeMmsInfoStruct)
		{
			return NULL;
		}
		return m_pMakeMmsInfoStruct(p_at_struct);//调用动态库接口
	}
    catch (...)
    {
        //
    }
	return NULL;
}

/*
* @brief	I_MakeMMSInfoStruct               释放MMS结构
* @param 	MMS_INFO_STRUCT *p_info_struct    待释放的结构
* @return	int
* @notes	无
* @sample	无
*/
int CCapTransformer::I_ReleaseMMSInfoStruct(MMS_INFO_STRUCT *p_info_struct)
{
	try
	{
		if(NULL == p_info_struct || NULL == m_pReleaseMmsInfoStruct)
		{
			return NULL;
		}
		return m_pReleaseMmsInfoStruct(p_info_struct);//调用动态库接口
	}
    catch (...)
    {
        //
    }
	return 0;
}

/*
* @brief	I_MakeSmvInfoStruct_TXT               制作采样结构（读取文本方式）
* @param 	AT_STRUCT *p_at_struct                待制作的结构
* @return	SMV_INFO_STRUCT *
* @notes	无
* @sample	无
*/
SMV_INFO_STRUCT* CCapTransformer::I_MakeSmvInfoStruct_TXT(AT_STRUCT *p_at_struct)
{
	try
	{
		if(NULL == p_at_struct || NULL == m_pMakeSmvInfoStruct_Txt)
		{
			return NULL;
		}
		return m_pMakeSmvInfoStruct_Txt(p_at_struct);//调用动态库接口
	}
    catch (...)
    {
        //
    }
	return NULL;
}

/*
* @brief	I_MakeSmvInfoStruct_TXT               制作采样结构（数据流方式）
* @param 	const char *c_msg_buf                 数据流起始指针
* @param 	int n_msg_len                         数据流长度
* @return	SMV_INFO_STRUCT *
* @notes	无
* @sample	无
*/
SMV_INFO_STRUCT * CCapTransformer::I_MakeSmvInfoStruct_MSGBUF(const char *c_msg_buf,int n_msg_len)
{
	try
	{
		if(NULL == c_msg_buf || n_msg_len <= 0 ||NULL == m_pSmvInfoStruct_MsgBuf)
		{
			return NULL;
		}
		return m_pSmvInfoStruct_MsgBuf(c_msg_buf,n_msg_len);//调用动态库接口
	}
    catch (...)
    {
        //
    }
	return NULL;
}

/*
* @brief	I_ReleaseSmvStruct               释放采样值结构
* @param 	SMV_INFO_STRUCT *p_info_struct    待释放的结构
* @return	int
* @notes	无
* @sample	无
*/
int CCapTransformer::I_ReleaseSmvStruct(SMV_INFO_STRUCT *p_info_struct)
{
	try
	{
		if(NULL == p_info_struct || NULL == m_pReleaseSmvInfoStruct)
		{
			return NULL;
		}
		return m_pReleaseSmvInfoStruct(p_info_struct);//调用动态库接口
	}
    catch (...)
    {
        //
    }
	return 0;
}
/****接口函数，供外部调用****/
/*
* @brief	I_MakeGooseInfoStruct_TXT             根据AT_STRUCT生成GOOSE结构
* @param 	AT_STRUCT *p_at_struct                 待制作的结构
* @return	GOOSE_INFO_STRUCT* 
* @notes	无
* @sample	无
*/
GOOSE_INFO_STRUCT*  CCapTransformer::I_MakeGooseInfoStruct_TXT(AT_STRUCT *p_at_struct)
{
	try
	{
		if(NULL == p_at_struct || NULL == m_pMakeGooseInfoStruct_Txt)
		{
			return NULL;
		}
		return m_pMakeGooseInfoStruct_Txt(p_at_struct);//调用动态库接口
	}
    catch (...)
    {
        //
    }
	return NULL;
}
/******释放GOOSE结构接口函数，供外部调用****/
/*
* @brief	I_Release_GOOSE_INFO_STRUCT               释放GOOSE结构
* @param 	GOOSE_INFO_STRUCT *p_info_struct          待释放的结构
* @return	int
* @notes	无
* @sample	无
*/
int CCapTransformer::I_Release_GOOSE_INFO_STRUCT(GOOSE_INFO_STRUCT *p_info_struct)
{
	try
	{
		if(NULL == p_info_struct || NULL == m_pRelealseGooseInfoStruct)
		{
			return -1;
		}
		return m_pRelealseGooseInfoStruct(p_info_struct);//调用动态库接口
	}
    catch (...)
    {
        //
    }
	return 0;
}
/******释放加载的结构***/
/*
* @brief	Release_AT_STRUCT_STEP                  释放加载的结构
* @param 	AT_STRUCT_STEP * p_at_struct_step                
* @return	int
* @notes	无
* @sample	无
*/
int CCapTransformer::I_Release_AT_STRUCT_STEP(AT_STRUCT_STEP * p_at_struct_step)
{
	//判断入口是否为空
	if(NULL == p_at_struct_step || m_pReleaseAtStructStep == NULL)
		return -1;
	try
	{
		return m_pReleaseAtStructStep(p_at_struct_step);
	}
    catch (...)
    {
        //
    }
	return -1;

}
/******释放分析出来的各种结构***/
/*
* @brief	Release_AT_STRUCT_STEP                  释放加载的结构
* @param 	void* pParserdStruct                
* @return	int
* @notes	无
* @sample	无
*/
int CCapTransformer::Release_PARSERD_STRUCT(void* pParserdStruct,int nStructType)
{
	if(pParserdStruct == NULL)
		return -1;
	if(nStructType == PROTOAPPTYPE_SMV92)
	{
		SMV_INFO_STRUCT* pSmvInfoStruct = (SMV_INFO_STRUCT*) pParserdStruct;
		I_ReleaseSmvStruct(pSmvInfoStruct);
	}
	else if(nStructType == PROTOAPPTYPE_GOOSE)
	{
		GOOSE_INFO_STRUCT* pGooseInfoStruct = (GOOSE_INFO_STRUCT*)pParserdStruct;
		I_Release_GOOSE_INFO_STRUCT(pGooseInfoStruct);
	}
	else if(nStructType == PROTOAPPTYPE_MMS)
	{
		MMS_INFO_STRUCT*  pMmsInfoStruct = (MMS_INFO_STRUCT*) pParserdStruct;
		I_ReleaseMMSInfoStruct(pMmsInfoStruct);
	}
	else
	{
		;
	}
	return 0;
}
/******转换成MMS报文***/
/*
* @brief	I_XJ_PKT_STRUCT_MAKE_MMS_INFO_STRUCT
* @param 	XJ_DISSECT_PKT *p_xj_dissect_pkt 
* @param    BOOL bFormatErrorAna            是否进行格式错误分析
* @return	int
* @notes	无
* @sample	无
*/
MMS_INFO_STRUCT* CCapTransformer::I_XJ_PKT_STRUCT_MAKE_MMS_INFO_STRUCT(CAPMSGGININFO * pCapPackage,BOOL bFormatErrorAna)
{
	try
	{
		if(pCapPackage == NULL || m_pPkt_struct_make_mmsinfo == NULL)
			return NULL;
		if(pCapPackage->pxj_dissect_pkt == NULL)
			return NULL;
		if(pCapPackage->napptype == ETHER_TYPE_COTP)
		{
			COTP_ANALYZE(pCapPackage);
		}
		if(pCapPackage->napptype == ETHER_TYPE_TPKT)
		{
			strcpy_s(pCapPackage->ccontent,"COTP分帧报文");
		}
		//格式错误报告
		if(Judge_Pkt_FormatError(pCapPackage))
		{
			if(bFormatErrorAna)//格式错误报告
			{
				pCapPackage->nAppConetentGood = 0;
				strcpy_s(pCapPackage->ccontent,"格式错误");
				return NULL;
			}
		}
		MMS_INFO_STRUCT* p_mms_info = m_pPkt_struct_make_mmsinfo(pCapPackage->pxj_dissect_pkt);
		if(p_mms_info == NULL)
			return NULL;
		if(strlen(p_mms_info->c_pdu_type) == 0)//判断
		{
			I_ReleaseMMSInfoStruct(p_mms_info);
			return NULL;
		}
		//信息报告单独提取 add by yinzhehong 20130321
		if(pCapPackage->napptpye_type == 0)
		{
			pCapPackage->napptpye_type = I_MMS_SERVICE_TYPE_2_ACIS(p_mms_info);//获取服务类型
		}
		if(pCapPackage->napptpye_type == ACSI_DETAIL_SRVC_TYPE_REPORT)
		{
			char reportdsref[128];
			char reportid[128];
			memset(reportdsref,0,128);
			memset(reportid,0,128);
			Get_DataSet_Reference_Report(p_mms_info,reportid,reportdsref);
            /* djf 为编译通过临时屏蔽，后面还需要打开
			//根据设定的需要过滤的ds数据集合列表进行过滤
			BOOL bfind = FALSE;
			CWSAnalyzerApp * pApp = (CWSAnalyzerApp *) AfxGetApp();
			if(pApp->m_wssysConfiguration.m_wsIec61850AnaCfg.breortexceptana_mms)//过滤模拟量的报告
			{
				for(int i = 0;i < pApp->m_wssysConfiguration.m_wsIec61850AnaCfg.n_excepcodition_mms; i++)
				{
					if(strlen(pApp->m_wssysConfiguration.m_wsIec61850AnaCfg.c_exceptcodition_mms[i]) >0 &&
						strstr(reportdsref,pApp->m_wssysConfiguration.m_wsIec61850AnaCfg.c_exceptcodition_mms[i]) != NULL)
					{
						bfind = TRUE;
						break;
					}
				}
			}
			if(!bfind)//如果未找到则设定为事件
			   pCapPackage->beventanalyzedgoose = true;
            */
		}
		pCapPackage->pparserdstruct = p_mms_info;
		if(pCapPackage->napptpye_type == ACSI_DETAIL_SRVC_TYPE_SERVICE_ERROR  && bFormatErrorAna)//格式错误报告
		{
			pCapPackage->nAppConetentGood = 0;
			strcpy_s(pCapPackage->ccontent,"格式错误");
			return NULL;
		}
		else  if(pCapPackage->napptpye_type==ACSI_DETAIL_SRVC_TYPE_UNKNOWN && bFormatErrorAna)//N_NO_ERROR_CLASS=9999
		{
			pCapPackage->nAppConetentGood = 0;
			strcpy_s(pCapPackage->ccontent,"格式错误:服务未知");
			return NULL;
		}
		//获取MMS描述信息
        strcpy_s(pCapPackage->ccontent,Get_MMS_PKT_DESC(p_mms_info,pCapPackage->nAppConetentGood,pCapPackage->napptpye_type).c_str());
		//
		return p_mms_info;
	}
    catch (...)
    {
        //
    }
	return NULL;
}
/******COTP报文分析****/
int CCapTransformer::COTP_ANALYZE(CAPMSGGININFO * pCapPackage)
{
	XJ_DISSECT_PKT* pxj_dissect_pkt = pCapPackage->pxj_dissect_pkt;//报文描述
	if(pxj_dissect_pkt->prototreelist_size < 1)
		return -1;
	//COTP的描述
	XJ_PROTO_NODE* pxj_proto_node_cotp = &pxj_dissect_pkt->pprototreelist[pxj_dissect_pkt->prototreelist_size-1];
	//是否最后帧判断
	if(pxj_proto_node_cotp->childlist_size < 1)
		return -1;
	XJ_PROTO_NODE* pxj_proto_node_end;
	pxj_proto_node_end = &pxj_proto_node_cotp->pchildlist[pxj_proto_node_cotp->childlist_size-1];
	//是否最后帧
	if(NULL == strstr(pxj_proto_node_end->node_desc, "Yes"))//分帧传输
	{
		pCapPackage->blastcotpunit = false;
		sprintf_s(pCapPackage->ccontent,"COTP分帧报文");
	}
	else
	{
		pCapPackage->blastcotpunit = TRUE;
		pCapPackage->napptype      = IEC61850_ETHER_TYPE_MMS;//修改报文类型
	}
	return 0;
}
/******Get_MMS_PKT_DESC***/
/*
* @brief	获取MMS报文信息包描述信息
* @param 	MMS_INFO_STRUCT* p_mms_info
* @param 	int& nappconetentgood
* @return	int
* @notes	无
* @sample	无
*/
string CCapTransformer::Get_MMS_PKT_DESC(MMS_INFO_STRUCT* p_mms_info,int& nappconetentgood,int napptype_type)
{
    return ("暂时屏蔽");
/*	为编译通过暂时屏蔽
 *  if(p_mms_info == NULL)
		return _T("");
	CWSAnalyzerApp * pApp = (CWSAnalyzerApp *) AfxGetApp();
    CString strContent,strSevType;//描述
    string strdesc;
	CString strSeverror,strRejectError,strdataaccessError;
	int nerrorcode;
	if(napptype_type == 23)//信息报告
	{
		char reportdsref[128];
		char reportid[128];
		memset(reportdsref,0,128);
		memset(reportid,0,128);
		char c_item_desc[256];
		memset(c_item_desc,0,256);
		Get_DataSet_Reference_Report(p_mms_info,reportid,reportdsref);
		pApp->m_scdParserWrapper.GetItemDesc_ByRef_I(reportdsref,c_item_desc,TS_SCD_ITEM_TYPE_SCDDataSet);
		if(strlen(c_item_desc) > 0)
		{
			ChineseCode myConvert;
			strdesc.clear();
			myConvert.UTF_8ToGB2312(strdesc,c_item_desc,strlen(c_item_desc));
			memset(c_item_desc,0,256);
			sprintf(c_item_desc,"%s",strdesc.c_str());
			strSevType.Format("%s %s",c_item_desc,pApp->m_KeyWords61850tranformer.Get_Acsi_Type_Desc(napptype_type));//获取服务名称
		}
		else
		{
			strSevType.Format("%s[ds_ref:%s]",pApp->m_KeyWords61850tranformer.Get_Acsi_Type_Desc(napptype_type),reportdsref);//获取服务名称
		}
		//strSevType.Format("%s[ds_ref:%s]",pApp->m_KeyWords61850tranformer.Get_Acsi_Type_Desc(napptype_type),reportdsref);//获取服务名称	
	}
	else
	{
		strSevType.Format("InvokeID:%d %s",p_mms_info->n_invoke_id,pApp->m_KeyWords61850tranformer.Get_Acsi_Type_Desc(napptype_type));//获取服务名称
	}
	//检查错误
	if(p_mms_info->struct_mms_service_error.n_error_class != 9999 && p_mms_info->struct_mms_service_error.n_error_code != 9999)
	{
		nerrorcode = I_GET_ACSI_ERROR_CODE(p_mms_info->struct_mms_service_error.n_error_class,p_mms_info->struct_mms_service_error.n_error_code);
		if(ACSI_ERR_CODE_NO_ERR != nerrorcode)
		{
			nappconetentgood = 0;
			strSeverror.Format("%s",pApp->m_KeyWords61850tranformer.Get_Acsi_Error_Desc(nerrorcode));
		}
	}
	//拒绝错误
	if(p_mms_info->struct_mms_service_reject.n_reject_pdu != -1 && p_mms_info->struct_mms_service_reject.n_reject_reason_code != -1)
	{
		nerrorcode = I_GET_ACSI_ERROR_CODE_REJECT(p_mms_info->struct_mms_service_reject.n_reject_pdu,p_mms_info->struct_mms_service_reject.n_reject_reason_code);
		if(ACSI_ERR_CODE_NO_ERR != nerrorcode)
		{
			strRejectError.Format("%s",pApp->m_KeyWords61850tranformer.Get_Acsi_Error_Desc(nerrorcode));
			nappconetentgood = 0;
		}
	}
	//数据访问错误
	for(int i = 0 ; i < p_mms_info->n_data_num; i++)
	{
		if(p_mms_info->p_data_struct[i].result != 9999)//9999初始值
		{
			strdataaccessError.Format("%s",pApp->m_KeyWords61850tranformer.Get_MMS_DATA_ACCESS_ERROR_ChineseDesc(p_mms_info->p_data_struct[i].result));
			nappconetentgood = 0;
			break;
		}
	}
	strContent.Format("%s %s%s",strSevType,strRejectError,strdataaccessError);
	if(strlen(strContent) > 110)//超长
		strContent = strContent.Left(110);//超长限制
    return strContent;
*/
}
BOOL CCapTransformer::Judge_Pkt_FormatError(CAPMSGGININFO * pCapPackage)
{
	BOOL bResult = FALSE;
	XJ_DISSECT_PKT * p_xj_dissect_pkt = pCapPackage->pxj_dissect_pkt;
	for(int i = p_xj_dissect_pkt->prototreelist_size-1; i >=0 ; i --)
	{
		if(strstr(p_xj_dissect_pkt->pprototreelist[i].node_name,"Malformed") != NULL)
		{
			bResult = TRUE;
			break;
		}
	}
	return bResult;
}
/******根据MMS结构获取ACSI服务类型****/
int CCapTransformer::I_MMS_SERVICE_TYPE_2_ACIS(MMS_INFO_STRUCT *p_info_struct)
{
	if(NULL == p_info_struct || NULL == m_p_mms_service_type_2_acsi)
		return 0;
	return m_p_mms_service_type_2_acsi(p_info_struct);
}
/******获取ACSI服务错误号****/
ACSI_ERR_CODE CCapTransformer::I_GET_ACSI_ERROR_CODE(int n_mms_error_class, int n_mms_error_code)
{
	if(NULL == m_p_get_acsi_error_code)
		return ACSI_ERR_CODE_NO_ERR;
	return m_p_get_acsi_error_code(n_mms_error_class,n_mms_error_code);
}
/******获取ACSI服务_REJECT错误号****/
ACSI_ERR_CODE CCapTransformer::I_GET_ACSI_ERROR_CODE_REJECT(REJECT_PDU n_rejectPdu, int n_Reject_Reason)
{
	if(NULL == m_p_get_acsi_error_reject)
		return ACSI_ERR_CODE_NO_ERR;
	return m_p_get_acsi_error_reject(n_rejectPdu,n_Reject_Reason);
}
/******获取ACSI服务_数据访问错误号****/
ACSI_ERR_CODE CCapTransformer::I_GET_ACSI_ERROR_CODE_DATA_ACCESS(int n_mms_data_access_error_code)
{
	if(NULL == m_p_get_acsi_error_code_data_access)
		return ACSI_ERR_CODE_NO_ERR;
	return m_p_get_acsi_error_code_data_access(n_mms_data_access_error_code);
}
/******获取报告的数据集参引****/
int CCapTransformer::Get_DataSet_Reference_Report(MMS_INFO_STRUCT* p_mms_info, char* c_dataset_rptid,char *c_dataset_reference)
{
	if(p_mms_info == NULL || c_dataset_reference == NULL || c_dataset_rptid == NULL)
		return -1;
	MMS_DATA_STRUCT* p_data_struct = p_mms_info->p_data_struct;
	if(p_data_struct == NULL)
		return -1;
	char*  OptFlds = NULL;
	int ds_index = 2;
	//获取报告控制块rptid
	strcpy(c_dataset_rptid, p_data_struct[0].c_data);
	//将OptFlds转换为二进制数，并只取前10位
	OptFlds = p_data_struct[1].c_data;
	if ( OptFlds[4] == '0' )//报告中不含数据集引用，则直接失败
	{
		return RES_FAIL;
	}

	if (OptFlds[1] == '1')
	{
		ds_index ++;
	}
	if (OptFlds[2] == '1')
	{
		ds_index ++;
	}
	//数据集引用
	strcpy(c_dataset_reference, p_data_struct[ds_index].c_data);
	return 0;
}


