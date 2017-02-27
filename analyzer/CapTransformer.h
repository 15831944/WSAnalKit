#pragma once
/********************************************************************
*	filename: 	CCapTransformer
*	author:		yinzhehong
*	created:	2010/10/20
*	purpose:  	txt文件结构解析动态库封装调用，该动态库支持将解析出来的数据结构解析成对应的业务结构(MMS、SMV、GOOSE)      
*   version:    1.0
*********************************************************************/
/*对应的数据接口*/
#include <string>
#include "xjlib.h"
#include "acsi_const.h"
#include "AT_STRUCT.h"
#include "capanalyzerstruct.h"

using std::string;

/**************转换成MMS报文*****************/
typedef MMS_INFO_STRUCT * (*XJ_PKT_STRUCT_MAKE_MMS_INFO_STRUCT)(XJ_DISSECT_PKT *p_xj_dissect_pkt);
/********************************动态库数据处理接口*********************************/

/************解析txt文件到内存,全部节点*****/
typedef AT_STRUCT*       (*ANALYZETXT)(const char *c_file_name);
/************释放解析后的内存*****/
typedef int               (*RELEASE_AT_STRUCT)(AT_STRUCT *p_at_struct);
/************指定数据包个数加载，用于数据显示时逐项个加载，增加界面显示速度*****/
typedef AT_STRUCT_STEP* (*ANALYZETXT_STEP)(void *p_fin,int &n_num);
/************释放解析后的内存*****/
typedef int (*RELEASE_AT_STRUCT_STEP)(AT_STRUCT_STEP * p_at_struct_step);

/************得到指定名称的子节点,仅遍历一层*****/
typedef AT_STRUCT*      (*GETCHILDSTRUCT)(AT_STRUCT *p_layer_struct,const char *c_child_des);
/**********得到指定描述的子节点,所有层均遍历*****/
typedef AT_STRUCT*      (*GETSTRUCTBYKEYDES)(AT_STRUCT *p_layer_struct,const char *c_key_des);
/*********从结构中得到指定协议、指定属性的值*****/
typedef const char*      (*GETPACKETCONTENT)(AT_STRUCT *p_packet_struct,const char *c_protocol,const char *c_des);

/********************MMS包相关******************/
/***将结构转换成MMS包***/
typedef MMS_INFO_STRUCT* (*MAKEMMSINFOSTRUCT)(AT_STRUCT *p_at_struct);                         
/****释放MMS包结构****/
typedef int               (*RELEASE_MMS_INFO_STRUCT)(MMS_INFO_STRUCT *p_info_struct);
/********************采样值相关******************/
/****根据AT_STRUCT生成采样值结构****/
typedef SMV_INFO_STRUCT* (*MAKESMVIINFOSTRUCT_TXT)(AT_STRUCT *p_at_struct);
/****根据一般报文生成采样值结构****/
typedef SMV_INFO_STRUCT* (*MAKESMVINfOSTRUCT_MSGBUF)(const char *c_msg_buf,int n_msg_len);
/****释放采样值结构****/
typedef int              (*RELEASE_SMV_INFO_STRUCT)(SMV_INFO_STRUCT *p_info_struct);
/*********************GOOSE相关******************/
/****根据AT_STRUCT生成GOOSE结构****/
typedef GOOSE_INFO_STRUCT* (*MAKEGOOSEINFOSTRUCT_TXT)(AT_STRUCT *p_at_struct);
/******释放GOOSE结构****/
typedef int                (*RELEASE_GOOSE_INFO_STRUCT)(GOOSE_INFO_STRUCT *p_info_struct);
/******根据MMS结构获取ACSI服务类型****/
typedef int (*MMS_SERVICE_TYPE_2_ACIS)(MMS_INFO_STRUCT *p_info_struct);
/******获取ACSI服务错误号****/
typedef ACSI_ERR_CODE (*GET_ACSI_ERROR_CODE)(int n_mms_error_class, int n_mms_error_code);
/******获取ACSI服务_REJECT错误号****/
typedef ACSI_ERR_CODE (*GET_ACSI_ERROR_CODE_REJECT)(REJECT_PDU n_rejectPdu, int n_Reject_Reason);
/******获取ACSI服务_数据访问错误号****/
typedef ACSI_ERR_CODE (*GET_ACSI_ERROR_CODE_DATA_ACCESS)(int n_mms_data_access_error_code);
/***********************************************************************************************************************/
class CCapTransformer
{
public:
	 CCapTransformer(void);
	~CCapTransformer(void);
public:
	/*初始化，加载动态库，导出库函数,cLibPathFullName为动态库相对路径+动态库名称*/
	int Initialize(const char *cLibPathName);
	/*卸载动态库*/
	int UnInitialize();
	/*********打开文件*************************/
private:
	/*加载动态库后返回的句柄*/
    XJHANDLE					m_hTxAnaInst;
private:
	/******根据MMS结构获取ACSI服务类型****/
	MMS_SERVICE_TYPE_2_ACIS          m_p_mms_service_type_2_acsi;
	/******获取ACSI服务错误号****/
	GET_ACSI_ERROR_CODE              m_p_get_acsi_error_code;
	/******获取ACSI服务_REJECT错误号****/
	GET_ACSI_ERROR_CODE_REJECT       m_p_get_acsi_error_reject;
	/******获取ACSI服务_数据访问错误号****/
	GET_ACSI_ERROR_CODE_DATA_ACCESS  m_p_get_acsi_error_code_data_access;
	/**************转换成MMS报文*****************/
	XJ_PKT_STRUCT_MAKE_MMS_INFO_STRUCT m_pPkt_struct_make_mmsinfo;
	/*解析txt文件到内存,全部节点接口函数指针*/
	ANALYZETXT                  m_pAnalyzeTxt;
	/*释放解析后的内存接口函数指针*/
	RELEASE_AT_STRUCT           m_pRelaseAtStruct;
	/*指定数据包个数加载接口函数指针*/
	ANALYZETXT_STEP             m_pAnalyzeTxt_Step;
	/*释放解析后的内存接口函数指针*/
	RELEASE_AT_STRUCT_STEP      m_pReleaseAtStructStep;

	/*得到指定名称的子节点,仅遍历一层接口函数指针*/
	GETCHILDSTRUCT              m_pGetChildStruct;
	/*得到指定描述的子节点,所有层均遍历接口函数指针*/
	GETSTRUCTBYKEYDES           m_pGetStructByKeyDes;

	/*从结构中得到指定协议、指定属性的值接口函数指针*/
	GETPACKETCONTENT            m_pGetPacketContent;

	/*将结构转换成MMS包接口函数指针*/
	MAKEMMSINFOSTRUCT          m_pMakeMmsInfoStruct;
	/*释放MMS包结构接口函数指针*/
	RELEASE_MMS_INFO_STRUCT    m_pReleaseMmsInfoStruct;

	/*根据AT_STRUCT生成采样值结构接口函数指针*/
	MAKESMVIINFOSTRUCT_TXT     m_pMakeSmvInfoStruct_Txt;
	/*根据一般报文生成采样值结构接口函数指针*/
	MAKESMVINfOSTRUCT_MSGBUF   m_pSmvInfoStruct_MsgBuf;
	/*释放采样值结构接口函数指针*/
	RELEASE_SMV_INFO_STRUCT    m_pReleaseSmvInfoStruct;

	//根据AT_STRUCT生成GOOSE结构接口函数指针*/
	MAKEGOOSEINFOSTRUCT_TXT    m_pMakeGooseInfoStruct_Txt;
	//释放GOOSE结构接口函数指针*/
	RELEASE_GOOSE_INFO_STRUCT  m_pRelealseGooseInfoStruct;
/****************************以下为对动态库接口函数的封装，应用程序不直接针对动态库接口直接进行调用*******************/
public:
	/******根据MMS结构获取ACSI服务类型****/
	int I_MMS_SERVICE_TYPE_2_ACIS(MMS_INFO_STRUCT *p_info_struct);
	/******获取ACSI服务错误号****/
	ACSI_ERR_CODE I_GET_ACSI_ERROR_CODE(int n_mms_error_class, int n_mms_error_code);
	/******获取ACSI服务_REJECT错误号****/
	ACSI_ERR_CODE I_GET_ACSI_ERROR_CODE_REJECT(REJECT_PDU n_rejectPdu, int n_Reject_Reason);
	/******获取ACSI服务_数据访问错误号****/
	ACSI_ERR_CODE I_GET_ACSI_ERROR_CODE_DATA_ACCESS(int n_mms_data_access_error_code);
	/**************转换成MMS报文*****************/
	MMS_INFO_STRUCT* I_XJ_PKT_STRUCT_MAKE_MMS_INFO_STRUCT(CAPMSGGININFO * pCapPackage,BOOL bFormatErrorAna=FALSE);
	/************解析txt文件到内存,全部节点接口函数，供外部调用*****/
	AT_STRUCT*        I_AnalyzeTxt(const char *c_file_name);
	/************指定数据包个数加载接口函数，供外部调用*****/
	AT_STRUCT_STEP*   I_AnalyzeTxt_STEP(void* p_fin,int& n_num);

	/************释放解析后的内存接口函数，供外部调用*****/
	int				  I_ReleaseATStruct(AT_STRUCT *p_at_struct);

	/************得到指定名称的子节点,仅遍历一层接口函数，供外部调用*****/
	AT_STRUCT*        I_GetChildStruct(AT_STRUCT *p_layer_struct,const char *c_child_des);
	/**********得到指定描述的子节点,所有层均遍历接口函数，供外部调用*****/
	AT_STRUCT*        I_GetStructByKeyDes(AT_STRUCT *p_layer_struct,const char *c_key_des);
	/*********从结构中得到指定协议、指定属性的值接口函数，供外部调用*****/
	const char*       I_GetPacketContent(AT_STRUCT *p_packet_struct,const char *c_protocol,const char *c_des);
	
	/***将结构转换成MMS包接口函数，供外部调用***/
	MMS_INFO_STRUCT*  I_MakeMMSInfoStruct(AT_STRUCT *p_at_struct);
	int               I_ReleaseMMSInfoStruct(MMS_INFO_STRUCT *p_info_struct);
	/****根据AT_STRUCT生成采样值结构接口函数，供外部调用****/
	SMV_INFO_STRUCT*   I_MakeSmvInfoStruct_TXT(AT_STRUCT *p_at_struct);
	/****根据文本流接口生成采样值结构接口函数，供外部调用****/
	SMV_INFO_STRUCT*   I_MakeSmvInfoStruct_MSGBUF(const char *c_msg_buf,int n_msg_len);
	/****释放采样值结构接口函数，供外部调用****/
	int                I_ReleaseSmvStruct(SMV_INFO_STRUCT *p_info_struct);
	/****根据AT_STRUCT生成GOOSE结构接口函数，供外部调用****/
	GOOSE_INFO_STRUCT*  I_MakeGooseInfoStruct_TXT(AT_STRUCT *p_at_struct);
	/******释放GOOSE结构接口函数，供外部调用****/
    int                 I_Release_GOOSE_INFO_STRUCT(GOOSE_INFO_STRUCT *p_info_struct);
	/******释放AT_STRUCT_STEP结构接口函数,供外部调用****/
	int I_Release_AT_STRUCT_STEP(AT_STRUCT_STEP * p_at_struct_step);
	//获取报告中数据集引用以及rptid
	int Get_DataSet_Reference_Report(MMS_INFO_STRUCT* p_mms_info, char* c_dataset_rptid,char *c_dataset_reference);

    string Get_MMS_PKT_DESC(MMS_INFO_STRUCT* p_mms_info,int& nappconetentgood,int napptpye_type);
public:
	int Release_PARSERD_STRUCT(void* pParserdStruct,int nStructType);
private:
	/******判断数据包格式是否错误****/
	BOOL Judge_Pkt_FormatError(CAPMSGGININFO * pCapPackage);

	/******COTP报文分析****/
	int COTP_ANALYZE(CAPMSGGININFO * pCapPackage);

};

