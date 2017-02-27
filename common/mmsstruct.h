/****************************************************************************/
/* Copyright (c) 2010,许继集团有限公司                                      */
/* All rights reserved.                                                     */
/*                                                                          */
/*  模块描述：                                                              */
/** mms服务与acsi服务转换接口
*  @file  mmsstruct.h                                                      
/*                                                                          */
/* 日期         作者    注释                                                */
/* 2010/07/17   LJM     创建文件                                            */
/****************************************************************************/
#ifndef MMSSTRUCT_INCLUDED
#define MMSSTRUCT_INCLUDED

//#include "glbtypes.h"

#ifdef OS_WINDOWS
 #include <memory.h>
#else
#include "define_scan.h"
#endif

/** 
* mms服务定义
*/
typedef enum                              
{  
	MMS_SRVC_TYPE_UNKNOWN = 0,

	MMS_SRVC_TYPE_READ,							//read
	MMS_SRVC_TYPE_WRITE,						//write
	MMS_SRVC_TYPE_FILEDIRECTORY,				//fileDirectory
	MMS_SRVC_TYPE_FILEOPEN,						//fileOpen
	MMS_SRVC_TYPE_FILEREAD,						//fileRead
	MMS_SRVC_TYPE_FILECLOSE,					//fileClose
	MMS_SRV_TYPE_OBTAIN_FILE,					//obtainFile
	MMS_SRV_TYPE_FILEDELETE,					//deleteFile
	MMS_SRVC_TYPE_INFO,							//informationReport
	MMS_SRVC_TYPE_INITIATE,						//Initiate
	MMS_SRVC_TYPE_P_ABORT,						//p_abort
	MMS_SRVC_TYPE_CONCLUDE,						//conclude
	MMS_SRVC_TYPE_REJECT,						//reject
	MMS_SRVC_TYPE_CANCEL,						//cancel
	MMS_SRVC_TYPE_GETNAMELIST,					//GetNameList
	MMS_SRVC_TYPE_GETVARACCESSATTR,				//GetVariableAccessAttribute
	MMS_SRVC_TYPE_GETNAMEDVARLSTATTR,			//GetNamedVariableListAttributes
	MMS_SRVC_TYPE_DEFINENAMEDVARLST,			//DefineNamedVariableList
	MMS_SRVC_TYPE_DELETENAMEDVARLST,			//DeleteNamedVariableList
	MMS_SRVC_TYPE_READJOURNAL,					//ReadJournal
	MMS_SRVC_TYPE_U_ABORT						//u_abort

}MMS_SRVC_TYPE;

#define MAX_DES_LEN			   128
#define MAX_CONTENT_LEN		   256

#define MAX_MMS_INFO_DES_LEN	63
#define MAX_MMS_INFO_FILENAME_LEN	255	//MMS报文中文件名最大长度？？？？？COSMOS定为255
#define MAX_MMS_INFO_FILEDIRECTORY_LEN	31	//MMS报文中文件名最大长度？？？？？COSMOS定为255
#define MAX_MMS_INFO_TIME_LEN	31
#define MAX_MMS_INFO_IP_LEN		31
#define MAX_MMS_INFO_DATA_LEN   257//129

#define MAX_BIT_MMS_PARAM_CBB 16
#define MAX_BIT_MMS_SURPPORTED_CALLING 88

typedef struct mms_file_attr_struct
{
	//文件大小
	int n_size_of_file;
	//文件最后修改时间
	char c_time_last_modified[MAX_MMS_INFO_TIME_LEN];

}MMS_FILE_ATTR_STRUCT;

//文件属性结构
typedef struct mms_file_entry{

	//文件名
	char c_file_name[MAX_MMS_INFO_FILENAME_LEN+1];

	//文件属性
	MMS_FILE_ATTR_STRUCT mms_file_attr;

}MMS_FILE_ENTRY_STRUCT;

//mms数据类型枚举,原文参见mms第一部分14.2，有关类型的说明
typedef enum {
	n_mdt_array = 1 ,		//1
	n_mdt_structure,		//2
	n_mdt_boolean,			//3
	n_mdt_bit_string,		//4
	n_mdt_integer,			//5
	n_mdt_unsigned,			//6
	n_mdt_flating_poing,	//7
	n_mdt_reserved,			//8
	n_mdt_octet_string,		//9
	n_mdt_visible_string,	//10
	n_mdt_generalized_time,	//11
	n_mdt_binary_time,		//12
	n_mdt_bcd,				//13
	n_mdt_booleanArray,		//14
	n_mdt_obj_id,			//15
	n_mdt_mms_string,		//16
	n_mdt_utc_time,			//17

	n_mdt_init=999			//初值，999
}MMS_DATA_TYPE;


//mms数据结构
typedef struct mms_data_struct{

	//mms数据类型，枚举
	MMS_DATA_TYPE n_data_type;
	//mms数据，简单类型时使用
	char c_data[MAX_MMS_INFO_DATA_LEN];

	//mms数据结构成员个数
	int n_struct_num;
	//mms数据结构类型，各成员数据结构
	struct mms_data_struct *p_struct;

	int result;
}MMS_DATA_STRUCT;

//MMS变量结构体，对应61850里的参引
typedef struct mms_variable_struct{

	// domain_id字符串
	char c_domain_id[MAX_MMS_INFO_DES_LEN];
	// item_id字符串
	char c_item_id[MAX_MMS_INFO_DES_LEN];
}MMS_VARIABLE_STRUCT;

//fileOpen，fileRead，fileClose，Obtainfile，fileDelete文件句柄
typedef struct mms_file_read_idfp
{
	//从服务器返回的文件标识，一般是服务器端打开文件得到的文件句柄
	int		n_frsmid;	
	//本地打开的文件句柄
	FILE	*fp;		

}MMS_FILE_READ_IDFP;

//fileOpen，fileRead，fileClose，Obtainfile，fileDelete服务参数
typedef struct mms_file_srv_param_struct
{
	//源文件名称，远方服务器文件名
	char c_src_fname[MAX_MMS_INFO_FILENAME_LEN+1];	
	
	int n_init_pos;

	//从服务器返回的文件标识，一般是服务器端打开文件得到的文件句
	int		n_frsmid;	
	//文件属性
	MMS_FILE_ATTR_STRUCT mms_file_attr;

	/* pointer to file data octets	*/
	char *p_file_data;			
	/* additional file content	*/

        unsigned char b_more_follows;

	//对于Obtainfile	
	char dest_fname[MAX_MMS_INFO_FILENAME_LEN+1];	//目标文件名称，存到本地文件系统中用的名字

}MMS_FILE_SRV_PARAM_STRUCT;

/** 
* DataAccessError定义
*/
typedef enum                              
{ 
	MS_DATA_ACCESS_ERR_CODE_OBJECT_INVALIDATED,							//对象无效
	MS_DATA_ACCESS_ERR_CODE_HARDWARE_FAULT,				//硬件错误
	MS_DATA_ACCESS_ERR_CODE_TEMPORARILY_UNVAILABLE,		//暂时不可访问
	MS_DATA_ACCESS_ERR_CODE_OBJECT_ACCESS_DENIED,		//对象访问拒绝
	MS_DATA_ACCESS_ERR_CODE_OBJECT_UNDEFINED,							//对象没定义
	MS_DATA_ACCESS_ERR_CODE_INVALID_ADDRESS,			//无效地址
	MS_DATA_ACCESS_ERR_CODE_TYPE_UNSUPPORTED,							//类型不支持
	MS_DATA_ACCESS_ERR_CODE_TYPE_INCONSISTENT,			//类型不一致
	MS_DATA_ACCESS_ERR_CODE_OBJECT_ATTRIBUTE_INCONSISTENT,				//对象属性不一致
	MS_DATA_ACCESS_ERR_CODE_OBJECT_ACCESS_UNSUPPORTED,					//对象访问不支持
	MS_DATA_ACCESS_ERR_CODE_OBJECT_NON_EXISTENT,		//对象不存在
	MS_DATA_ACCESS_ERR_CODE_OBJECT_VALUE_INVALID,						//对象值无效

	MS_DATA_ACCESS_ERR_CODE_NO_ERR = 9999				//无错误
	
}MMS_DATA_ACCESS_ERR_CODE;

//启动的细节
typedef struct mms_init_detail_struct
{
	//主叫建议/被叫协商 版本号
	signed short n_VersionNum;

	//建议/协商 参数
	char c_paramCBB[MAX_BIT_MMS_PARAM_CBB+1];

	char c_addition_paramCBB[MAX_BIT_MMS_PARAM_CBB+1];

	//主叫/被叫 支持的服务
	char c_supportedCall[MAX_BIT_MMS_SURPPORTED_CALLING+1];

	char c_addition_supportedCall[MAX_BIT_MMS_SURPPORTED_CALLING+1];

}MMS_INIT_DETAIL_STRUCT;

//环境和通用管理参数结构
typedef struct mms_comm_manage_param_struct
{
	//Max_Mms_Pdu_Length
        int n_localDetailCall;

	//建议/协商最大主叫服务器数目
        short n_maxOutstandingCalling;

	//建议/协商最大被叫服务器数目
        short n_maxOutstandingCalled;

	//
        char n_dataStructNestingLevel;

	//本地主叫/被叫细节
	MMS_INIT_DETAIL_STRUCT struct_init_Detail;

}MMS_COMM_MANAGE_PARAM_STRUCT;

//文件目录服务参数结构
typedef struct mms_file_directory_struct
{
	//文件路径
	char c_file_request_directory[MAX_MMS_INFO_FILEDIRECTORY_LEN+1];

	//文件个数
	int n_file_num;			
	//文件结构体数组首指针
	MMS_FILE_ENTRY_STRUCT *p_file_entry_struct;	
	//是否有后续帧
        unsigned char b_morefollows;

}MMS_FILE_DIRECTORY_STRUCT;

//MMS服务错误类号
typedef enum 
{
	N_WMD_STATE,
	N_APPLICATION_REFERENCE,
	N_DEFINITION,
	N_RESOURCE,
	N_SERVICE,
	N_SERVICE_PREEMPT,
	N_TIME_RESOLUTION,
	N_ACCESS,
	N_INITIATE,
	N_CONCLUDE,
	N_CANCEL,
	N_FILE,
	N_OTHERS,

	N_NO_ERROR_CLASS = 9999,

}MMS_SRV_ERROR_CLASS;

//MMS的Service-Error结构
typedef struct mms_service_error
{
	//服务错误类号
	int n_error_class;

	//服务错误代码
	int	n_error_code;

	int n_serviceSpecificInfo;

}MMS_SERVICE_ERROR;

//MMS的rejectPdu
typedef enum
{
	REJECT_UNKOWN_PDU = -1,
	REJECT_CONFIRMED_REQUEST_PDU = 1,
	REJECT_CONFIRMED_RESPONSE_PDU,
	REJECT_CONFIRMED_ERROR_PDU,
	REJECT_UNCONFIRMED_PDU,
	REJECT_PDU_ERROR,
	REJECT_CANCEL_REQUEST_PDU,
	REJECT_CANCEL_RESPONSE_PDU,
	REJECT_CANCEL_ERROR_PDU,
	REJECT_CANCLUDE_REQUEST_PDU,
	REJECT_CANCLUDE_RESPONSE_PDU,
	REJECT_CANCLUDE_ERROR_PDU

}REJECT_PDU;

//MMS的reject服务结构
typedef struct mms_service_reject
{
	int n_originalInvoikeID;

	//pdu
	REJECT_PDU n_reject_pdu;

	//拒绝原因代码
	int	n_reject_reason_code; 

}MMS_SERVICE_REJECT;

//MMS解析信息结构体
typedef struct mms_info_struct{
	
	//源地址ip
	char c_src_ip[MAX_MMS_INFO_IP_LEN];
	//目的地址ip
	char c_dest_ip[MAX_MMS_INFO_IP_LEN];

	//invokeID号，据此进行命令结果匹配
	int n_invoke_id;						
	
	//pdu类型，Request或者Response
	char c_pdu_type[MAX_MMS_INFO_DES_LEN];	

	//mms服务类型
	char c_service_type[MAX_MMS_INFO_DES_LEN];
	
	//变量个数
	int n_variable_num;	
	//变量结构体数组首指针
	MMS_VARIABLE_STRUCT *p_variable_struct;	

	//data个数（参引及值/值的结构体）
	int n_data_num;		
	//data结构的原数据结构指针，具体内容根据服务类型再做解析
	MMS_DATA_STRUCT *p_data_struct;			

	//文件目录服务参数结构
	MMS_FILE_DIRECTORY_STRUCT mms_file_directory;

	//文件服务参数结构
	MMS_FILE_SRV_PARAM_STRUCT struct_file_srv_param;		

	//通用管理服务initiate、conclude、abort参数结构
	MMS_COMM_MANAGE_PARAM_STRUCT struct_comm_manage_param;	//mmslite关联函数mvla_initiate_req

	//service-error
	MMS_SERVICE_ERROR struct_mms_service_error;

	//reject服务
	MMS_SERVICE_REJECT struct_mms_service_reject;


}MMS_INFO_STRUCT;

/**********************************************新增 20121109**************************************/

/** 
* mms服务定义
*/
typedef enum                              
{  
	MMS_DETAIL_SRVC_TYPE_UNKNOWN = 9999,
		
	MMS_DETAIL_SRVC_TYPE_READ_REQ,							//read request
	MMS_DETAIL_SRVC_TYPE_READ_RESP,							//read response

	MMS_DETAIL_SRVC_TYPE_WRITE_REQ,							//write request
	MMS_DETAIL_SRVC_TYPE_WRITE_RESP,						//write response

	MMS_DETAIL_SRVC_TYPE_FILEDIRECTORY_REQ,					//fileDirectory request
	MMS_DETAIL_SRVC_TYPE_FILEDIRECTORY_RESP,				//fileDirectory response

	MMS_DETAIL_SRVC_TYPE_FILEOPEN_REQ,						//fileOpen request
	MMS_DETAIL_SRVC_TYPE_FILEOPEN_RESP,						//fileOpen response

	MMS_DETAIL_SRVC_TYPE_FILEREAD_REQ,						//fileRead request
	MMS_DETAIL_SRVC_TYPE_FILEREAD_RESP,						//fileRead response

	MMS_DETAIL_SRVC_TYPE_FILECLOSE_REQ,						//fileClose request
	MMS_DETAIL_SRVC_TYPE_FILECLOSE_RESP,					//fileClose response

	MMS_SRV_TYPE_OBTAIN_FILE_REQ,							//obtainFile request
	MMS_SRV_TYPE_OBTAIN_FILE_RESP,							//obtainFile response

	MMS_SRV_TYPE_FILEDELETE_REQ,							//deleteFile request
	MMS_SRV_TYPE_FILEDELETE_RESP,							//deleteFile response

	MMS_DETAIL_SRVC_TYPE_INFO,								//informationReport

	MMS_DETAIL_SRVC_TYPE_INITIATE_REQ,						//Initiate request
	MMS_DETAIL_SRVC_TYPE_INITIATE_RESP,						//Initiate response

	MMS_DETAIL_SRVC_TYPE_P_ABORT_REQ,						//p_abort request
	MMS_DETAIL_SRVC_TYPE_P_ABORT_RESP,						//p_abort response

	MMS_DETAIL_SRVC_TYPE_CONCLUDE_REQ,						//conclude request
	MMS_DETAIL_SRVC_TYPE_CONCLUDE_RESP,						//conclude response

	MMS_DETAIL_SRVC_TYPE_REJECT,							//reject

	MMS_DETAIL_SRVC_TYPE_CANCEL_REQ,						//cancel request
	MMS_DETAIL_SRVC_TYPE_CANCEL_RESP,						//cancel response

	MMS_DETAIL_SRVC_TYPE_GETNAMELIST_REQ,					//GetNameList request
	MMS_DETAIL_SRVC_TYPE_GETNAMELIST_RESP,					//GetNameList response

	MMS_DETAIL_SRVC_TYPE_GETVARACCESSATTR_REQ,				//GetVariableAccessAttribute request
	MMS_DETAIL_SRVC_TYPE_GETVARACCESSATTR_RESP,				//GetVariableAccessAttribute response

	MMS_DETAIL_SRVC_TYPE_GETNAMEDVARLSTATTR_REQ,			//GetNamedVariableListAttributes request
	MMS_DETAIL_SRVC_TYPE_GETNAMEDVARLSTATTR_RESP,			//GetNamedVariableListAttributes response

	MMS_DETAIL_SRVC_TYPE_DEFINENAMEDVARLST_REQ,				//DefineNamedVariableList request
	MMS_DETAIL_SRVC_TYPE_DEFINENAMEDVARLST_RESP,			//DefineNamedVariableList response

	MMS_DETAIL_SRVC_TYPE_DELETENAMEDVARLST_REQ,				//DeleteNamedVariableList request
	MMS_DETAIL_SRVC_TYPE_DELETENAMEDVARLST_RESP,			//DeleteNamedVariableList response

	MMS_DETAIL_SRVC_TYPE_READJOURNAL_REQ,					//ReadJournal request
	MMS_DETAIL_SRVC_TYPE_READJOURNAL_RESP,					//ReadJournal response

	MMS_DETAIL_SRVC_TYPE_U_ABORT_REQ,						//u_abort request
	MMS_DETAIL_SRVC_TYPE_U_ABORT_RESP						//u_abort response
		
}MMS_DETAIL_SRVC_TYPE;


#endif	/* !MMSSTRUCT_INCLUDED	*/
