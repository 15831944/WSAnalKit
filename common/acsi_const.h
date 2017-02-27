#ifndef ACSI_CONST_INCLUDE
#define ACSI_CONST_INCLUDE


#define MAX_NAME_LEN 32 //对象名称长度
#define MAX_IP_LEN 15   //ip地址长度
#define MAX_FILE_DIRECTORY_LEN 31	//文件路径长度
#define MAX_FILE_NAME_LEN 255	//文件名长度
#define MAX_TIME_LEN	31	//文件最后修改时间长度

#define SRV_RESULT_SUCCESS	9999//服务结果成功

/** 
* 报告触发选项定义，和本地数据格式的trgop值一致，长度为一个字节
*/
#define     ACSI_RPT_REASON_RESERVED  0x80
#define     ACSI_RPT_REASON_DCH  0x40
#define     ACSI_RPT_REASON_QCH  0x20
#define     ACSI_RPT_REASON_DUPD  0x10
#define     ACSI_RPT_REASON_INTGPD  0x08
#define     ACSI_RPT_REASON_GI  0x04
#define     ACSI_RPT_REASON_UNKNOWN 0x02

/**                                            
* 61850对象类型                                
*/                                       
typedef enum                              
{  
	OBJECT_TYPE_UNKNOWN = 0,
	OBJECT_TYPE_IED,
	OBJECT_TYPE_LD,
	OBJECT_TYPE_LN,
	OBJECT_TYPE_DS,
	OBJECT_TYPE_FCN, //带fc的ln
	OBJECT_TYPE_FCD, 
	OBJECT_TYPE_FCDA,
	OBJECT_TYPE_CB  //控制块
}ACSI_OBJ_TYPE;

/**
* 61850简单数据类型     
*/
typedef enum{
	VAL_TYPE_UNKNOWN = 0,
	VAL_TYPE_BOOLEAN,   
	VAL_TYPE_ENUM,
	VAL_TYPE_INT8,
	VAL_TYPE_INT16,
	VAL_TYPE_INT32,
	VAL_TYPE_INT128,
	VAL_TYPE_INT8U,
	VAL_TYPE_INT16U,
	VAL_TYPE_INT32U,
	VAL_TYPE_FLOAT32,
	VAL_TYPE_FLOAT64, 
	VAL_TYPE_CODEDENUM,     //固定长度的bitstring, 2bit
	VAL_TYPE_TCMD,			//固定长度的bitstring, 2bit
	VAL_TYPE_OSTRING6,      //gocb$DstAddress$Addr
	VAL_TYPE_OSTRING8,      //变长octet string,最大长度8个字节
	VAL_TYPE_OSTRING64,     //变长octet string,最大长度64个字节
	VAL_TYPE_VSTRING64,     //可视变长字符串，最大长度64
	VAL_TYPE_VSTRING65,     //可视变长字符串，最大长度65
	VAL_TYPE_VSTRING129,     //可视变长字符串，最大长度129
	VAL_TYPE_VSTRING255	,	//可视变长字符串，最大长度255
	VAL_TYPE_UNISTRING255,  //utf-8字符串，最大255个字符
	
	VAL_TYPE_QUALITY,		//变长bitstring 13bit
	VAL_TYPE_TIMESTAMP,		//utctime
	VAL_TYPE_ENTRYTIME,		//binary time，btime6格式
	VAL_TYPE_OPTFLDS,		//变长bitstring 10bit
	VAL_TYPE_TRGC,			//变长bitstring 6bit
	VAL_TYPE_CHECK,			//变长bitstring 2bit
	VAL_TYPE_ENTRYID,		//固定长度的octet string, 8个字节
	VAL_TYPE_STRUCT			//复杂类型的数据
}AI_VAL_TYPE;

/**
* 控制块类型     
*/
typedef enum                  
{  
	CB_TYPE_UNKNOWN = 0,
	CB_TYPE_SG,             
	CB_TYPE_RP,
	CB_TYPE_BR,
	CB_TYPE_LOG,
	CB_TYPE_GO
}ACSI_CB_TYPE;

/** 
* mmspdu类型定义
*/
typedef enum                              
{  
	ACSI_MMSPDU_UNKNOWN = 0,
	ACSI_MMSPDU_REQ ,
	ACSI_MMSPDU_RESP,
	ACSI_MMSPDU_RPT,
	ACSI_MMSPDU_SRVERROR,
	ACSI_MMSPDU_REJECT
}ACSI_MMSPDU_TYPE;

/** 
* acsi服务定义
*/
//typedef enum                              
//{  
//	ACSI_SRVC_TYPE_UNKNOWN = 0,
//	ACSI_SRVC_TYPE_GETSERVERDIRECTORY,
//	ACSI_SRVC_TYPE_ASSOCIATE,
//	ACSI_SRVC_TYPE_RELEASE,
//	ACSI_SRVC_TYPE_ABORT,
//	ACSI_SRVC_TYPE_GETDATAVAL,
//	ACSI_SRVC_TYPE_SETDATAVALUES,
//	ACSI_SRVC_TYPE_REPORT,
//	ACSI_SRVC_TYPE_GETFILEDIRECTORY,
//	ACSI_SRVC_TYPE_GETFILE
//}ACSI_SRVC_TYPE;
typedef enum                              
{  
	ACSI_SRVC_TYPE_UNKNOWN = 0,
	ACSI_SRVC_TYPE_GETSERVERDIR,				//GetServerDirectory
	ACSI_SRVC_TYPE_ASSOCIATE,					//关联Associate
	ACSI_SRVC_TYPE_RELEASE,						//结束Release
	ACSI_SRVC_TYPE_ABORT,						//异常终止Abort

	ACSI_SRVC_TYPE_GETLOGICALDEVICEDIR,			//GetLogicalDeviceDirectory

	ACSI_SRVC_TYPE_GETLOGICALNODEDIR,			//GetLogicalNodeDirectory
	ACSI_SRVC_TYPE_GETALLDATAVALS,				//GetAllDataValues
	
	ACSI_SRVC_TYPE_GETDATAVALS,					//GetDataValues
	ACSI_SRVC_TYPE_SETDATAVALS,					//SetDataValues
	ACSI_SRVC_TYPE_GETDATADIR,					//GetDataDirectory
	ACSI_SRVC_TYPE_GETDATADEF,					//GetDataDefinition

	ACSI_SRVC_TYPE_REPORT,						//报告Reort
	ACSI_SRVC_TYPE_GETBRCBVALS,					//GetBRCBValues
	ACSI_SRVC_TYPE_SETBRCBVALS,					//SetBRCBValues
	ACSI_SRVC_TYPE_GETURCBVALS,					//GetURCBValues
	ACSI_SRVC_TYPE_SETURCBVALS,					//SetURCBValues

	ACSI_SRVC_TYPE_GETFILEDIRECTORY,			//GetFileDirectory
	ACSI_SRVC_TYPE_GETFILE_OPEN,				//GetFile_openfile
	ACSI_SRVC_TYPE_SETFILE,						//SetFile
	ACSI_SRVC_TYPE_DELETEFILE,					//DeleteFile

	ACSI_SRVC_TYPE_GETSGCBVALS,					//读顶值控制块的值GetSGCBValues
	ACSI_SRVC_TYPE_GETSGVALS,					//召唤定值GetSGValues
	ACSI_SRVC_TYPE_SETSGVALS,					//修改定值SetSGValues
	ACSI_SRVC_TYPE_CONFIRMEDITSGVALS,			//确认修改定值ConfirmEditSGValues
	ACSI_SRVC_TYPE_SELECTACTSG,					//切换激活区SelectActSG
	ACSI_SRVC_TYPE_SELECTEDITSG,				//切换编辑区SelectEditSG

	ACSI_SRVC_TYPE_GETDSVALS,					//GetDataSetValues
	ACSI_SRVC_TYPE_SETDSVALS,					//SetDataSetValues
	ACSI_SRVC_TYPE_CREATEDS,					//CreateDataSet
	ACSI_SRVC_TYPE_DELETEDS,					//DeleteDataSet
	ACSI_SRVC_TYPE_GETDSDIR,					//GetDataSetDirectory

	ACSI_SRVC_TYPE_SELECT,						//Select
	ACSI_SRVC_TYPE_SELECTWITHVAL,				//SelectWithValue
	ACSI_SRVC_TYPE_OPERATE,						//Operate
	ACSI_SRVC_TYPE_CANCEL,						//Cancel

	ACSI_SRVC_TYPE_GETGOCBVALS,					//GetGoCBValues
	ACSI_SRVC_TYPE_SETGOCBVALS,					//SetGoCBValues
	ACSI_SRVC_TYPE_GETGSCBVALS,					//GetGsCBValues
	ACSI_SRVC_TYPE_SETGSCBVALS,					//SetGsCBValues

	ACSI_SRVC_TYPE_GETMSVCBVALS,				//GetMSVCBValues
	ACSI_SRVC_TYPE_SETMSVCBVALS,				//SetMSVCBValues
	ACSI_SRVC_TYPE_GETUSVCBVALS,				//GetUSVCBValues
	ACSI_SRVC_TYPE_SETUSVCBVALS,				//SetUSVCBValues

	ACSI_SRVC_TYPE_GETLOGSTATUSVALS,			//GetLogStatusValues
	ACSI_SRVC_TYPE_QUERYLOGBYTIME,				//QueryLogByTime
	ACSI_SRVC_TYPE_QUERYLOGAFTER,				//QueryLogAfter

	ACSI_SRVC_TYPE_GETFILE_READ,				//GetFile_readfile
	ACSI_SRVC_TYPE_GETFILE_CLOSE,				//GetFile_closefile

	ACSI_SRVC_TYPE_GETFILEATTR					//GetFileAttributes

}ACSI_SRVC_TYPE;

/** 
* acsi错误定义
*/
typedef enum                              
{  
	ACSI_ERR_CODE_UNKNOWN = -1,

	ACSI_ERR_CODE_INSTANCE_NOT_AVAILABLE,	//实例不可用
	ACSI_ERR_CODE_INSTANCE_IN_USE,			//实例在使用
	ACSI_ERR_CODE_ACCESS_VIOLATION,			//访问违例
	ACSI_ERR_CODE_ACCESS_NOT_ALLOWED_IN_CURENT_STATE,//在当前状态下不允许访问
	ACSI_ERR_CODE_PARAMETER_VALUE_INAPPROPRIATE,//参数值不合适
	ACSI_ERR_CODE_PARAMETER_VALUE_INCONSISTENT,//参数值不一致
	ACSI_ERR_CODE_CLASS_NOT_SURPPORTED,//类不支持
	ACSI_ERR_CODE_INSTANCE_LOCKED_BY_OTHER_CLIENT,
	ACSI_ERR_CODE_CONTROL_MUST_BE_SELECTED,
	ACSI_ERR_CODE_TYPE_CONFILICT,
	ACSI_ERR_CODE_FAILED_DUE_TO_COMMUNICATIONS_CONSTRAINT,
	ACSI_ERR_CODE_FAILED_DUE_TO_SERVER_CONSTRAINT,

	ACSI_ERR_CODE_NO_ERR = 9999 //无错误
	
}ACSI_ERR_CODE;

///**
//*服务错误代码
//*/
//typedef enum
//{
//	//n_vmd_other = 0,
//	//n_vmd_state_confilict,
//	//n_vmd_operational_problem,
//	//n_vdm_domain_transfer_problem,
//	//n_vmd_state_machine_invalid,
//
//	//n_application_reference_other = 10,
//	//n_application_unreachable,
//	//n_application_connection_lost,
//	//n_application_context_unsupported,
//
//	//n_definition_other = 20,
//	//n_definition_object_undefined,
//	//n_definition_invalid_address,
//	//n_definition_type_unsurpported,
//	//n_definition_type_inconsistent,
//	//n_definition_object_exists,
//
//	//n_resourse_other = 30,
//	//n_resourse_memory_unavailable,
//	//n_resourse_processor_resource_unavailable,
//	//n_resourse_mass_storage_unavailable,
//	//n_resourse_capability_unavaliable,
//	//n_resourse_capability_unkown,
//
//	//n_service_other = 40,
//	//n_service_primitives_out_of_sequence,
//	//n_service_object_state_conflict,
//	//n_service_continuation_invalid,
//	//n_service_object_constraint_conflict,
//
//	//n_service_preempt_other = 50,
//	//n_service_timeout,
//	//n_service_deadlock,
//	//n_service_cancel,
//
//	//n_time_resolution_other = 60,
//	//n_time_resolution_unsupportable_time_resolution,
//	//
//	//n_access_other = 70,
//	//n_access_object_access_unsupported,
//	//n_access_object_non_existent,
//	//n_access_object_access_denied,
//	//n_access_object_invalidated,
//
//	//n_initiate_other = 80,
//	//n_initiate_max_services_outstanding_calling_insufficient,
//	//n_initiate_outstanding_called_insufficient,
//	//n_initiate_services_cbb_insufficient,
//	//n_initiate_parameter_cbb_insufficient,
//	//n_initiate_nesting_level_insufficient,
//
//	//n_canclude_other = 90,
//	//n_canclude_further_communication_required,
//
//	//n_cancel_other = 100,
//	//n_cancel_invike_id_unknown,
//	//n_cancel_cancel_not_possible,
//
//	//n_file_other = 110,
//	//n_file_filename_ambiguous,
//	//n_file_file_busy,
//	//n_file_filename_syntax_error,
//	//n_file_content_type_invalid,
//	//n_file_position_invalid,
//	//n_file_file_access_denied,
//	//n_file_non_existent,
//	//n_file_duplicate_filename,
//	//n_file_insufficient_space_in_filestore,
//
//	//n_others_additionalcode = 121,
//	//n_others_additonaldescription,
//	//n_others_servicespecificinfo
//
//	ACSI_SRV_ERR_CODE_UNKNOWN = -1,
//	ACSI_SRV_ERR_CODE_INSTANCE_NOT_AVAILABLE,	//实例不可用
//	ACSI_SRV_ERR_CODE_INSTANCE_IN_USE,			//实例在使用
//	ACSI_SRV_ERR_CODE_ACCESS_VIOLATION,			//访问违例
//	ACSI_SRV_ERR_CODE_ACCESS_NOT_ALLOWED_IN_CURENT_STATE,//在当前状态下不允许访问
//	ACSI_SRV_ERR_CODE_PARAMETER_VALUE_INAPPROPRIATE,	//参数值不合适
//	ACSI_SRV_ERR_CODE_PARAMETER_VALUE_INCONSISTENT,		//参数值不一致
//	ACSI_SRV_ERR_CODE_CLASS_NOT_SURPPORTED,				//类不支持
//	ACSI_SRV_ERR_CODE_INSTANCE_LOCKED_BY_OTHER_CLIENT,
//	ACSI_SRV_ERR__CODE_CONTROL_MUST_BE_SELECTED,
//	ACSI_SRV_ERR_CODE_TYPE_CONFILICT,
//	ACSI_SRV_ERR_CODE_FAILED_DUE_TO_COMMUNICATIONS_CONSTRAINT,
//	ACSI_SRV_ERR_CODE_FAILED_DUE_TO_SERVER_CONSTRAINT,
//	ACSI_SRV_ERR_CODE_NO_ERR = 9999			//无错误
//
//}ACSI_SRV_ERROR_CODE;      


/*********************************************以下是 2012-11-16 新增*********************************************/
//ACSI详细服务类型定义
typedef enum                              
{  
	ACSI_DETAIL_SRVC_TYPE_UNKNOWN = 0,

	/*****************************SERVER*******************************************************/
	ACSI_DETAIL_SRVC_TYPE_GETSERVERDIR_REQ,					//GetServerDirectory request
	ACSI_DETAIL_SRVC_TYPE_GETSERVERDIR_RESP,				//GetServerDirectory response

	ACSI_DETAIL_SRVC_TYPE_ASSOCIATE_REQ,					//关联Associate request
	ACSI_DETAIL_SRVC_TYPE_ASSOCIAT_RESP,					//关联Associate response

	ACSI_DETAIL_SRVC_TYPE_RELEASE_REQ,						//结束Release request
	ACSI_DETAIL_SRVC_TYPE_RELEASE_RESP,						//结束Release response

	ACSI_DETAIL_SRVC_TYPE_ABORT_REQ,						//异常终止Abort request
	ACSI_DETAIL_SRVC_TYPE_ABORT_RESP,						//异常终止Abort response

	/******************************logical device**********************************************/
	ACSI_DETAIL_SRVC_TYPE_GETLOGICALDEVICEDIR_REQ,			//GetLogicalDeviceDirectory request
	ACSI_DETAIL_SRVC_TYPE_GETLOGICALDEVICEDIR_RESP,			//GetLogicalDeviceDirectory response
	
	/******************************logical node**********************************************/
	ACSI_DETAIL_SRVC_TYPE_GETLOGICALNODEDIR_REQ,			//GetLogicalNodeDirectory request
	ACSI_DETAIL_SRVC_TYPE_GETLOGICALNODEDIR_RESP,			//GetLogicalNodeDirectory response

	ACSI_DETAIL_SRVC_TYPE_GETALLDATAVALS_REQ,				//GetAllDataValues request
	ACSI_DETAIL_SRVC_TYPE_GETALLDATAVALS_RESP,				//GetAllDataValues response

	/******************************logical device**********************************************/
	ACSI_DETAIL_SRVC_TYPE_GETDATAVALS_REQ,					//GetDataValues request
	ACSI_DETAIL_SRVC_TYPE_GETDATAVALS_RESP,					//GetDataValues response

	ACSI_DETAIL_SRVC_TYPE_SETDATAVALS_REQ,					//SetDataValues request
	ACSI_DETAIL_SRVC_TYPE_SETDATAVALS_RESP,					//SetDataValues response

	ACSI_DETAIL_SRVC_TYPE_GETDATADIR_REQ,					//GetDataDirectory request
	ACSI_DETAIL_SRVC_TYPE_GETDATADIR_RESP,					//GetDataDirectory response

	ACSI_DETAIL_SRVC_TYPE_GETDATADEF_REQ,					//GetDataDefinition request
	ACSI_DETAIL_SRVC_TYPE_GETDATADEF_RESP,					//GetDataDefinition response

	/******************************report control block******************************************/
	ACSI_DETAIL_SRVC_TYPE_REPORT,							//报告Reort

	ACSI_DETAIL_SRVC_TYPE_GETBRCBVALS_REQ,					//GetBRCBValues request
	ACSI_DETAIL_SRVC_TYPE_GETBRCBVALS_RESP,					//GetBRCBValues response

	ACSI_DETAIL_SRVC_TYPE_SETBRCBVALS_REQ,					//SetBRCBValues request
	ACSI_DETAIL_SRVC_TYPE_SETBRCBVALS_RESP,					//SetBRCBValues response

	ACSI_DETAIL_SRVC_TYPE_GETURCBVALS_REQ,					//GetURCBValues request
	ACSI_DETAIL_SRVC_TYPE_GETURCBVALS_RESP,					//GetURCBValues response

	ACSI_DETAIL_SRVC_TYPE_SETURCBVALS_REQ,					//SetURCBValues request
	ACSI_DETAIL_SRVC_TYPE_SETURCBVALS_RESP,					//SetURCBValues response

	/******************************File transfer*************************************************/
	ACSI_DETAIL_SRVC_TYPE_GETFILEDIRECTORY_REQ,				//GetFileDirectory request
	ACSI_DETAIL_SRVC_TYPE_GETFILEDIRECTORY_RESP,			//GetFileDirectory response

	ACSI_DETAIL_SRVC_TYPE_GETFILE_OPEN_REQ,					//GetFile_openfile request
	ACSI_DETAIL_SRVC_TYPE_GETFILE_OPEN_RESP,				//GetFile_openfile response

	ACSI_DETAIL_SRVC_TYPE_GETFILE_READ_REQ,					//GetFile_readfile request
	ACSI_DETAIL_SRVC_TYPE_GETFILE_READ_RESP,				//GetFile_readfile response
	
	ACSI_DETAIL_SRVC_TYPE_GETFILE_CLOSE_REQ,				//GetFile_closefile request
	ACSI_DETAIL_SRVC_TYPE_GETFILE_CLOSE_RESP,				//GetFile_closefile response

	ACSI_DETAIL_SRVC_TYPE_SETFILE_REQ,						//SetFile request
	ACSI_DETAIL_SRVC_TYPE_SETFILE_RESP,						//SetFile response

	ACSI_DETAIL_SRVC_TYPE_DELETEFILE_REQ,					//DeleteFile request
	ACSI_DETAIL_SRVC_TYPE_DELETEFILE_RESP,					//DeleteFile response

	/******************************setting control block******************************************/
	ACSI_DETAIL_SRVC_TYPE_GETSGCBVALS_REQ,					//读顶值控制块的值GetSGCBValues request
	ACSI_DETAIL_SRVC_TYPE_GETSGCBVALS_RESP,					//读顶值控制块的值GetSGCBValues response

	ACSI_DETAIL_SRVC_TYPE_GETSGVALS_REQ,					//召唤定值GetSGValues request
	ACSI_DETAIL_SRVC_TYPE_GETSGVALS_RESP,					//召唤定值GetSGValues response

	ACSI_DETAIL_SRVC_TYPE_SETSGVALS_REQ,					//修改定值SetSGValues request
	ACSI_DETAIL_SRVC_TYPE_SETSGVALS_RESP,					//修改定值SetSGValues response

	ACSI_DETAIL_SRVC_TYPE_CONFIRMEDITSGVALS_REQ,			//确认修改定值ConfirmEditSGValues request
	ACSI_DETAIL_SRVC_TYPE_CONFIRMEDITSGVALS_RESP,			//确认修改定值ConfirmEditSGValues response

	ACSI_DETAIL_SRVC_TYPE_SELECTACTSG_REQ,					//切换激活区SelectActSG request
	ACSI_DETAIL_SRVC_TYPE_SELECTACTSG_RESP,					//切换激活区SelectActSG response

	ACSI_DETAIL_SRVC_TYPE_SELECTEDITSG_REQ,					//切换编辑区SelectEditSG request
	ACSI_DETAIL_SRVC_TYPE_SELECTEDITSG_RESP,				//切换编辑区SelectEditSG response

	/******************************data set********************************************************/
	ACSI_DETAIL_SRVC_TYPE_GETDSVALS_REQ,					//GetDataSetValues request
	ACSI_DETAIL_SRVC_TYPE_GETDSVALS_RESP,					//GetDataSetValues response

	ACSI_DETAIL_SRVC_TYPE_SETDSVALS_REQ,					//SetDataSetValues request
	ACSI_DETAIL_SRVC_TYPE_SETDSVALS_RESP,					//SetDataSetValues response

	ACSI_DETAIL_SRVC_TYPE_CREATEDS_REQ,						//CreateDataSet request
	ACSI_DETAIL_SRVC_TYPE_CREATEDS_RESP,					//CreateDataSet response

	ACSI_DETAIL_SRVC_TYPE_DELETEDS_REQ,						//DeleteDataSet request
	ACSI_DETAIL_SRVC_TYPE_DELETEDS_RESP,					//DeleteDataSet response

	ACSI_DETAIL_SRVC_TYPE_GETDSDIR_REQ,						//GetDataSetDirectory request
	ACSI_DETAIL_SRVC_TYPE_GETDSDIR_RESP,					//GetDataSetDirectory response

	/******************************Control********************************************************/
	ACSI_DETAIL_SRVC_TYPE_SELECT_REQ,						//Select request
	ACSI_DETAIL_SRVC_TYPE_SELECT_RESP,						//Select response

	ACSI_DETAIL_SRVC_TYPE_SELECTWITHVAL_REQ,				//SelectWithValue request
	ACSI_DETAIL_SRVC_TYPE_SELECTWITHVAL_RESP,				//SelectWithValue response

	ACSI_DETAIL_SRVC_TYPE_OPERATE_REQ,						//Operate request
	ACSI_DETAIL_SRVC_TYPE_OPERATE_RESP,						//Operate response

	ACSI_DETAIL_SRVC_TYPE_CANCEL_REQ,						//Cancel request
	ACSI_DETAIL_SRVC_TYPE_CANCEL_RESP,						//Cancel response

	ACSI_DETAIL_SRVC_TYPE_CommandTermination_REQ,			//CommandTermination request
	ACSI_DETAIL_SRVC_TYPE_CommandTermination_RESP,			//CommandTermination response
	
	ACSI_DETAIL_SRVC_TYPE_TimeActivatedOperate_REQ,			//TimeActivatedOperate request
	ACSI_DETAIL_SRVC_TYPE_TimeActivatedOperate_RESP,		//TimeActivatedOperate response
	
	/******************************GOOSE********************************************************/
	ACSI_DETAIL_SRVC_TYPE_GETGOCBVALS_REQ,					//GetGoCBValues request
	ACSI_DETAIL_SRVC_TYPE_GETGOCBVALS_RESP,					//GetGoCBValues response

	ACSI_DETAIL_SRVC_TYPE_SETGOCBVALS_REQ,					//SetGoCBValues request
	ACSI_DETAIL_SRVC_TYPE_SETGOCBVALS_RESP,					//SetGoCBValues response

	ACSI_DETAIL_SRVC_TYPE_GetGoReference_REQ,				//GetGoReference  request
	ACSI_DETAIL_SRVC_TYPE_GetGoReference_RESP,				//GetGoReference response
	
	ACSI_DETAIL_SRVC_TYPE_GetGOOSEElementNumber_REQ,		//GetGOOSEElementNumber  request
	ACSI_DETAIL_SRVC_TYPE_GetGOOSEElementNumber_RESP,		//GetGOOSEElementNumber response
	
	ACSI_DETAIL_SRVC_TYPE_SendGOOSEMessage_REQ,				//SendGOOSEMessage  request
	ACSI_DETAIL_SRVC_TYPE_SendGOOSEMessage_RESP,			//SendGOOSEMessage response

	/******************************GSSE********************************************************/
	ACSI_DETAIL_SRVC_TYPE_GETGSCBVALS_REQ,					//GetGsCBValues request
	ACSI_DETAIL_SRVC_TYPE_GETGSCBVALS_RESP,					//GetGsCBValues response

	ACSI_DETAIL_SRVC_TYPE_SETGSCBVALS_REQ,					//SetGsCBValues request
	ACSI_DETAIL_SRVC_TYPE_SETGSCBVALS_RESP,					//SetGsCBValues response
	
	/******************************MSVCB********************************************************/
	ACSI_DETAIL_SRVC_TYPE_GETMSVCBVALS_REQ,					//GetMSVCBValues request
	ACSI_DETAIL_SRVC_TYPE_GETMSVCBVALS_RESP,				//GetMSVCBValues response

	ACSI_DETAIL_SRVC_TYPE_SETMSVCBVALS_REQ,					//SetMSVCBValues request
	ACSI_DETAIL_SRVC_TYPE_SETMSVCBVALS_RESP,				//SetMSVCBValues response

	/******************************USVCB********************************************************/
	ACSI_DETAIL_SRVC_TYPE_GETUSVCBVALS_REQ,					//GetUSVCBValues request
	ACSI_DETAIL_SRVC_TYPE_GETUSVCBVALS_RESP,				//GetUSVCBValues response

	ACSI_DETAIL_SRVC_TYPE_SETUSVCBVALS_REQ,					//SetUSVCBValues request
	ACSI_DETAIL_SRVC_TYPE_SETUSVCBVALS_RESP,				//SetUSVCBValues response
	
	/******************************log control block********************************************************/

	ACSI_DETAIL_SRVC_TYPE_GETLCBVALS_REQ,					//GetLCBValues  request
	ACSI_DETAIL_SRVC_TYPE_GETLCBVALS_RESP,					//GetLCBValues  response

	ACSI_DETAIL_SRVC_TYPE_SETLCBVALS_REQ,					//SetLCBValues request
	ACSI_DETAIL_SRVC_TYPE_SETLCBVALS_RESP,					//SetLCBValues response

	ACSI_DETAIL_SRVC_TYPE_GETLOGSTATUSVALS_REQ,				//GetLogStatusValues request
	ACSI_DETAIL_SRVC_TYPE_GETLOGSTATUSVALS_RESP,			//GetLogStatusValues response

	ACSI_DETAIL_SRVC_TYPE_QUERYLOGBYTIME_REQ,				//QueryLogByTime request
	ACSI_DETAIL_SRVC_TYPE_QUERYLOGBYTIME_RESP,				//QueryLogByTime response

	ACSI_DETAIL_SRVC_TYPE_QUERYLOGAFTER_REQ,				//QueryLogAfter request
	ACSI_DETAIL_SRVC_TYPE_QUERYLOGAFTER_RESP,				//QueryLogAfter response

	/*********************************************************************************/
	ACSI_DETAIL_SRVC_TYPE_SERVICE_FAIL_RESP,				//ServiceResponse- 服务否定响应
	ACSI_DETAIL_SRVC_TYPE_SERVICE_ERROR,					//ServiceError
	ACSI_DETAIL_SRVC_TYPE_REJECT,							//RejectError
	ACSI_DETAIL_SRVC_TYPE_ASSOCIATE_FAIL,					//关联Associate response
	ACSI_DETAIL_SRVC_TYPE_SETBRCBVALS_RPTENA_REQ,			//SetBRCBValues request
	/******************************READ WRITE**********************************************/
	ACSI_DETAIL_SRVC_TYPE_MMS_READ_,				    //GetAllDataValues request
	ACSI_DETAIL_SRVC_TYPE_MMS_READ_RESP_,			//GetAllDataValues request
	ACSI_DETAIL_SRVC_TYPE_MMS_WRITE_,				//GetAllDataValues response
	ACSI_DETAIL_SRVC_TYPE_MMS_WRITE_RESP_,				//GetAllDataValues response
	ACSI_DETAIL_SRVC_TYPE_GETFILEDIRECTORY_FAIL_,
	ACSI_DETAIL_ETHER_TYPE_TCP_FIN,
	ACSI_DETAIL_ETHER_TYPE_TCP_SYN_REQ,
	ACSI_DETAIL_ETHER_TYPE_TCP_SYN_RESP,
	ACSI_DETAIL_ETHER_TYPE_TCP_RST,
	ACSI_DETAIL_ETHER_TYPE_TCP_PSH,
	ACSI_DETAIL_ETHER_TYPE_TCP_ACK,
	ACSI_DETAIL_ETHER_TYPE_TCP_URG,
	
}ACSI_DETAIL_SRVC_TYPE; //参考 MMS_DETAIL_SRVC_TYPE作为补充，和本处有重复

//MMS->ACSI事件号定义
typedef enum
{
	MMS_2_ACSI_EVENT_ID_UNKOWN=0,					//未知MMS事件
	MMS_2_ACSI_EVENT_ID_ASSOCIATE,					//Associate
	MMS_2_ACSI_EVENT_ID_ABORT,						//Abort
	MMS_2_ACSI_EVENT_ID_RELEASE,					//Release
	MMS_2_ACSI_EVENT_ID_REPORT,						//Report
	MMS_2_ACSI_EVENT_ID_SETSGVALUES,				//SetSGValues
	MMS_2_ACSI_EVENT_ID_CONFIRMEDITSGVALUES,		//ConfirmEditSGValues				
	MMS_2_ACSI_EVENT_ID_SELECTACTIVESG,				//SelectActiveSG
	MMS_2_ACSI_EVENT_ID_SELECT,						//Select
	MMS_2_ACSI_EVENT_ID_SELECTWITHVALUE,			//SelectWithValue
	MMS_2_ACSI_EVENT_ID_OPERATE,					//Operate
	MMS_2_ACSI_EVENT_ID_CANCLE,						//Cancel

	MMS_2_ACSI_EVENT_ID_SERVICE_FAIL_RESP,			//服务否定响应
	MMS_2_ACSI_EVENT_ID_SERVICE_ERROR,				//服务错误
	MMS_2_ACSI_EVENT_ID_SOE_DATA_VALUES_INVALID,	//SOE报告中数据值无效
	MMS_2_ACSI_EVENT_ID_RCB_INIT_ERROR,				//报告控制块初始化异常
	MMS_2_ACSI_EVENT_ID_DIFFER_SCD,					//与SCD文件配置不一致
	MMS_2_ACSI_EVENT_ID_REJECT,						//服务拒绝
	MMS_2_ACSI_EVENT_ID_TCP_FIN,					//释放链接					
	MMS_2_ACSI_EVENT_ID_TCP_SYN_REQ,				//请求连接			
	MMS_2_ACSI_EVENT_ID_TCP_SYN_RESP,				//接受链接
	MMS_2_ACSI_EVENT_ID_TCP_RST,					//重置链接
	MMS_2_ACSI_EVENT_ID_TCP_PUSH,					//应用层有数据，接受放需要尽快处理
	MMS_2_ACSI_EVENT_ID_TCP_ACK,					//保持连接
	MMS_2_ACSI_EVENT_ID_TCP_URG,					//紧急数据
	MMS_2_ACSI_EVENT_ID_GETBRCBVALS_REQ,       //读报告控制块
	MMS_2_ACSI_EVENT_ID_SETBRCBVALS_REQ,      //写报告控制块
	MMS_2_ACSI_EVENT_ID_SETBRCBVALS_RPTENA_REQ,     //报告使能请求
	MMS_2_ACSI_EVENT_ID_ASSOCIATE_SUC,			    //Associate
	MMS_2_ACSI_EVENT_ID_ASSOCIATE_FAIL,             //关联失败
	MMS_2_ACSI_EVENT_ID_GETFILEDIRECTORY,           //读取文件列表
	MMS_2_ACSI_EVENT_ID_GETFILEDIRECTORY_SUC,       //读取文件列表成功
	MMS_2_ACSI_EVENT_ID_CANCLE_SUC,                 //取消控制成功
	MMS_2_ACSI_EVENT_ID_SELECTEDITSG,               //选择编辑定值区号
	MMS_2_ACSI_EVENT_ID_SERVICE_GENERAL_READ,       //读服务
	MMS_2_ACSI_EVENT_ID_SERVICE_GENERAL_READ_SUC,   //读服务成功
	MMS_2_ACSI_EVENT_ID_SERVICE_GENERAL_WRITE,      //写服务
	MMS_2_ACSI_EVENT_ID_SERVICE_GENERAL_WRITE_SUC,  //写服务成功
	MMS_2_ACSI_EVENT_ID_GETFILEDIRECTORY_FAIL,      //读取文件列表失败
	MMS_2_ACSI_EVENT_ID_GETURCBVALS_REQ,       //读报告控制块 非缓存
	MMS_2_ACSI_EVENT_ID_SETURCBVALS_REQ,      //写报告控制块 非缓存
	//将来扩展
	MMS_2_ACSI_EVENT_ID_GETALLDATAVALS,//总召
	MMS_2_ACSI_EVENT_ID_GETDSVALS, //读写数据集
	MMS_2_ACSI_EVENT_ID_SETDSVALS,
	MMS_2_ACSI_EVENT_ID_GETSGVALS,//召唤定值
	MMS_2_ACSI_EVENT_ID_GETLCBVALS,//读写日志报告控制块
	MMS_2_ACSI_EVENT_ID_SETLCBVALS,
	MMS_2_ACSI_EVENT_ID_GETGOCBVALS,//goose控制块
	MMS_2_ACSI_EVENT_ID_SETGOCBVALS,
	MMS_2_ACSI_EVENT_ID_GETGSCBVALS,//gsse控制块
	MMS_2_ACSI_EVENT_ID_SETGSCBVALS,
	MMS_2_ACSI_EVENT_ID_GETMSVCBVALS,//采样控制块多路
	MMS_2_ACSI_EVENT_ID_SETMSVCBVALS,
	MMS_2_ACSI_EVENT_ID_GETUSVCBVALS,//采样控制块单路
	MMS_2_ACSI_EVENT_ID_SETUSVCBVALS_REQ,
	MMS_2_ACSI_EVENT_ID_GETSGCBVALS,//读当前定值区区号?
	MMS_2_ACSI_EVENT_ID_GETDATAVALS,
	MMS_2_ACSI_EVENT_ID_SETDATAVALS,

}MMS_2_ACSI_EVENT_ID;

//对象类型
typedef enum 
{
	DETAIL_OBJECT_TYPE_UNKOWN = 0,

	DETAIL_OBJECT_TYPE_IED,		//IED
	DETAIL_OBJECT_TYPE_LD,		//LD
	DETAIL_OBJECT_TYPE_LN,		//LN
	DETAIL_OBJECT_TYPE_DS,		//DataSet

// 	DETAIL_OBJECT_TYPE_FCN,		//带fc的ln
// 	DETAIL_OBJECT_TYPE_FCD, 
// 	DETAIL_OBJECT_TYPE_FCDA,

	DETAIL_OBJECT_TYPE_ST,
	DETAIL_OBJECT_TYPE_MX,
	DETAIL_OBJECT_TYPE_CO,
	DETAIL_OBJECT_TYPE_SP,
	DETAIL_OBJECT_TYPE_SV,
	DETAIL_OBJECT_TYPE_CF,
	DETAIL_OBJECT_TYPE_DC,
	DETAIL_OBJECT_TYPE_SG,
	DETAIL_OBJECT_TYPE_SE,
	DETAIL_OBJECT_TYPE_EX,

	DETAIL_OBJECT_TYPE_BRCB,			//缓存报告控制块
	DETAIL_OBJECT_TYPE_URCB,			//非缓存报告控制块
	DETAIL_OBJECT_TYPE_LCB,				//日志控制块
	DETAIL_OBJECT_TYPE_GOCB,			//GOOSE控制块
	DETAIL_OBJECT_TYPE_GSCB,			//GSSE控制块
	DETAIL_OBJECT_TYPE_MSVCB,			//多路广播采样值
	DETAIL_OBJECT_TYPE_USVCB,			//单路传输采样值控制块
	DETAIL_OBJECT_TYPE_SGCB,			//定值控制块

	DETAIL_OBJECT_TYPE_ACTSG,		//当前定值区号
	DETAIL_OBJECT_TYPE_EDITSG,		//编辑定值区号
	DETAIL_OBJECT_TYPE_CNFEDIT,		//CnfEdit
	DETAIL_OBJECT_TYPE_LACTTM,		//LActTm
	DETAIL_OBJECT_TYPE_OPER,		//Oper
	DETAIL_OBJECT_TYPE_SBO,			//SBO
	DETAIL_OBJECT_TYPE_SBOW,		//SBOw	
	DETAIL_OBJECT_TYPE_BRCB_RPTENA,		//缓存报告控制块使能
	DETAIL_OBJECT_TYPE_CANCEL,      //cancel遥控撤销

}DETAIL_OBJ_TYPE;


#endif /*ACSI_CONST_INCLUDE*/