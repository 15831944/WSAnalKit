#ifndef PTP_ANALYZE_H_I
#define PTP_ANALYZE_H_I

#include "LogFile.h"
#include "acsistruct.h"
#include "AnalyzeOnline_STRUCT.h"
#include "share_scan.h"
#include "SYS_MODEL_STRUCT.h"
#include "Packet2Message_I.h"
/*************************PTP分析定值**********************/
#define SETTING_PTP_SQNUM_JUMP				0X00000001
#define SETTING_PTP_SQNUM_REVERSE				0X00000002
#define SETTING_PTP_STNUM_JUMP				0X00000004		
#define SETTING_PTP_STNUM_REVERSE				0X00000008
#define SETTING_PTP_SQNUM_UNRESET				0X00000010
#define SETTING_PTP_PTP_DOUBLE				0X00000020
#define SETTING_PTP_PTP_REPEAT				0X00000040
#define SETTING_PTP_STNUMCHANGE_FAKE			0X00000080
#define SETTING_PTP_PTP_DELAY				0X00000100
#define SETTING_PTP_TAL_ZERO					0X00000200
#define SETTING_PTP_APPID_ZERO				0X00000400
#define SETTING_PTP_NDSCOMM_TRUE				0X00000800
#define SETTING_PTP_T0_T3_ERR					0X00001000
#define SETTING_PTP_DANUM_DIFFER_DSMEMBERNUM	0X00002000
#define SETTING_PTP_GOCBREF_DIFFER_CFG		0X00004000
#define SETTING_PTP_GOID_DIFFER_CFG			0X00008000
#define SETTING_PTP_DS_DIFFER_CFG				0X00010000
#define SETTING_PTP_CONFREV_DIFFER_CFG		0X00020000
#define SETTING_PTP_DAENTRIES_DIFFER_DANUM	0X00040000
#define SETTING_PTP_DESTMAC_ERR				0X00080000
#define SETTING_PTP_PTP_RESTART				0X00100000
#define SETTING_PTP_STNUMCHANGE_RIGHT			0X00200000
#define SETTING_PTP_TEST_TRUE					0X00400000
#define SETTING_PTP_FORMAT_ERR				0X00800000
#define SETTING_PTP_MAC_DIFFER_CFG			0X01000000
#define SETTING_PTP_DATYPE_DIFFER_CFG			0X02000000
#define SETTING_PTP_PTP_DROP				0X04000000
#define SETTING_PTP_PTP_THEMBLE				0X08000000
#define SETTING_PTP_RESERVE1					0X10000000
#define SETTING_PTP_RESERVE2					0X20000000
#define SETTING_PTP_RESERVE3					0X40000000
#define SETTING_PTP_RESERVE4					0X80000000

enum PTP_ANALYZE_I_TYPE
{
	PTP_ANALYZE_I_TYPE_ONLINE = 1, //在线分析
	PTP_ANALYZE_I_TYPE_OFFLINE	//离线分析
};

//typedef struct _PTP_CFG_STRUCT
//{
//	//日志文件
//	CLogFile *pLogFile;
//
//	ACSI_IED_CTRL *pIED_ctrls;
//
//	//节点信息
//	SNIFFER_APP sniffer_app_info;
//
//	//遥信通道个数
//	int n_yx_channel_num;
//	//遥信通道队列
//	CFG_REC_CHANNEL** pyx_channel_list;
//
//	_PTP_CFG_STRUCT()
//	{
//		pLogFile = NULL;
//		pIED_ctrls = NULL;
//		n_yx_channel_num = 0;
//		pyx_channel_list = NULL;
//	}
//	
//
//}PTP_CFG_STRUCT;
//
//typedef struct _PTP_SETTING_STRUCT
//{
//
//	/**********************判据开关配置***********************************/
//	unsigned int nerr_switch_setting;
//
//	//PTP中断时间-定值(s)" name="">11</cfgitem>
//	unsigned int ao_ms_ptp_discon;                                    
//	//PTP同步延时时间-定值s" name="">2</cfgitem>
//	unsigned int ao_ms_ptp_syncdelay;                                 
//	//delay_resp(时钟请求)延时时间-定值(s)" name="">2</cfgitem>
//	unsigned int ao_ms_ptp_delayresp_delay;                           
//	//pdelay_resp(时钟请求two-step)延时时间-定值(s)" name="">2</cfgitem>
//	unsigned int ao_ms_ptp_pdelayresp_delay;                          
//	//CF域超差-定值(ns)" "name=">400000000</cfgitem>
//	unsigned int ao_ns_ptp_cf; 
//	//PTP同步报文中断时间-定值(s)" name="">10</cfgitem>
//	unsigned int ao_ms_ptp_syn_disc;                                  
//	//PTP的delay请求响应中断时间-定值(s)" name="">10</cfgitem>
//	unsigned int ao_ms_ptp_delayresp_disc;                            
//	//TP的pdelay请求响应中断时间-定值断时间-定值(s)" name="">10</cfgitem>
//	unsigned int ao_ms_ptp_pdelayresp_disc;
//
//	_PTP_SETTING_STRUCT()
//	{
//		//PTP中断时间-定值(s)" name="">11</cfgitem>
//		ao_ms_ptp_discon=11;                                    
//		//PTP同步延时时间-定值s" name="">2</cfgitem>
//		ao_ms_ptp_syncdelay=2;                                 
//		//delay_resp(时钟请求)延时时间-定值(s)" name="">2</cfgitem>
//		ao_ms_ptp_delayresp_delay=2;                           
//		//pdelay_resp(时钟请求two-step)延时时间-定值(s)" name="">2</cfgitem>
//		ao_ms_ptp_pdelayresp_delay=2;                          
//		//CF域超差-定值(ns)" "name=">400000000</cfgitem>
//		ao_ns_ptp_cf=400000000; 
//		//PTP同步报文中断时间-定值(s)" name="">10</cfgitem>
//		ao_ms_ptp_syn_disc=10;                                  
//		//PTP的delay请求响应中断时间-定值(s)" name="">10</cfgitem>
//		ao_ms_ptp_delayresp_disc=10;                            
//		//TP的pdelay请求响应中断时间-定值断时间-定值(s)" name="">10</cfgitem>
//		ao_ms_ptp_pdelayresp_disc=10;                           
//
//		nerr_switch_setting = 0XFFFFFFFF;
//	}
//
//}PTP_SETTING_STRUCT;

#ifdef OS_WINDOWS

#ifdef DLL_FILE_PTP 

class _declspec(dllexport) CPtpAnalyze_I //导出类 

#else 

class _declspec(dllimport) CPtpAnalyze_I //导入类 

#endif//DLL_FILE_PTP

#endif//OS_WINDOWS

#ifdef OS_LINUX

class CPtpAnalyze_I

#endif //OS_LINUX

{
protected:
	CPtpAnalyze_I(){};
	
public:
	virtual int ptpanalyze_init(PTP_CFG_STRUCT *pCfgInfo)=0;
	//考虑了闭锁机制的
	virtual MESSAGE_ERROR_INFO_ARRAY_STRUCT* ptpanalyze_online(PTP_INFO_STRUCT *p_ptp_infos, int n_num)=0;//不再支持
	//不考虑考虑闭锁机制
	virtual MESSAGE_ERROR_INFO_ARRAY_STRUCT* ptpanalyze_offline(PTP_INFO_STRUCT *p_ptp_infos, int n_num)=0;

	virtual int ptpanalyze_releasemsgerr(MESSAGE_ERROR_INFO_ARRAY_STRUCT* p_message_errs)=0;

	virtual int ptpanalyze_end()=0;
	virtual int GetPTP_MSG_TIME(PTP_INFO_STRUCT* p_ptp_info_struct,__int64 &time_s, UINT &time_ns)=0;

public:
	virtual int reset_lastinfo()=0;
	virtual int reset_gserr()=0;
	//virtual void set_pPktconvert(CPacketConvert_I *g_pPktconvert)=0; 
public:
	 
	virtual int ptpanalze_set_setting(PTP_SETTING_STRUCT* p_setiing)=0;
	virtual MESSAGE_ERROR_INFO_ARRAY_STRUCT* ptpanalyze_withcool(PTP_INFO_STRUCT *p_ptp_infos, int n_num,bool bCool)=0;

};


#ifdef OS_WINDOWS

#ifdef DLL_FILE_PTP 

//导出函数

extern "C"  __declspec( dllexport ) CPtpAnalyze_I * createPTPAnalyze_I();
extern "C"  __declspec( dllexport ) void destroyPTPAnalyze_I(CPtpAnalyze_I* theInterface);

#else 

//导入函数

extern "C"  __declspec( dllimport ) CPtpAnalyze_I * createPTPAnalyze_I();
extern "C"  __declspec( dllimport ) void destroyPTPAnalyze_I(CPtpAnalyze_I* theInterface);

#endif //DLL_FILE_PTP
#endif //OS_WINDOWS

#ifdef OS_LINUX
#ifdef __cplusplus
extern "C"
{
#endif
	
	CPtpAnalyze_I * createPTPAnalyze_I();
	void destroyPTPAnalyze_I(CPtpAnalyze_I* theInterface);
	
#ifdef __cplusplus
}
#endif

#endif //OS_LINUX


#endif /*PTP_ANALYZE_H_I*/