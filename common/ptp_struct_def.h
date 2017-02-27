#ifndef PTP_STRUCT_DEF_H_INCLUDE
#define PTP_STRUCT_DEF_H_INCLUDE

#include "define_scan.h"
#include "const_scan.h"

/** PTP报文类型 */
enum PTP_MESSAGE_TYPE
{
	//EVENT
	PTP_SYNC_MESSAGE        = 0,
	PTP_DELAY_REQ_MESSAGE   = 1,
	PTP_PDELAY_REQ_MESSAGE  = 2,
	PTP_PDELAY_RESP_MESSAGE = 3,
	//备用4-7
	PTP_PDELAY_RESERVE_4 = 4,
	PTP_PDELAY_RESERVE_5 = 5,
	PTP_PDELAY_RESERVE_6 = 6,
	PTP_PDELAY_RESERVE_7 = 7,
	//
	PTP_FOLLOWUP_GENERAL     = 8,
	PTP_DELAY_RESP_GENERAL   = 9,
	PTP_PDELAY_RESP_FOLLOW_UP_GENERAL  = 10,
	PTP_ANNOUNCE_GENERAL  = 11,
	PTP_SIGNALING_GENERAL  = 12,
	PTP_MANAGEMENT_GENERAL   = 13,
	//备用14-15
	PTP_OTHER_GENERAL_14     = 14,
	PTP_OTHER_GENERAL_15      = 15,

};

#pragma pack (1) //指定按一个字节对齐

/** unsigned int48定义 */
typedef struct _UINT48
{
	UINT u_LSB_4byte;
	u_short u_MSB_2byte;
	
}UINT48;

/** int64定义 */
typedef struct _INTEGER64
{
	int n_LSB;
	int n_MSB;
	
	
}INTEGER64;

/** int64定义 */
typedef struct _CORRECTION_FIELD
{
	//纳秒
	UINT48 n_Ns_6byte;

	//纳秒的小数
	short n_SubNs_2byte;
	
	
}CORRECTION_FIELD;

/** PTP报文事件戳标记 */
typedef struct _PTP_TIME_STAMP
{
 	//6字节
 	UINT48 u_seconds;

	//4字节
	UINT u_nanoseconds;


}PTP_TIME_STAMP;

typedef struct _CLOCK_IDENTITY_STRUCT
{
	uint8 c_bit0;
	uint8 c_bit1;
	uint8 c_bit2;
	uint8 c_bit3;
	uint8 c_bit4;
	uint8 c_bit5;
	uint8 c_bit6;
	uint8 c_bit7;

}CLOCK_IDENTITY_STRUCT;

/* PortIdentity 定义 */
typedef struct _PORTIDENTITY_STRUCT
{
	//时钟标识
//	char c_clock_identity[11];
	CLOCK_IDENTITY_STRUCT clock_identity;

	//端口号
	u_short u_port_id;
	
	
}PORTIDENTITY_STRUCT;

/* PTP Message header */
typedef struct _PTP_MSGHEADER{
	
	//报文类型
	uint8 enum_ptp_msg_type;
	
	//PTP版本
	char n_ptp_vertion;
	
	//报文长度
	u_short n_msg_len;
	
	//域节点号 此消息的发出节点不同，domainNumber的值不同
	char n_domain_number; 

	//备用字节
	char c_reserved;
	
	//标志域
	short n_flag_field;//2字节
	
	//时间修正域，ns数* 65536(2的16次方) 值依赖于消息类型
	CORRECTION_FIELD correction_field;

	//备用字节
	int n_reserved;
	
	//发送PTP报文的源端口地址信息
	PORTIDENTITY_STRUCT port_identity; 
	
	//报文发送序列号
	u_short n_sq_id;
	
	//控制域值
	uint8 n_control_field;
	
	//兼容第一版本设置的值，日志消息间隔
	char n_logmsg_periond;
	
	_PTP_MSGHEADER()
	{
		enum_ptp_msg_type = PTP_PDELAY_RESERVE_4;
		n_ptp_vertion = 2;
		n_msg_len       = 0;
		n_domain_number = 0;
		n_flag_field = 0;
//		nint64_correction_field = 0;
		n_sq_id          = 0;
		n_control_field = 0;
		n_logmsg_periond = 0;
	}
	
}PTP_MSGHEADER;

/* ClockQuality 定义*/
typedef struct _CLOCK_QUALITY_STRUCT
{
	uint8 u_clockClass;
	char n_clockAccuracy;
	uint16 u_offsetScaledLogVariance;

	
}CLOCK_QUALITY_STRUCT;

/* announce 消息定义 */
typedef struct _ANNOUNCE_STRUCT
{
	//定义数值为0或精度为-1~+1的时间戳
	PTP_TIME_STAMP time_stamp_origin;

	//UTC与TAI时间标尺间的润秒时间差
	short n_utcoffset;

	//发送节点数据集成员的parentDS.grandmasterPriority1的值
	u_short u_masterpriority1;

	//grandmaster的时钟质量
	CLOCK_QUALITY_STRUCT clock_quality;

	//发送节点数据集成员的parentDS.grandmasterPriority2的值
	uint8 u_masterpriority2;

	//grandmaster的时钟设备ID
//	char c_clock_identity[8];
	CLOCK_IDENTITY_STRUCT clock_identity;

	//grandmaster与Slave设备间的时钟(差?)
	u_short u_steps_removed;

	//时钟源类型
	uint8 u_time_source;


}ANNOUNCE_STRUCT;

/* Sync 消息定义 */
typedef struct _SYNC_STRUCT
{
	//时间戳
	PTP_TIME_STAMP time_stamp_origin;
	
	
}SYNC_STRUCT;

/* Delay_Req 消息定义 */
typedef struct _DELAY_REQ_STRUCT
{
	//时间戳
	PTP_TIME_STAMP time_stamp_origin;

}DELAY_REQ_STRUCT;

/* Delay_Resp 消息定义 */
typedef struct _DELAY_RESP_STRUCT
{
	//响应delay_req报文的接收时间戳(t4)，精度为纳秒级
	PTP_TIME_STAMP time_stamp_origin;

	//delay_req的发送设备端口标识
	PORTIDENTITY_STRUCT port_identity;
	
	
}DELAY_RESP_STRUCT;

/* Follow_Up 消息定义 */
typedef struct _FOLLOW_UP_STRUCT
{
	//时间戳
	PTP_TIME_STAMP time_stamp_origin;
	
	
}FOLLOW_UP_STRUCT;

/* Pdelay_Req 消息定义 */
typedef struct _PDELAY_REQ_STRUCT
{
	//时间戳
	PTP_TIME_STAMP time_stamp_origin;
	
	
}PDELAY_REQ_STRUCT;

/* Pdelay_Resp 消息定义 */
typedef struct _PDELAY_RESP_STRUCT
{
	//在OneStep模式下为0，TowStep模式下为响应pdelay_req的接收时间戳(t2)，精度为纳秒级以上
	PTP_TIME_STAMP time_stamp_origin;
	
	//pdelay_req的发送设备端口标识
	PORTIDENTITY_STRUCT port_identity;
	
	
}PDELAY_RESP_STRUCT;

enum ACTITION_TYPE
{
	ACTTION_GET					=0,
	ACTTION_SET,
	ACTTION_RESPONSE,
	ACTTION_COMMOND,
	ACTTION_ACKNOWLEDGE,
	ACTTION_RESERVED1,
	ACTTION_RESERVED2,
	ACTTION_RESERVED3,
	ACTTION_RESERVED4,
	ACTTION_RESERVED5,
	ACTTION_RESERVED6,
	ACTTION_RESERVED7,
	ACTTION_RESERVED8,
	ACTTION_RESERVED9,
	ACTTION_RESERVED10,
	ACTTION_RESERVED11

};

/* management TLV field */
typedef struct _PTP_MANAGEMENT_TLV 
{
	//tlvType
	short n_tlv_type;

	//tlvLength
	u_short u_length_field;

	//值为0X0000~0XFFFF
	u_short u_management_id;

	//
	char *p_value_field;


}PTP_MANAGEMENT_TLV;


/* manage 管理消息定义 */
typedef struct _PTP_MANAGE_STRUCT
{
	//端口标识
	PORTIDENTITY_STRUCT port_identity;

	/*对于非响应的管理消息，startingBoundaryHops是依情况变化的。
	对于响应的管理消息，它的值是startingBoundaryHops－boundaryHops*/
	uint8 u_starting_boundary_hops;

	//管理消息在边界时钟的剩下需连续转发数量
	uint8 boundary_hops;

	uint8/*ACTITION_TYPE*/ n_action_filed;//4bit 值为0~F

	//备用字节
	char c_reserved;

	PTP_MANAGEMENT_TLV management_tlv;
	
	
}PTP_MANAGE_STRUCT;

typedef struct _PDELAY_FOLLOW_UP_STRUCT
{
	//响应pdelay_resp报文的发送时间戳(t3)，精度为ns级以上
	PTP_TIME_STAMP time_stamp_origin;
	
	//pdelay_resp的发送设备端口标识
	PORTIDENTITY_STRUCT port_identity;

}PDELAY_FOLLOW_UP_STRUCT;

typedef struct _SIGNALING_STRUCT
{
	//目的设备的端口标识
	PORTIDENTITY_STRUCT port_identity;

}SIGNALING_STRUCT;
enum enumPtpErr
{
	PTP_PKTERR_NONE=0,
	PTP_PKTERR_LEN=1,
	PTP_PKTERR_VAL=2
};
typedef struct _PTP_INFO_STRUCT
{
	/****************报文属性***********************/
	char c_avtm_epocsec[MAX_ARV_TIME_LEN];
	//源MAC地址
	char c_src_mac[MAX_MAC_LEN];	
	//目的MAC地址
	char c_dest_mac[MAX_MAC_LEN];

	/****************PTP报文头**********************/
	PTP_MSGHEADER ptp_header;

	/****************PTP报文具体内容****************/
	union
	{
		ANNOUNCE_STRUCT msg_announce;					//announce 消息
		SYNC_STRUCT msg_sync;							//sync 消息
		DELAY_REQ_STRUCT msg_delay_req;					//delay_req 消息
		DELAY_RESP_STRUCT msg_delay_resp;				//delay_resp 消息
		FOLLOW_UP_STRUCT msg_follow_up;					//follow_up 消息
		PDELAY_REQ_STRUCT msg_pdelay_req;				//pdelay_req 消息
		PDELAY_RESP_STRUCT msg_pdelay_resp;				//pdelay_resp 消息
		PTP_MANAGE_STRUCT msg_ptp_manage;				//管理 消息
		PDELAY_FOLLOW_UP_STRUCT msg_pdelay_followup;	//pdelay_follow_up
		SIGNALING_STRUCT msg_signaling;
	}u;

	//报文解析结果
	unsigned int u_result;

	_PTP_INFO_STRUCT()
	{
		memset(c_avtm_epocsec,0,sizeof(c_avtm_epocsec));
		memset(c_src_mac,0,sizeof(c_src_mac));
		memset(c_dest_mac,0,sizeof(c_dest_mac));
		u_result = 0x00000000;
		
	}

}PTP_INFO_STRUCT;

#pragma pack () /*取消指定对齐，恢复缺省对齐*/

#endif /*PTP_STRUCT_DEF_H_INCLUDE*/