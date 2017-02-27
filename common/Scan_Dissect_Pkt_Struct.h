#if !defined(_SCAN_DISSECT_STRUCT_H)
#define _SCAN_DISSECT_STRUCT_H
/**
 * @brief       数据包解析接口
 * @use			wirshark数据包解析封装接口结构定义
 * @author      尹浙洪
 * @version     ver1.0
 * @date        2012/10/17
 */
/* field types 各个节点类型*/
enum xj_pkt_field_type_enum {
	PKT_FT_NONE,	/* used for text labels with no value */
	PKT_FT_PROTOCOL,
	PKT_FT_BOOLEAN,	/* TRUE and FALSE come from <glib.h> */
	PKT_FT_UINT8,
	PKT_FT_UINT16,
	PKT_FT_UINT24,	/* really a UINT32, but displayed as 3 hex-digits if FD_HEX*/
	PKT_FT_UINT32,
	PKT_FT_UINT64,
	PKT_FT_INT8,
	PKT_FT_INT16,
	PKT_FT_INT24,	/* same as for UINT24 */
	PKT_FT_INT32,
	PKT_FT_INT64,
	PKT_FT_FLOAT,
	PKT_FT_DOUBLE,
	PKT_FT_ABSOLUTE_TIME,
	PKT_FT_RELATIVE_TIME,
	PKT_FT_STRING,
	PKT_FT_STRINGZ,	/* for use with proto_tree_add_item() */
	PKT_FT_UINT_STRING,	/* for use with proto_tree_add_item() */
	/*FT_UCS2_LE, */    /* Unicode, 2 byte, Little Endian     */
	PKT_FT_ETHER,
	PKT_FT_BYTES,
	PKT_FT_UINT_BYTES,
	PKT_FT_IPv4,
	PKT_FT_IPv6,
	PKT_FT_IPXNET,
	PKT_FT_FRAMENUM,	/* a UINT32, but if selected lets you go to frame with that number */
	PKT_FT_PCRE,	/* a compiled Perl-Compatible Regular Expression object */
	PKT_FT_GUID,	/* GUID, UUID */
	PKT_FT_OID,		/* OBJECT IDENTIFIER */
	PKT_FT_EUI64,
	PKT_FT_NUM_TYPES /* last item number plus one */
};
/* ETHER_TYPE 各个节点类型*/
enum xj_pkt_ether_type_enum//同步const_scan.h::enum ETHER_TYPE::ETHER_TYPE_DROP等
{
    PKT_ETHER_TYPE_UNKOWN           =0,
	PKT_ETHER_TYPE_IEC61850_MMS     =1,
	PKT_ETHER_TYPE_IEC61850_GOOSE   =2,
	PKT_ETHER_TYPE_IEC61850_SMV     =3,
	PKT_ETHER_TYPE_IEC61850_SMV_91  =4,
	PKT_ETHER_TYPE_IEC61850_PTP_1588=5,
	PKT_ETHER_TYPE_ARP              =6,
	PKT_ETHER_TYPE_IP               =7,
	PKT_ETHER_TYPE_TCP              =8,
	PKT_ETHER_TYPE_UDP              =9,
	PKT_ETHER_TYPE_COTP             =13,
	PKT_ETHER_TYPE_TCP_FIN			    =14,//释放TCP链接 
	PKT_ETHER_TYPE_TCP_SYN_REQ		    =15,//请求
	PKT_ETHER_TYPE_TCP_SYN_RESP	        =16,//接受链接
	PKT_ETHER_TYPE_TCP_RST			    =17,//重置链接
	PKT_PKT_ETHER_TYPE_TCP_PSH			=18,//有应用数据，接收方需要尽快处理
	PKT_ETHER_TYPE_TCP_ACK			    =19,//保持连接
	PKT_ETHER_TYPE_TCP_URG			    =20,//紧急数据
	PKT_ETHER_TYPE_TPKT                 =21,//add by yinzhehong 20130321
	PKT_ETHER_TYPE_DROP                     =22,//add by guohuawen 20151010 //链路层丢弃报文
};
typedef struct _xj_proto_node
{
	struct _xj_proto_node  *parent_node;       //父节点
	struct _xj_proto_node  *pchildlist;        //子节点根指针
	int                    childlist_size;     //子节点个数
	int				       start_pos;         //在源数据中的起始位置
	int				       length;			  //< 数据占用长度
	void*				   pkt_usrview;       //供外部应用使用
	char		           *node_name;        //节点名称
	char                   *node_name_detail; //节点名称详细描述
	char                   *node_desc;        //节点描述
	int                     errortype;        //节点错误类型 
	xj_pkt_ether_type_enum node_type;         //节点类型 0:正常节点 1:变位节点 2:异常节点        
} XJ_PROTO_NODE;
/**************转化后的数据包*******************/
typedef struct _xj_dissect_pkt
{
	xj_pkt_ether_type_enum ether_type;   //报文类型
	int          pkt_length;             //报文长度
	void*        pkt_data;               //原始数据帧对应指针
	int          utc_s;                  //utc秒
	int          utc_ms;                 //utc毫秒
	XJ_PROTO_NODE * pprototreelist;      //协议树
	int           prototreelist_size;    //协议树层次
	int           prototreelist_app_seq; //有效应用层的层号
	char         mac_src[18];            //发送端MAC地址
	char         mac_dst[18];            //接收端MAC地址
	char         ip_src[18];             //发送端IP地址
	char         ip_dst[18];             //接收端IP地址
	int          port_src;               //发送端端口
	int          port_dst;               //接收端端口
	
}XJ_DISSECT_PKT;

#endif
