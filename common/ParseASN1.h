#ifndef PARSE_ASN1_H
#define  PARSE_ASN1_H

//#include "memory"
#include "define_scan.h"

#define	MAX_DATA_LEN_TLV 1500


typedef struct TLV_STRUCT{

	int n_tag;
	int n_len;
	int n_lenlen;//描述字节长度的长度
	char c_value[MAX_DATA_LEN_TLV];
	TLV_STRUCT(){
		n_tag=0;
		n_len=0;
		n_lenlen=0;
		memset(c_value,0,sizeof(c_value));
	}

}_TLV_STRUCT;

typedef struct _TLV_STRUCT_EX
{
	char *p_T;
	int nlen_T;
	char *p_L;
	int nlen_L;
	char *p_V;
	int nlen_V;

}TLV_STRUCT_EX;

int ParseASN1_tag(const char *c_msg_buf,TLV_STRUCT *p_tlv);
int ParseASN1_len(const char *c_msg_buf,TLV_STRUCT *p_tlv);
int ParseASN1_value(const char *c_msg_buf,TLV_STRUCT *p_tlv);
int ParseASN1_TLV(const char *c_msg_buf,TLV_STRUCT *p_tlv);

int ParseASN1_TLV_ex(const char *c_msg_buf,TLV_STRUCT_EX *p_tlv);
int Parse_uInt_byTLV(TLV_STRUCT_EX *ptlv, unsigned int &nvalue);
/************值复位*******************/
void Rest_TLV_STRUCT_EX(TLV_STRUCT_EX* pTlv_struct_ex);


#endif// PARSE_ASN1_H
