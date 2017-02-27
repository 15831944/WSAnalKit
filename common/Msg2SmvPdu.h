#ifndef MSG_2_SMV_PDU_H
#define MSG_2_SMV_PDU_H

#include "AT_STRUCT.h"
#include "ParseASN1.h"

//#ifdef __cplusplus
//extern "C" {
//#endif
//
	int CreateAsduInfo(SMV_INFO_STRUCT *p_info_struct);
	int MSIS_ASDU_Sum(const char *c_msg_buf,SMV_INFO_STRUCT *p_info_struct);
	int MSIS_Eth_Pdu(const char *c_msg_buf,SMV_INFO_STRUCT *p_info_struct);
	int MSIS_ASDU(const char *c_msg_buf,ASDU_INFO_STRUCT *p_asdu,bool b_parseData=false);
	int ParseASDU_Total_Len(const char *c_msg_buf,int &n_tag,int &n_len);
	int ParseASDU_Atr(const char *c_msg_buf,ASDU_INFO_STRUCT *p_asdu);
	int ParseASDU_DataSet(const char *c_msg_buf,ASDU_INFO_STRUCT *p_asdu,int n_dataset_len);
	int GetValueOffset(TLV_STRUCT *p_tlv);
	int ConvertValue_Int(TLV_STRUCT &tlv);
	int CreateSMVDataStruct(ASDU_INFO_STRUCT *p_asdu,int n_data_num);
	int Hex2Binary(char *cHex);
	int my_itoa(int val, char* buf, int radix);
	unsigned int ConvertValue_uInt(TLV_STRUCT &tlv);
	int Buf2Int32(const char* c_msg_buf);

//#ifdef __cplusplus
//};
//#endif

#endif//MSG_2_SMV_PDU_H