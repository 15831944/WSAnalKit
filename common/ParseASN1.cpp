#pragma execution_character_set("UTF-8")
#include "ParseASN1.h"

int ParseASN1_TLV(const char *c_msg_buf,TLV_STRUCT *p_tlv)
{
	//入口判断
	if (NULL==c_msg_buf || NULL==p_tlv)
	{
		return 0;
	}

	int n_offset=0;
	//解析tag位
	n_offset+=ParseASN1_tag(c_msg_buf,p_tlv);	
	//解析长度
	n_offset+=ParseASN1_len(c_msg_buf+n_offset,p_tlv);
	//解析内容
	n_offset+=ParseASN1_value(c_msg_buf+n_offset,p_tlv);
	return n_offset;
}

int ParseASN1_tag(const char *c_msg_buf,TLV_STRUCT *p_tlv)
{
	//入口判断
	if (NULL==c_msg_buf || NULL==p_tlv)
	{
		return 0;
	}

	memcpy((char *)( &(p_tlv->n_tag) ),c_msg_buf,1);
	return 1;
}

int ParseASN1_len(const char *c_msg_buf,TLV_STRUCT *p_tlv)
{
	//入口判断
	if (NULL==c_msg_buf || NULL==p_tlv)
	{
		return 0;
	}

	int n_temp=0;
	int n_offset=0;
	//先判断是长模式还是短模式
	memcpy((char *)&n_temp,c_msg_buf,1);
	n_offset=1;

	if(n_temp & 0x80)	//长模式
	{
		//去高位
		if ((n_temp &= 0x7F) > 0)	// 定长模式的长形式
		{
			//偏移量向后加指定长度
			p_tlv->n_lenlen =n_temp +1; //描述长度所占用的字节数
			n_offset += n_temp;
			if(n_temp == 2 )		//暂时只处理两字节整数
			{
				int nRet=0;
				memcpy((char *)&n_temp,c_msg_buf+1,1);
				n_temp=256*n_temp;
				memcpy((char *)&nRet,c_msg_buf+2,1);
				n_temp+=nRet;
			}
			else
			{
				memcpy((char *)&n_temp,c_msg_buf+1,1);
			}
		}
		//非定长模式暂不处理
	}
	else
	{
		p_tlv->n_lenlen =1;
	}
	if(n_temp < 0)//防异常处理
		n_temp = 0;
	p_tlv->n_len=n_temp;
	return n_offset;
}

int ParseASN1_value(const char *c_msg_buf,TLV_STRUCT *p_tlv)
{
	//入口判断
	if (NULL==c_msg_buf || NULL==p_tlv)
	{
		return 0;
	}
//	int ntemp = (strlen(c_msg_buf) > p_tlv->n_len)?p_tlv->n_len:strlen(c_msg_buf);//add by yinzhehong 20130325
	memcpy(p_tlv->c_value,c_msg_buf,p_tlv->n_len);

	return p_tlv->n_len;
}

int ParseASN1_TLV_ex(const char *c_msg_buf,TLV_STRUCT_EX *p_tlv)
{
	Rest_TLV_STRUCT_EX(p_tlv);//结构复位

	int nRet = RES_SUCCESS;
	int n_temp = 0;
	char *p_buf_tmp;

	//tag
	p_tlv->p_T = (char *)c_msg_buf;
	p_tlv->nlen_T = 1;

	//length
	p_tlv->p_L = p_tlv->p_T + 1;

	memcpy((char *)&n_temp,p_tlv->p_L,1);
	if(n_temp & 0x80)	//长模式
	{
		//去高位
		if ((n_temp &= 0x7F) > 0)	// 定长模式的长形式
		{
			p_tlv->nlen_L = n_temp +1; //描述长度所占用的字节数
			if(n_temp == 2 )		//暂时只处理两字节整数
			{
				p_buf_tmp = p_tlv->p_L + 1;
				p_tlv->nlen_V = (unsigned char)p_buf_tmp[1] + ( ((unsigned char)p_buf_tmp[0]) << 8 );
/*				int nRet=0;
				memcpy((char *)&n_temp,c_msg_buf+1,1);
				n_temp=256*n_temp;
				memcpy((char *)&nRet,c_msg_buf+2,1);
				n_temp+=nRet;*/
			}
			else
			{
				memcpy((char *)( &(p_tlv->nlen_V) ), p_tlv->p_L+1, 1);
			}
		}
		//非定长模式暂不处理
	}
	else
	{
		p_tlv->nlen_L = 1;
		memcpy((char *)( &(p_tlv->nlen_V) ), p_tlv->p_L, 1);
	}

	//value
	p_tlv->p_V = p_tlv->p_L + p_tlv->nlen_L;

	return nRet;
}

// int Parse_uInt_byTLV(TLV_STRUCT_EX *ptlv, unsigned int &nvalue)
// {
// 	int nRet = RES_SUCCESS;
// 
// 	nvalue = 0;
// 
// 	if(ptlv->nlen_V==1)//一字节
// 		memcpy((char *)&nvalue, ptlv->p_V, 1);
// 	else if (ptlv->nlen_V==2)//二字节
// 	{
// 		nvalue = (unsigned char)ptlv->p_V[1] + ( ((unsigned char)ptlv->p_V[0]) << 8 );
// 	}
// 	else if (ptlv->nlen_V==3)//三字节
// 	{
// 		nvalue = (unsigned char)ptlv->p_V[2] + (((unsigned char)ptlv->p_V[1]) << 8) + (((unsigned char)ptlv->p_V[0]) << 16);
// 	}
// 	else if (ptlv->nlen_V==4)//四字节
// 	{
// 		nvalue = (unsigned char)ptlv->p_V[3] + (((unsigned char)ptlv->p_V[2]) << 8) + (((unsigned char)ptlv->p_V[1]) << 16) + (((unsigned char)ptlv->p_V[0]) << 24);
// 	}
// 	else//多于四字节
// 	{
// 		nRet = RES_FAIL;
// /*		int ntemp = 0;
// 		for (int i=0; i<nvalue_byte-1; i++)
// 		{
// 			ntemp = 0;
// 			memcpy((char *)&ntemp, p_tmp+i, 1);
// 			nRet += pow(256.0,double(nvalue_byte-i-1))*ntemp;
// 		}
// 		ntemp = 0;
// 		memcpy((char *)&ntemp, p_tmp+nvalue_byte-1, 1);
// 		nvalue += ntemp;*/
// 	}
// 
// 	return nRet;
// }
//modified on 20121102 许昌
int Parse_uInt_byTLV(TLV_STRUCT_EX *ptlv, unsigned int &nvalue)
{
	int nRet = RES_SUCCESS;

	nvalue = 0;

	if(ptlv->nlen_V==1)//一字节
		memcpy((unsigned char *)&nvalue, ptlv->p_V, 1);
	else if (ptlv->nlen_V==2)//二字节
	{
		nvalue = (unsigned char)ptlv->p_V[1] + ( ((unsigned char)ptlv->p_V[0]) << 8 );
	}
	else if (ptlv->nlen_V==3)//三字节
	{
		nvalue = (unsigned char)ptlv->p_V[2] + (((unsigned char)ptlv->p_V[1]) << 8) + (((unsigned char)ptlv->p_V[0]) << 16);
	}
	else if (ptlv->nlen_V==4)//四字节
	{
		nvalue = (unsigned char)ptlv->p_V[3] + (((unsigned char)ptlv->p_V[2]) << 8) + (((unsigned char)ptlv->p_V[1]) << 16) + (((unsigned char)ptlv->p_V[0]) << 24);
	}
	else//多于四字节
	{
		int nstep=0;

		nvalue = (unsigned char)ptlv->p_V[ptlv->nlen_V-1];
		for (int i=0; i<ptlv->nlen_V-1; i++)
		{
			nstep = (ptlv->nlen_V -1 - i)*8;//移动的位数
			nvalue += ( (unsigned char)ptlv->p_V[i] << nstep );
		}
	}

	return nRet;
}
/**************重置*******************/
void Rest_TLV_STRUCT_EX(TLV_STRUCT_EX* pTlv_struct_ex)
{
	memset(pTlv_struct_ex,0,sizeof(TLV_STRUCT_EX));
/*	pTlv_struct_ex->p_T = NULL;
	pTlv_struct_ex->nlen_T =0;
	pTlv_struct_ex->p_L = NULL;
	pTlv_struct_ex->nlen_L = 0;
	pTlv_struct_ex->p_V = NULL;
	pTlv_struct_ex->nlen_V = 0;*/
}
