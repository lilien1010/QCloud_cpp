 
#include "HMAC_SHA1.h"
#include <time.h>
#include <iostream>

using namespace std; 

int qc_app_sign(unsigned int appid, const char* secret_id, const char* secret_key, unsigned int expired, const char* userid, char*& sign);
bool Encode(const unsigned char* pIn, unsigned long uInLen, string& strOut);

void main(){
    unsigned int appid      = 201212;
    const char * secret_id = "ABIDkXYplGJ7x24fNedKK6ELiaBdnrhRL7Dp";
    const char * secret_key = "BGD4nliGfnYCfqPhns4ZdmRuxgNTIRCb";
    unsigned int expired    = time(NULL)+200;
    const char * userid     = "222";
    char * sign             = NULL; 
     

    qc_app_sign(appid,  secret_id,  secret_key,   expired,  userid, sign);


//     char * goodStr = "L9r18rk5VJEcOT9Fftmi9Y3ld6JhPTIwMTIxMiZrPUFCSURrWFlwbEdKN3gyNGZOZWRLSzZFTGlhQmRucmhSTDdEcCZlPTE0MzM0ODc1MzcmdD0xNDMzNDg3MzM3JnI9NDEmdT0yMjImZj0=";
//     int cmp = strcmp(sign,goodStr);
//     if(cmp!=0){
//          cout<<cmp<<"["<<strlen(sign)<<"]"<<"BAD:"<<sign<<endl;
//     }else
//     {
//                  cout<<"==========OK==================="<<endl;
//     }

   cout<<"sign="<<sign<<endl;
     

}

/*
 * @func    服务端签名函数,APP级别,有效期expired内使用
 * @param   appid       腾讯云APPID 
 * @param   secret_id   Qcloud上申请到的密钥id
 * @param   secret_key  Qcloud上申请到的密钥key
 * @param   expired     过期时间(绝对时间)
 * @param   userid      业务没有账号体系填NULL
 * @param   sign        输出函数,计算得到的签名值,函数内malloc,业务使用完需要自行释放free
 * @return  0成功 <0失败
*/
int qc_app_sign(unsigned int appid, const char* secret_id, const char* secret_key, unsigned int expired, const char* userid, char*& sign){
    
    if(secret_id==NULL || appid==0 || secret_key==NULL || userid==NULL){
        return 0;
    }
    
    int nowt =  time(NULL);   // 1433481781;//
    int rdm =   rand();  //322;//
    char plain_text[256] = {0};
    BYTE  bin[20] ={0};
   
    sprintf_s(plain_text,sizeof(plain_text),"a=%d&k=%s&e=%d&t=%d&r=%d&u=%s&f=",appid,secret_id,expired,nowt,rdm,userid);
    int   pLen  =   strlen(plain_text);
    //cout<<plain_text<<endl;

    
    CHMAC_SHA1 HMAC_SHA1 ;
    HMAC_SHA1.HMAC_SHA1((BYTE*)plain_text, pLen, (BYTE *)secret_key,strlen(secret_key), bin) ;
    
   
    char  text[256] = {0}; 
    memcpy(text,bin,sizeof(bin));
    memcpy((char*)text+sizeof(bin),plain_text,pLen); 

    string strOut="";
    Encode((const unsigned char * )text,sizeof(bin)+pLen,strOut);
    
    //分配内存，输出数据，业务层要注意free
    int len =   strOut.length()+1;
    sign    =   (char*)malloc(len);
    memset(sign,0,len);
    memcpy(sign,strOut.c_str(),len); 
    return 1;
}



const char *g_pCodes = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
const unsigned char g_pMap[256] =
{
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255,  62, 255, 255, 255,  63,
    52,  53,  54,  55,  56,  57,  58,  59,  60,  61, 255, 255,
    255, 254, 255, 255, 255,   0,   1,   2,   3,   4,   5,   6,
    7,   8,   9,  10,  11,  12,  13,  14,  15,  16,  17,  18,
    19,  20,  21,  22,  23,  24,  25, 255, 255, 255, 255, 255,
    255,  26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,
    37,  38,  39,  40,  41,  42,  43,  44,  45,  46,  47,  48,
    49,  50,  51, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255
}; 

bool Encode(const unsigned char* pIn, unsigned long uInLen, string& strOut)
{
    unsigned long i, len2, leven;
    strOut = "";

    //ASSERT((pIn != NULL) && (uInLen != 0) && (pOut != NULL) && (uOutLen != NULL));

    len2 = ((uInLen + 2) / 3) << 2;
    //if((*uOutLen) < (len2 + 1)) return false;

    //p = pOut;
    leven = 3 * (uInLen / 3);
    for(i = 0; i < leven; i += 3)
    {
        strOut += g_pCodes[pIn[0] >> 2];
        strOut += g_pCodes[((pIn[0] & 3) << 4) + (pIn[1] >> 4)];
        strOut += g_pCodes[((pIn[1] & 0xf) << 2) + (pIn[2] >> 6)];
        strOut += g_pCodes[pIn[2] & 0x3f];
        pIn += 3;
    }

    if (i < uInLen)
    {
        unsigned char a = pIn[0];
        unsigned char b = ((i + 1) < uInLen) ? pIn[1] : 0;
        unsigned char c = 0;

        strOut += g_pCodes[a >> 2];
        strOut += g_pCodes[((a & 3) << 4) + (b >> 4)];
        strOut += ((i + 1) < uInLen) ? g_pCodes[((b & 0xf) << 2) + (c >> 6)] : '=';
        strOut += '=';
    }

    return true;
}

bool Decode(const string& strIn, unsigned char* pOut, unsigned long* uOutLen)
{
    unsigned long t, x, y, z;
    unsigned char c;
    unsigned long g = 3;

    for(x = y = z = t = 0; x < strIn.length(); x++)
    {
        c = g_pMap[(int)strIn[x]];
        if(c == 255) continue;
        if(c == 254) { c = 0; g--; }

        t = (t << 6) | c;

        if(++y == 4)
        {
            if((z + g) > *uOutLen) { return false; } // Buffer overflow
            pOut[z++] = (unsigned char)((t>>16)&255);
            if(g > 1) pOut[z++] = (unsigned char)((t>>8)&255);
            if(g > 2) pOut[z++] = (unsigned char)(t&255);
            y = t = 0;
        }
    }

    *uOutLen = z;

    return true;
}