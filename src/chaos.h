#ifndef CHAOS_H
#define CHAOS_H

#include "aes.h"

const double MY_PI = 3.14159265359;          //PI的值，精度会影响混沌生成的AES密钥
const int    SBOX_FIRST_COUNT = 50;          //生成S盒的初始迭代次数
const int    SBOX_EVERY_COUNT = 32;          //生成S盒的每次迭代次数，不得小于30
const int 	 LOGI_FIRST_COUNT = 100;         //Logistic流加密的初始迭代次数
const int    LOGI_EVERY_COUNT = 8;           //Logistic流加密的每次迭代次数
const int    LOGI_GROUP_MOD   = 64;          //Logistic流加密的自同步除数

class ChaosEncrypt:public AES
{
    public:
        
        ChaosEncrypt();            
        bool    Encrypt(char *, int);                             //加密
        bool    Decrypt(char *, int);                             //解密
        void    SetKey(double, double, double, double, double);   //设置密钥
        double  GetAesAvg(int) const;                             //检验AES加密的轮密钥分布，返回字节平均值
        double  GetXorAvg(const char *, int) const;               //检验流加密的序列分布，返回比特平均值，必须对密文调用
        
    protected:

        void    BuildBox();                     //生成S盒子
        void    InvBox();                       //逆置S盒子(解密时必须先生成，再逆置)
        void    EncryptXor(char *, int);        //混沌流加密
        void    DecryptXor(char *, int);        //混沌流解密(自同步流加密，因此加解密算法不能用同一个函数)
        void    EncryptAES(char *, int);        //混沌AES加密
        void    DecryptAES(char *, int);        //混沌AES解密
        bool    CheckBeforeEncrypt(int);        //检验5个参数的取值，以及明文/密文的长度是否为16的倍数

    private:
        
        double  x_sbox;          //生成s盒的第一个参数
        double  b_sbox;          //生成s盒的第二个参数
        double  x_aes;           //生成AES密钥的参数
        double  x_xor;           //混沌流加密的第一个参数
        double  b_xor;           //混沌流加密的第二个参数

};

#endif
