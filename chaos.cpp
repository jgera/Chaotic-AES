#include <cmath>
#include "aes.h"
#include "chaos.h"

//初始化构造，将所有参数设为0 
ChaosEncrypt::ChaosEncrypt()
{
    x_sbox = 0;
    b_sbox = 0;
    x_aes  = 0;
    x_xor  = 0;
    b_xor  = 0;
}

//设置密钥
void ChaosEncrypt::SetKey(double _x_sbox, double _b_sbox, double _x_aes, double _x_xor, double _b_xor)
{
    x_sbox = _x_sbox;
    b_sbox = _b_sbox;
    x_aes  = _x_aes;
    x_xor  = _x_xor;
    b_xor  = _b_xor;
}

bool ChaosEncrypt::Encrypt(char *text, int length)
{
    if (!CheckBeforeEncrypt(length))
        return false;

    BuildBox();                 //生成S盒子
    EncryptAES(text, length);   //基于混沌的AES加密
    EncryptXor(text, length);   //混沌流加密
    return true;
}

bool ChaosEncrypt::Decrypt(char *text, int length)
{
    if (!CheckBeforeEncrypt(length))
        return false;

    BuildBox();                 //生成S盒子
    InvBox();                   //逆置S盒子
    DecryptXor(text, length);   //混沌流解密
    DecryptAES(text, length);   //基于混沌的AES解密
    return true;
}

//在加密前检测所有参数适合符合范围
bool ChaosEncrypt::CheckBeforeEncrypt(int n)
{
    if (x_sbox <= 0 || x_sbox >= 1 || b_sbox <= 0 || b_sbox >= 1 ||
            x_aes <= -1 || x_aes >= 1 || x_xor <= 0 || x_xor >= 1 ||
            b_xor < 3.7 || b_xor > 4)
        return false;

    if (n % 16 != 0)
        return false;

    return true;
}


//检验AES加密的轮密钥分布，返回字节平均值
double ChaosEncrypt::GetAesAvg(int length) const
{
    int group_count = length / 16; 
    double  key_value, 
            total = 0,
            x = x_aes;

    for (int i = 0; i < LOGI_FIRST_COUNT; i++)
        x = 1 - x * x * 2;

    for (int i = 0; i < group_count; i++)
    {

        for (int j = 0; j < 11; j++)                    //生成11组轮密钥
            for (int k = 0; k < 16; k++)
            {
                for (int m = 0; m < LOGI_EVERY_COUNT; m++)
                {
                    x = 1 - x * x * 2;
                }
                key_value = acos((-1) * x) / MY_PI * 256;
                total    += (unsigned char)(key_value);
            }
    }
    return total / (length * 11);
}
    

//检验流加密的序列分布，返回比特平均值，必须对密文调用
double ChaosEncrypt::GetXorAvg(const char *text, int n) const
{ 
    int last_matrix = 0;
    double x = x_xor,
           count = 0;

    for (int j = 0; j < LOGI_FIRST_COUNT; j++)
        x = x * (1 - x) * b_xor;
    
    for (int i = 0; i < n; i++)
    {
        for (int k = 0; k < 8; k++)
        {
            for (int j = 0; j < LOGI_EVERY_COUNT; j++)
                x = x * (1 - x) * b_xor;
            count += (x > 0.5);
        }

        last_matrix += (unsigned char)(text[i]);
        
        if (i % 16 == 15)
        {
            last_matrix %= LOGI_GROUP_MOD;
            for (int j = 0; j < last_matrix; j++)
                x = x * (1 - x) * b_xor;
            last_matrix = 0;
        }
    }

    return double(count / 8.0 / n);
}

//根据PLCM生成s盒
void ChaosEncrypt::BuildBox()
{
    unsigned char newbox[256]; 
    int    t, 
           n = 256;
    double x = x_sbox;

    for (int i = 0; i < 256; i++)                                 //初始化S盒子
        sbox[i] = i;

    for (int i = 0; i < SBOX_FIRST_COUNT; i++)                    //初始迭代
        if (x <= b_sbox)
            x = x / b_sbox;
        else
            x = (1 - x) / (1 - b_sbox);

    while (n > 0)
    { 
        for (int i = 0; i < SBOX_EVERY_COUNT; i++)               //每回合连续迭代
            if (x <= b_sbox)
                x = x / b_sbox;
            else
                x = (1 - x) / (1 - b_sbox);
        t = n * x;
        newbox[256 - n] = sbox[t];
        n--;
        for (int j = t; j < n; j++)
            sbox[j] = sbox[j + 1];
    }

    for (int i = 0; i < 256; i++)
        sbox[i] = newbox[i];
}

void ChaosEncrypt::InvBox()
{
    unsigned char newbox[256];

    for (int i = 0; i < 256; i++)
        newbox[sbox[i]] = i;

    for (int i = 0; i < 256; i++)
        sbox[i] = newbox[i];
}

//序列加密，与Logistic进行异或，每16个字节后根据密文额外迭代
void ChaosEncrypt::EncryptXor(char *text, int n)
{
    int last_matrix = 0;                    //记录上16个密文的字节和
    double x = x_xor;

    for (int j = 0; j < LOGI_FIRST_COUNT; j++)
        x = x * (1 - x) * b_xor;

    for (int i = 0; i < n; i++)
    {
       int p = 1;
       unsigned key = 0;
       for (int k = 0; k < 8; k++)         //8位1组，即仍按字节运算
        {
            for (int j = 0; j < LOGI_EVERY_COUNT; j++)
                x = x * (1 - x) * b_xor;
            key += (x > 0.5) * p;
            p *= 2;
        }

        text[i] ^= key;
        last_matrix += (unsigned char)(text[i]);
        
        if (i % 16 == 15)
        {
            last_matrix %= LOGI_GROUP_MOD;
            for (int j = 0; j < last_matrix; j++)
                x = x * (1 - x) * b_xor;
            last_matrix = 0;
        }
    }
}

//序列解密，与Logistic进行异或，每16个字节后根据密文额外迭代
void ChaosEncrypt::DecryptXor(char *text, int n)
{
    int last_matrix = 0;                    //记录上16个密文的字节和
    double x = x_xor;

    for (int j = 0; j < LOGI_FIRST_COUNT; j++)
        x = x * (1 - x) * b_xor;

    for (int i = 0; i < n; i++)
    {
       int p = 1;
       unsigned key = 0;
       for (int k = 0; k < 8; k++)         //8位1组，即仍按字节运算
        {
            for (int j = 0; j < LOGI_EVERY_COUNT; j++)
                x = x * (1 - x) * b_xor;
            key += (x > 0.5) * p;
            p *= 2;
        }

        last_matrix += (unsigned char)(text[i]);     //这两句与加密的顺序相反
        text[i] ^= key;
        
        if (i % 16 == 15)
        {
            last_matrix %= LOGI_GROUP_MOD;
            for (int j = 0; j < last_matrix; j++)
                x = x * (1 - x) * b_xor;
            last_matrix = 0;
        }
    }
}



void ChaosEncrypt::EncryptAES(char *text, int length) 
{
    unsigned char matrix[4][4],             //明/密文矩阵
                  key[11][16];              //轮密钥
    int group_count = length / 16;          //将明文分为length/16组
    double  key_value, 
            x = x_aes;  

    for (int i = 0; i < LOGI_FIRST_COUNT; i++)
        x = 1 - x * x * 2;

    for (int i = 0; i < group_count; i++)
    {
        for (int k = 0; k < 16; k++)                    //取16位明文放入矩阵,类型由char转为unsigned char
            matrix[k / 4][k % 4] = text[i * 16 + k];

        for (int j = 0; j < 11; j++)                    //生成11组轮密钥
            for (int k = 0; k < 16; k++)
            {
                for (int m = 0; m < LOGI_EVERY_COUNT; m++)
                {
                    x = 1 - x * x * 2;
                }
                key_value = acos((-1) * x) / MY_PI * 256;
                key[j][k] = (unsigned char)(key_value);
            }

        AddRoundKey(matrix, key[0]);
       
        for (int k = 1; k < 10; k++)
        {
            SubBytes(matrix, sbox);        
            ShiftRows(matrix);
            MixColumns(matrix);
            AddRoundKey(matrix, key[k]);
        }
      
        SubBytes(matrix, sbox);        
        ShiftRows(matrix);
        AddRoundKey(matrix, key[10]);

        for (int k = 0; k < 16; k++)
            text[i * 16 + k] = matrix[k / 4][k % 4];   //将密文矩阵放回字符串
    }
}

void ChaosEncrypt::DecryptAES(char *text, int length)
{
    unsigned char matrix[4][4],             //明/密文矩阵
                  key[11][16];              //轮密钥
    int group_count = length / 16;          //将明文分为length/16组
    double  key_value, 
            x = x_aes;  

    for (int i = 0; i < LOGI_FIRST_COUNT; i++)
        x = 1 - x * x * 2;

    for (int i = 0; i < group_count; i++)
    {
        for (int k = 0; k < 16; k++)                    //取16位明文放入矩阵,类型由char转为unsigned char
            matrix[k / 4][k % 4] = text[i * 16 + k];

        for (int j = 0; j < 11; j++)                    //生成11组轮密钥
            for (int k = 0; k < 16; k++)
            {
                for (int m = 0; m < LOGI_EVERY_COUNT; m++)
                {
                    x = 1 - x * x * 2;
                }
                key_value = acos((-1) * x) / MY_PI * 256;
                key[j][k] = (unsigned char)(key_value);
            }

        AddRoundKey(matrix, key[10]);
        InvShiftRows(matrix);
        SubBytes(matrix, sbox);

        for (int k = 9; k > 0; k--)
        {
            AddRoundKey(matrix, key[k]);
            InvMixColumns(matrix);
            InvShiftRows(matrix);
            SubBytes(matrix, sbox);
        }
      
        AddRoundKey(matrix, key[0]);
        
        for (int k = 0; k < 16; k++)
            text[i * 16 + k] = matrix[k / 4][k % 4];   //将明文矩阵放回字符串
    }
}

