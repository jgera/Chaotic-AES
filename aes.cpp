#include "aes.h"

AES::AES()
{
    for (int i = 0; i < 256; i++)
        sbox[i] = i;
}

//返回S盒子P号元素的值
int AES::GetBoxValue(int p) const
{
    if (p < 0 || p > 255)
        return -1;
        
    return sbox[p];
}

//字节替代
void AES::SubBytes(unsigned char matrix[4][4], const unsigned char sbox[256])
{
    for (int i = 0; i < 4; i++)
        for (int k = 0; k < 4; k++)
    matrix[i][k] = sbox[matrix[i][k]];
}

//行位移
void AES::ShiftRows(unsigned char matrix[4][4])
{
    unsigned char tmp[4];

    for (int i = 1; i < 4; i++)
    {
        for (int k = 0; k < 4; k++)
            tmp[k] = matrix[i][(k + i) % 4];
            
        for (int k = 0; k < 4; k++)
            matrix[i][k] = tmp[k];
    }
}

//行位移(反方向)
void AES::InvShiftRows(unsigned char matrix[4][4])
{
    unsigned char tmp[4];

    for (int i = 1; i < 4; i++)
    {
        for (int k = 0; k < 4; k++)
            tmp[k] = matrix[i][(k - i + 4) % 4];
            
        for (int k = 0; k < 4; k++)
            matrix[i][k] = tmp[k];
    }
}

//定义的点乘
unsigned char AES::HexMultiply(const unsigned char &a, const unsigned char &b)
{
    unsigned char ans = 0,
                  byte_c[4] = {b};

    for (int i = 1; i < 4; i++)
    {
        byte_c[i] = byte_c[i-1] << 1;
        if (byte_c[i - 1] & 0x80)
            byte_c[i] ^= 0x1b;
    }

    for (int i = 0; i < 4; i++)
        if( (a >> i) & 0x01)
            ans ^= byte_c[i];

    return ans;
}

//列混合
void AES::MixColumns(unsigned char matrix[4][4])
{
    unsigned char tmp[4];

    for (int i = 0; i < 4; i++)
    {
        for (int k = 0; k < 4; k++)
            tmp[k] = matrix[k][i];

        for (int k = 0; k < 4; k++)
            matrix[k][i] = HexMultiply(0x2, tmp[k])
                        ^ HexMultiply(0x3, tmp[(k + 1) % 4])
                        ^ HexMultiply(0x1, tmp[(k + 2) % 4])
                        ^ HexMultiply(0x1, tmp[(k + 3) % 4]);
    }
}
 
//列混合的逆操作
void AES::InvMixColumns(unsigned char matrix[4][4])
{
    unsigned char tmp[4];

    for (int i = 0; i < 4; i++)
    {
        for (int k = 0; k < 4; k++)
            tmp[k] = matrix[k][i];

        for (int k = 0; k < 4; k++)
            matrix[k][i] = HexMultiply(0xe, tmp[k])
                        ^ HexMultiply(0xb, tmp[(k + 1) % 4])
                        ^ HexMultiply(0xd, tmp[(k + 2) % 4])
                        ^ HexMultiply(0x9, tmp[(k + 3) % 4]);
    }
}

//与16位密钥位运算，列优先
void AES::AddRoundKey(unsigned char matrix[4][4], const unsigned char key[16])
{
   for (int i = 0; i < 4; i++)
        for (int k = 0; k < 4; k++)
            matrix[k][i] ^= key[i * 4 + k];
}

