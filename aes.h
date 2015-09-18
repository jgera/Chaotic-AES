#ifndef AES_H
#define AES_H

class AES
{

    public:

        //构造函数
        AES();

        //返回S盒子某一位的值
        int             GetBoxValue(int) const; 
    
    protected:

        //自定义点积
        unsigned char   HexMultiply(const unsigned char &a, const unsigned char &b);

        //字节替代
        void            SubBytes(unsigned char matrix[4][4], const unsigned char sbox[256]);

        //行位移
        void            ShiftRows(unsigned char matrix[4][4]);

        //行位移的逆操作
        void            InvShiftRows(unsigned char matrix[4][4]);

        //列混合
        void            MixColumns(unsigned char matrix[4][4]);

        //列混合的逆操作
        void            InvMixColumns(unsigned char matrix[4][4]);

        //与16位密钥位运算
        void            AddRoundKey(unsigned char matrix[4][4], const unsigned char key[16]);

        //S盒子，构造默认初值为序列0-255
        unsigned char sbox[256]; 

};

#endif
