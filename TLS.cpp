
#include <windows.h>

#define u8  unsigned char
#define u16 unsigned short
#define u32 unsigned int

ULONG MakeClientHello(UCHAR *pBuf, ULONG size)
{
    u8 *p = pBuf;
    //
    *p = 0x16;              p+=1;  // HandShake
    *(u16*)p = 0x0303;      p+=2;  // TLS Version  tls 1.2 (0x0303)
    u8 *pTlsRecordLen = p;  p+=2;  // TlsRecordLen : 2Bytes
    *p = 1;                 p+=1;  // Client Hello
    u8 *pHandShakeLen = p;  p+=3;  // HandShakeLen : 3Bytes
    *(u16*)p = 0x0303;      p+=2;  // TLS Version
                            p+=32; // Random       : 32Bytes
    *p = 0;                 p+=1;  // SessionIdLen
    *(u16*)p = 0x0200;      p+=2;  // Cipher Suites length
    *(u16*)p = 0x2fc0;      p+=2;  // Cipher Suites (USHORT CipherLabel[])
    *p = 1;                 p+=1;  // Compression Methods Len:1 (minimum 1)
    *p = 0;                 p+=1;  // Compression Methods value:null
    *(u16*)p = 0;           p+=2;  // ExtLen       : 2Bytes

    u16 TlsRecordLen = (u16)(p - (pTlsRecordLen + 2));
    //
    *(u16*)pTlsRecordLen = _byteswap_ushort(TlsRecordLen);

    u16 HandShakeLen = (u16)(p - (pHandShakeLen + 3));
    //
    pHandShakeLen[0] = 0;
    *(u16*)(&pHandShakeLen[1]) = _byteswap_ushort(HandShakeLen);

    return (ULONG)(p - pBuf);
}