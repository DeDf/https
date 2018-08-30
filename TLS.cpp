
#include <windows.h>

ULONG MakeClientHello(CHAR *pBuf, ULONG size)
{
    CHAR *p = pBuf;
    //
    *p = 0x16;            p+=1;  // HandShake
    *(PSHORT)p = 0x0303;  p+=2;  // TLS Version  tls 1.2 (0x0303)
    CHAR *pTlsRecordLen = p;
                          p+=2;
    *p = 1;               p+=1;  // Client Hello
    CHAR *pHandShakeLen = p;
                          p+=3;
    *(PSHORT)p = 0x0303;  p+=2;  // TLS Version
                          p+=32; // Random
    *p = 0;               p+=1;  // SessionIdLen
    *(PSHORT)p = 0x0200;  p+=2;  // Cipher Suites length
    *(PSHORT)p = 0x2fc0;  p+=2;  // Cipher Suites (USHORT CipherLabel[])
    *(PUSHORT)p = 1;      p+=2;  // Compression Methods (Len:1, value:null) - Compression Methods minimum 1
    *(PUSHORT)p = 0;      p+=2;  // ExtLen

    USHORT len;
    len = (USHORT)(p - (PCHAR)pTlsRecordLen - 2);

    pTlsRecordLen[0] = *((PCHAR)&len+1);
    pTlsRecordLen[1] = *(PCHAR)&len;

    len -= 4;

    pHandShakeLen[0] = 0;
    pHandShakeLen[1] = *((PCHAR)&len+1);
    pHandShakeLen[2] = *(PCHAR)&len;

    return (ULONG)(p - pBuf);
}