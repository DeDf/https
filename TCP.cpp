
#include <stdio.h>
#include <winsock2.h>

#pragma comment(lib,"ws2_32.lib")

ULONG MakeClientHello(CHAR *pBuf, ULONG size);

BOOL Write(char *chFileName, UCHAR *buf, DWORD len)
{
    BOOL bRet = FALSE;

    HANDLE pFile = CreateFileA(chFileName,
        GENERIC_WRITE,          
        0,
        NULL,               
        CREATE_ALWAYS,        //总是创建文件
        FILE_ATTRIBUTE_NORMAL, 
        NULL);

    if ( pFile != INVALID_HANDLE_VALUE)
    {
        DWORD dwBytesToWrite = len;
        DWORD dwBytesWrite = 0;

        UCHAR *p = buf;
        do  //循环写文件，确保完整的文件被写入
        {
            bRet = WriteFile(pFile,p,dwBytesToWrite,&dwBytesWrite,NULL);
            if (bRet)
            {
                dwBytesToWrite -= dwBytesWrite;
                p += dwBytesWrite;
            }
            else
            {
                break;
            }

        } while (dwBytesToWrite > 0);

        CloseHandle(pFile);
    }

    return bRet;
}

int main(int argc, char* argv[])
{
    char *pchIP = "14.215.177.38";  // www.baidu.com
    //char *pchIP = "61.135.169.121";  // www.baidu.com
    short port  = 443;

    //初始化套接字
    WSADATA wsa;
    if(WSAStartup(MAKEWORD(2,2),&wsa))
    {
        printf("套接字初始化失败!\n");
        return -1;
    }

    //创建套接字
    SOCKET s = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if(s==INVALID_SOCKET)
    {
        printf("创建套接字失败!\n");
        return -1;
    }

    //建立和服务器的连接
    struct sockaddr_in serverAddress;
    memset(&serverAddress,0,sizeof(sockaddr_in));
    serverAddress.sin_family=AF_INET;
    serverAddress.sin_addr.s_addr = inet_addr(pchIP);
    serverAddress.sin_port = htons(port);
    
    printf("Connecting to %s:%d......\n", pchIP, port);
    if(connect(s,(sockaddr*)&serverAddress,sizeof(serverAddress))==SOCKET_ERROR)
    {
        printf("建立连接失败!\n");
        return -1;
    }

    char ClientHello[64];
    ULONG SendLen = MakeClientHello(ClientHello, sizeof(ClientHello));

    // SendClientHello
    if(send(s,ClientHello,SendLen,0)==SOCKET_ERROR)
    {
        printf("发送数据失败!\n");
        return -1;
    }

    UCHAR *p = NULL;
    ULONG nOverBytes = 0;

    UCHAR ServerHello[100];
    UCHAR Certificate[0x1000];

    int RecvLen1=recv(s,(char*)ServerHello,sizeof(ServerHello),0);
    if(RecvLen1==SOCKET_ERROR)
    {
        printf("接收数据失败!\n");
        return -1;
    }
    p = ServerHello + 3;
    USHORT ServerHelloDataLen = _byteswap_ushort(*(PUSHORT)p);
    USHORT ServerHelloLen = 3 + 2 + ServerHelloDataLen;
    if (ServerHelloLen != RecvLen1)
    {
        if (ServerHelloLen > RecvLen1)
        {
            printf("ServerHello Format Error!\n");
            goto L_Exit;
        }
        else
        {
            p = ServerHello + ServerHelloLen;
            nOverBytes = RecvLen1 - ServerHelloLen;
            memcpy(Certificate, p, nOverBytes);
        }
    }
    
    int RecvLen2=recv(s, (char*)Certificate + nOverBytes, sizeof(Certificate) - nOverBytes, 0);
    if(RecvLen2==SOCKET_ERROR)
    {
        printf("接收数据失败!\n");
        return -1;
    }
    p = Certificate + 3;
    USHORT CertificateLen = _byteswap_ushort(*(PUSHORT)p);

    p = Certificate + 0xC;
    ULONG CerLen1 = p[0]<<16 | p[1]<<8 | p[2];
    p += 3;
    Write("d:\\1.cer", p, CerLen1);
    p += CerLen1;

    ULONG CerLen2 = p[0]<<16 | p[1]<<8 | p[2];
    p += 3;
    Write("d:\\2.cer", p, CerLen2);
    p += CerLen2;
    //
    printf("CertificateLen : %d, CerLen1 : %d, CerLen2 : %d\n", CertificateLen, CerLen1, CerLen2);

    char ServerKeyExchange[512];
    int RecvLen3=recv(s,(char*)ServerKeyExchange,sizeof(ServerKeyExchange),0);
    if(RecvLen3==SOCKET_ERROR)
    {
        printf("接收数据失败!\n");
        return -1;
    }

    char ServerHelloDone[20];
    int RecvLen4=recv(s,ServerHelloDone,sizeof(ServerHelloDone),0);
    if(RecvLen4==SOCKET_ERROR)
    {
        printf("接收数据失败!\n");
        return -1;
    }

    printf("Message from %s: %s\n", inet_ntoa(serverAddress.sin_addr), ServerHello);

L_Exit:
    getchar();
    //清理套接字占用的资源
    WSACleanup();
    return 0;
}