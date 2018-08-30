//Client.cpp
#include <stdio.h>
#include <winsock2.h>

#pragma comment(lib,"ws2_32.lib")

ULONG MakeClientHello(CHAR *pBuf, ULONG size);

BOOL Write(char* chFileName, char *buf, DWORD len)
{
    HANDLE pFile;
    char *tmpBuf;
    DWORD dwBytesWrite,dwBytesToWrite;

    pFile = CreateFileA(chFileName,
        GENERIC_WRITE,          
        0,
        NULL,               
        CREATE_ALWAYS,        //���Ǵ����ļ�
        FILE_ATTRIBUTE_NORMAL, 
        NULL);

    if ( pFile == INVALID_HANDLE_VALUE)
    {
        printf("create file error!\n");
        CloseHandle(pFile);
        return FALSE;
    }

    dwBytesToWrite = len;
    dwBytesWrite = 0;

    tmpBuf = buf;

    do{                                       //ѭ��д�ļ���ȷ���������ļ���д��  

        WriteFile(pFile,tmpBuf,dwBytesToWrite,&dwBytesWrite,NULL);

        dwBytesToWrite -= dwBytesWrite;
        tmpBuf += dwBytesWrite;

    } while (dwBytesToWrite > 0);

    CloseHandle(pFile);

    return TRUE;
}

int main(int argc, char* argv[])
{
    char *pchIP = "61.135.169.121";  // www.baidu.com
    short port  = 443;

    //��ʼ���׽���DLL
    WSADATA wsa;
    if(WSAStartup(MAKEWORD(2,2),&wsa)!=0)
    {
        printf("�׽��ֳ�ʼ��ʧ��!\n");
        exit(-1);
    }

    //�����׽���
    SOCKET s = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if(s==INVALID_SOCKET)
    {
        printf("�����׽���ʧ��!\n");
        exit(-1);
    }

    //�����ͷ�����������
    struct sockaddr_in serverAddress;
    memset(&serverAddress,0,sizeof(sockaddr_in));
    serverAddress.sin_family=AF_INET;
    serverAddress.sin_addr.s_addr = inet_addr(pchIP);
    serverAddress.sin_port = htons(port);
    
    printf("Connecting to %s:%d......\n", pchIP, port);
    if(connect(s,(sockaddr*)&serverAddress,sizeof(serverAddress))==SOCKET_ERROR)
    {
        printf("��������ʧ��!\n");
        exit(-1);
    }

    char ClientHello[64];
    ULONG SendLen = MakeClientHello(ClientHello, sizeof(ClientHello));

    // SendClientHello
    if(send(s,ClientHello,SendLen,0)==SOCKET_ERROR)
    {
        printf("��������ʧ��!\n");
        exit(-1);
    }

    char ServerHello[100];
    int RecvLen1=recv(s,ServerHello,sizeof(ServerHello),0);
    if(RecvLen1==SOCKET_ERROR)
    {
        printf("��������ʧ��!\n");
        exit(-1);
    }

    char Certificate[4096];
    int RecvLen2=recv(s,Certificate,sizeof(Certificate),0);
    if(RecvLen2==SOCKET_ERROR)
    {
        printf("��������ʧ��!\n");
        exit(-1);
    }

    UCHAR *p = (UCHAR *)(Certificate + 0xC);
    ULONG CerLen1 = p[0]<<16 | p[1]<<8 | p[2];
    p += 3;
    Write("d:\\1.cer", (char*)p, CerLen1);

    p += CerLen1;
    ULONG CerLen2 = p[0]<<16 | p[1]<<8 | p[2];
    p += 3;
    Write("d:\\2.cer", (char*)p, CerLen2);

    char ServerKeyExchange[512];
    int RecvLen3=recv(s,ServerKeyExchange,sizeof(ServerKeyExchange),0);
    if(RecvLen3==SOCKET_ERROR)
    {
        printf("��������ʧ��!\n");
        exit(-1);
    }

    char ServerHelloDone[20];
    int RecvLen4=recv(s,ServerHelloDone,sizeof(ServerHelloDone),0);
    if(RecvLen4==SOCKET_ERROR)
    {
        printf("��������ʧ��!\n");
        exit(-1);
    }

    printf("Message from %s: %s\n", inet_ntoa(serverAddress.sin_addr), ServerHello);

    //�����׽���ռ�õ���Դ
    WSACleanup();
    return 0;
}