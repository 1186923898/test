// �ͻ�-������ ģʽ����ģ��(CS)

#pragma once

#include <stdio.h>
#include <malloc.h>
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <Mstcpip.h>
#include <Iphlpapi.h>
#include <iostream>
using namespace std;

#pragma comment(lib, "Ws2_32")
#pragma comment(lib, "Iphlpapi")

#define ENDMSG "#!End!#"

#define PrintError(str)\
	fprintf(stderr, "%s: %d, %s [%d] \n", str, GetLastError(), __FILE__, __LINE__); 

//��ӡ����IP
//choose == 1ʱ��Ҫ��Ϊѡ��һ��IP������Ĭ�ϵ�0��
in_addr GetIP(bool choose = 0);

/*************************************************************/

class Client
{
private:

	SOCKET sock;
	struct sockaddr_in serverAddress;
	WSADATA wsa_init;

public:

	Client();
	~Client() {};

	//�������ӣ�sock
	void Connect(const char* IP, u_short Port);
	void Connect(in_addr IP, u_short Port);

	//�����ֽ���������ʵ�ʷ��ͳ���
	u_int Send(char* str, u_int len);
	u_int Send(const char* str, u_int len);

	//�����ֽ���������ʵ�ʽ��ճ���
	u_int Receive(char** buffer);

	//�ر�����
	void Close();
};


/*************************************************************/

class Server
{
private:

	SOCKET sock;
	struct sockaddr_in serverAddress, clientAddress;
	socklen_t clientAddressLen;
	WSADATA wsa_init;

	int nTimeout = 5000;//���ó�ʱ5��

	//�������������Ӧ����(LPVOID)(&PS)ָ��
	typedef struct ParamStruct
	{
		LPVOID param = NULL; //����
		void* _this = NULL;
	}PS;

	//���̣߳�����ÿ������
	static DWORD WINAPI Worker(LPVOID param);
	
	//�����ֽ���������ʵ�ʷ��ͳ���
	u_int Send(SOCKET sock, char* str, u_int len);
	u_int Send(SOCKET sock, const char* str, u_int len);

	//�����ֽ���������ʵ�ʽ��ճ���
	u_int Receive(SOCKET sock, char** buffer);


public:
	//������ָ������
	//str:�����ֽ�����len:�����ֽ������ȣ�res:�����ֽ���������ֵ:�����ֽ�������
	u_int (**Works)(char* str, u_int len, char** res); 
	u_char Worknum = 0;

	Server();
	~Server() {};

	//���÷�����
	void SetWork(u_int(**works)(char* str, u_int len, char** res), u_char worknum);

	//�ȴ����ӣ�ʹ��(**Works)������
	void WaitConnect(u_short Port);
};


//�������Ʊ�־
//extern bool bloop = 1;

//�¼��ص�����
BOOL WINAPI EndCtl(DWORD event);

//ʵʱ��ȡ����
int get_key_input(LPDWORD key, DWORD exitkey, BOOL keydown);


