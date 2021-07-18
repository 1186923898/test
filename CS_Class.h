// 客户-服务器 模式网络模块(CS)

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

//打印本地IP
//choose == 1时需要人为选择一个IP；否则默认第0个
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

	//建立连接，sock
	void Connect(const char* IP, u_short Port);
	void Connect(in_addr IP, u_short Port);

	//发送字节流，返回实际发送长度
	u_int Send(char* str, u_int len);
	u_int Send(const char* str, u_int len);

	//接收字节流，返回实际接收长度
	u_int Receive(char** buffer);

	//关闭连接
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

	int nTimeout = 5000;//设置超时5秒

	//函数的输入参数应该是(LPVOID)(&PS)指针
	typedef struct ParamStruct
	{
		LPVOID param = NULL; //参数
		void* _this = NULL;
	}PS;

	//子线程，处理每个连接
	static DWORD WINAPI Worker(LPVOID param);
	
	//发送字节流，返回实际发送长度
	u_int Send(SOCKET sock, char* str, u_int len);
	u_int Send(SOCKET sock, const char* str, u_int len);

	//接收字节流，返回实际接收长度
	u_int Receive(SOCKET sock, char** buffer);


public:
	//服务函数指针数组
	//str:输入字节流，len:输入字节流长度，res:返回字节流，返回值:返回字节流长度
	u_int (**Works)(char* str, u_int len, char** res); 
	u_char Worknum = 0;

	Server();
	~Server() {};

	//设置服务函数
	void SetWork(u_int(**works)(char* str, u_int len, char** res), u_char worknum);

	//等待连接，使用(**Works)来服务
	void WaitConnect(u_short Port);
};


//结束控制标志
//extern bool bloop = 1;

//事件回调函数
BOOL WINAPI EndCtl(DWORD event);

//实时读取键盘
int get_key_input(LPDWORD key, DWORD exitkey, BOOL keydown);


