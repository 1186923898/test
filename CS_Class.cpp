// 客户-服务器 模式网络模块(CS)

#include "CS_Class.h"

//结束控制标志
bool bloop = 1;

in_addr GetIP(bool choose)
{
	char LocalName[64];
	struct hostent *pHost;
	WSADATA wsa_init;

	//先开启WSA
	if (WSAStartup(MAKEWORD(2, 2), &wsa_init) ||
		LOBYTE(wsa_init.wVersion) != 2 ||
		HIBYTE(wsa_init.wVersion) != 2)
		PrintError("Failed to initialize socket.\n");

	//获取主机名
	if (gethostname((char*)LocalName, sizeof(LocalName) - 1) == SOCKET_ERROR)
	{
		PrintError("can't gethostname");
		exit(-1);
	}
	printf("\n主机名：%s\n\n", LocalName);

	// 获取本地IP地址 
	if ((pHost = gethostbyname((char*)LocalName)) == NULL)
	{
		PrintError("can't gethostbyname");
		exit(-1);
	}
	printf("主机IP:\n");
	for (int i = 0; i < pHost->h_length; i++)
	{
		in_addr ip = *(in_addr *)pHost->h_addr_list[i];
		printf("%d. %d.%d.%d.%d\n", i, ip.S_un.S_un_b.s_b1, ip.S_un.S_un_b.s_b2, ip.S_un.S_un_b.s_b3, ip.S_un.S_un_b.s_b4);
	}

	if (choose == 1)
	{
		printf("\n请选择IP：");
		int k = -1;
		scanf("%d", &k);

		return *(in_addr *)pHost->h_addr_list[k];
	}

	return *(in_addr *)pHost->h_addr_list[0];
}


/*************************************************************/

Client::Client()
{
	//先开启WSA
	if (WSAStartup(MAKEWORD(2, 2), &wsa_init) ||
		LOBYTE(wsa_init.wVersion) != 2 ||
		HIBYTE(wsa_init.wVersion) != 2)
		PrintError("Failed to initialize socket.\n");

	//创建一个socket，IPv4，TCP
	//sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	sock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
	return;
}

void Client::Connect(const char* IP, u_short Port)
{
	unsigned long ip;

	//inet_addr() 与 inet_ntoa()
	if ((ip = inet_addr(IP)) == INADDR_NONE) 
	{
		PrintError("Illegal IP");
		return;
	}

	memset(&serverAddress, 0, sizeof(sockaddr_in));
	serverAddress.sin_family = AF_INET; //IPv4
	serverAddress.sin_addr.S_un.S_addr = ip; //IP
	serverAddress.sin_port = htons(Port); //端口

	//建立和服务器的连接
	if (connect(sock, (sockaddr*)&serverAddress, sizeof(serverAddress)) == SOCKET_ERROR)
	{
		PrintError("Failed to connect");
	}
	else
		printf("Connect to %s:%d\n", IP, Port);

	return;
}

void Client::Connect(in_addr IP, u_short Port)
{
	char* ip = inet_ntoa(IP);
	Connect(ip, Port);
	return;
}

u_int Client::Send(const char* buffer, u_int buflen)
{
	char buf[4]{};
	*(u_int*)buf = htonf(buflen);

	if (send(sock, buf, 4, 0) == SOCKET_ERROR) //字节流长度
	{
		PrintError("Failed to send");
		return 0;
	}

	int i = 0;
	if (buflen > 1024)
	{
		for (i = 0; i < buflen - 1024; i += 1024) //循环发
		{
			if (send(sock, buffer + i, 1024, 0) == SOCKET_ERROR)
			{
				PrintError("Failed to send");
				return i;
			}
		}
		if (send(sock, buffer + i, buflen - i, 0) == SOCKET_ERROR) //最后一点
		{
			PrintError("Failed to send");
		}
	}
	else
	{
		if (send(sock, buffer, buflen, 0) == SOCKET_ERROR) //最后一点
		{
			PrintError("Failed to send");
		}
		i = buflen;
	}

	return i;
}

inline u_int Client::Send(char* buffer, u_int buflen)
{
	return Send((const char*)buffer, buflen);
}

u_int Client::Receive(char** buffer) //接收字节流
{
	u_int bytes = 0;
	char* buf = new char[8];
	if ((recv(sock, buf, 4, 0)) == SOCKET_ERROR)
	{
		PrintError("Failed to receive");
		return 0;
	}

	int i = 0;
	u_int len = ntohf(*(u_int*)buf); //数据长度
	delete[] buf;
	delete [] *buffer;
	*buffer = new char[len + 1];

	if (len > 1024)
	{
		for (i = 0; i < len - 1024; i += 1024)
		{
			if ((bytes += recv(sock, *buffer + i, 1024, 0)) == SOCKET_ERROR)
			{
				PrintError("Failed to receive");
				return 0;
			}
		}
		if ((bytes += recv(sock, *buffer + i, len - i, 0)) == SOCKET_ERROR)
		{
			PrintError("Failed to receive");
			return 0;
		}
	}
	else
	{
		if ((bytes += recv(sock, *buffer, len, 0)) == SOCKET_ERROR)
		{
			PrintError("Failed to receive");
			return 0;
		}
	}

	(*buffer)[bytes] = '\0';
	return bytes;
}

void Client::Close()
{
	Send(ENDMSG, strlen(ENDMSG));
	closesocket(sock);
	return;
}


/*************************************************************/

Server::Server()
{
	//先开启套接字
	if (WSAStartup(MAKEWORD(2, 2), &wsa_init) ||
		LOBYTE(wsa_init.wVersion) != 2 ||
		HIBYTE(wsa_init.wVersion) != 2)
	{
		PrintError("Failed to initialize socket.\n");
		return;
	}

	//创建一个socket，IPv4，TCP
	//sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	sock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
	if (INVALID_SOCKET == sock)
	{
		PrintError("Failed to create a sock");
		return;
	}

	u_long mode = 0; //0:阻塞；1:非阻塞
	ioctlsocket(sock, FIONBIO, &mode);

	//设置接收超时
	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&nTimeout, sizeof(nTimeout)) == SOCKET_ERROR)
		PrintError("Failed to setsockopt");
	
	//设置发送超时
	if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&nTimeout, sizeof(nTimeout)) == SOCKET_ERROR)
		PrintError("Failed to setsockopt");

	return;
}

void Server::SetWork(u_int(**works)(char* str, u_int len, char** res), u_char worknum)
{
	Works = works;
	Worknum = worknum;
	return;
}

void Server::WaitConnect(u_short Port)
{
	HANDLE hThread = NULL;
	DWORD dwThreadID;

	memset(&serverAddress, 0, sizeof(serverAddress));
	serverAddress.sin_family = AF_INET;                 //IPv4
	serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);  //监听本地所有IP地址
	serverAddress.sin_port = htons(Port);				//绑定端口号    

	/*绑定服务器地址结构*/
	if (bind(sock, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) != 0)
	{
		PrintError("Failed to bind");
		return;
	}

	//同一时刻允许向服务器发起链接请求的数量，放入队列等待处理
	
	if (SOCKET_ERROR == listen(sock, 128))
	{
		PrintError("Failed to listen");
		return;
	}

	//创建CtrlHandler处理列程
	if (!SetConsoleCtrlHandler(EndCtl, TRUE))
	{
		PrintError("Failed to install console handler");
		return;
	}

	//要赋值，否则accept()不阻塞！！！
	clientAddressLen = sizeof(SOCKADDR_IN);

	DWORD i;
	while (bloop)
	{
		//从链接队列中，取出一个连接请求
		SOCKET sock2 = accept(sock, (struct sockaddr *)&clientAddress, &clientAddressLen); //阻塞
		if (INVALID_SOCKET != sock2 && sock2 != -1)
		{
			PS fs{ &sock2, (void*)this };

			hThread = CreateThread(NULL, 0, Worker, (LPVOID)(&fs), 0, &dwThreadID); //创建
			if (hThread == NULL)
			{
				PrintError("Failed to create thread");
				return;
			}
			printf("SOCKET %d - Get a connect from %s:%d\n", sock2, inet_ntoa(clientAddress.sin_addr), ntohs(clientAddress.sin_port));

			CloseHandle(hThread);
			Sleep(10);//等一下，足够将参数复制到子线程
		}
	}

	//取消CtrlHandler处理列程
	SetConsoleCtrlHandler(EndCtl, FALSE);

	if (sock != INVALID_SOCKET)
	{
		closesocket(sock);
		sock = INVALID_SOCKET;
	}

	return;
}


u_int Server::Send(SOCKET sock, const char* buffer, u_int buflen)
{
	char buf[4]{};
	*(u_int*)buf = htonf(buflen);

	if (send(sock, buf, 4, 0) == SOCKET_ERROR) //字节流长度
	{
		PrintError("Failed to send");
		return 0;
	}

	int i = 0;
	if (buflen > 1024)
	{
		for (i = 0; i < buflen - 1024; i += 1024) //循环发
		{
			if (send(sock, buffer + i, 1024, 0) == SOCKET_ERROR)
			{
				PrintError("Failed to send");
				return i;
			}
		}
		if (send(sock, buffer + i, buflen - i, 0) == SOCKET_ERROR) //最后一点
		{
			PrintError("Failed to send");
		}
	}
	else
	{
		if (send(sock, buffer, buflen, 0) == SOCKET_ERROR) //最后一点
		{
			PrintError("Failed to send");
		}
		i = buflen;
	}

	return i;
}

inline u_int Server::Send(SOCKET sock, char* buffer, u_int buflen)
{
	return Send(sock, (const char*)buffer, buflen);
}

u_int Server::Receive(SOCKET sock, char** buffer) //接收字节流
{
	u_int bytes = 0;
	char* buf = new char[8];
	if ((recv(sock, buf, 4, 0)) == SOCKET_ERROR)
	{
		PrintError("Failed to receive");
		return 0;
	}

	int i = 0;
	u_int len = ntohf(*(u_int*)buf); //数据长度
	delete[] buf;
	delete[] * buffer;
	*buffer = new char[len + 1];

	if (len > 1024)
	{
		for (i = 0; i < len - 1024; i += 1024)
		{
			if ((bytes += recv(sock, *buffer + i, 1024, 0)) == SOCKET_ERROR)
			{
				PrintError("Failed to receive");
				return 0;
			}
		}
		if ((bytes += recv(sock, *buffer + i, len - i, 0)) == SOCKET_ERROR)
		{
			PrintError("Failed to receive");
			return 0;
		}
	}
	else
	{
		if ((bytes += recv(sock, *buffer, len, 0)) == SOCKET_ERROR)
		{
			PrintError("Failed to receive");
			return 0;
		}
	}

	(*buffer)[bytes] = '\0';
	return bytes;
}

DWORD WINAPI  Server::Worker(LPVOID param)
{
	PS* p = (PS*)param;
	SOCKET sock = *(SOCKET*)p->param;
	Server* _this = (Server*)p->_this;

	while (1)
	{
		char* buf = NULL;
		u_int count = _this->Receive(sock, &buf);

		if (strcmp(ENDMSG, buf) == 0)
			break;

		u_char tag = (u_char)buf[0] - '0'; //工作标识
		if (tag >= _this->Worknum)
		{
			PrintError("Don't have this work");
			return -1;
		}
		u_int(*f)(char* str, u_int len, char** res) = _this->Works[tag]; //取出相应的工作

		char* res = NULL;
		u_int len = f(buf + 1, count - 1, &res); //工作

		if (len != 0)
			_this->Send(sock, res, len);

		delete[] buf;
		delete[] res;
	}

	closesocket(sock);
	printf("SOCKET %d disconnect\n", sock);

	return 0;
}


BOOL WINAPI EndCtl(DWORD event)
{
	DWORD length;

	INPUT_RECORD record;

	switch (event)
	{
	case CTRL_C_EVENT:
	case CTRL_CLOSE_EVENT:
	case CTRL_BREAK_EVENT:
	case CTRL_LOGOFF_EVENT:
	case CTRL_SHUTDOWN_EVENT:

		fprintf(stdout, "System is exiting...\n");

		ZeroMemory(&record, sizeof(INPUT_RECORD));
		record.EventType = KEY_EVENT;
		record.Event.KeyEvent.bKeyDown = 1;
		record.Event.KeyEvent.wRepeatCount = 1;
		record.Event.KeyEvent.wVirtualKeyCode = VK_ESCAPE;

		// 模拟用户按下ESC按键。
		WriteConsoleInput(GetStdHandle(STD_INPUT_HANDLE), &record, 1, &length);

		Sleep(10);

		// 指示所有工作线程停止工作。
		if (bloop)
			bloop = 0; //。。。线程已经阻塞的，结束不了

		break;

	default:
		// unknown type--better pass it on.
		return FALSE;
	}

	return TRUE;
}

int get_key_input(LPDWORD key, DWORD exitkey, BOOL keydown)
{
	DWORD
		length;

	INPUT_RECORD
		record;

	*key = -1;
	// 读取一组控制台事件记录。
	if (!ReadConsoleInput(GetStdHandle(STD_INPUT_HANDLE), &record, 1, &length) ||
		!length)
	{
		PrintError("Failed to get user key events");
		Sleep(100);
		// 读取键盘输入失败，返回TRUE进入下一个读取动作。
		return 1;
	}

	// 判断是否为键盘事件。
	if (record.EventType != KEY_EVENT ||
		!(keydown ? record.Event.KeyEvent.bKeyDown : !record.Event.KeyEvent.bKeyDown))
		return 1;

	// 返回当前KEY值。
	*key = record.Event.KeyEvent.wVirtualKeyCode;

	// 如果是指定的退出按键或ESC则返回FALSE。
	return !(*key == exitkey || *key == VK_ESCAPE);
}



