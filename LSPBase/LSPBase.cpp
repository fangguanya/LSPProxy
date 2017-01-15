#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <ws2spi.h>  
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <errno.h>  
#include <fstream>
#pragma   comment(lib,"Ws2_32.lib")  

// !< 与LSPProxy中定义的GUID一致, 在便利LSP协议处理层的时候有用.
GUID ProviderGuid = { 0xd3c21122, 0x85e1, 0x48f3,{ 0x9a,0xb6,0x23,0xd9,0x0c,0x73,0x77,0xef } };

LPWSAPROTOCOL_INFOW  ProtoInfo = NULL;
WSPPROC_TABLE        NextProcTable;
DWORD                ProtoInfoSize = 0;
int                  TotalProtos = 0;
// 输出函数  
int PutDbgStr(LPCTSTR lpFmt, ...)
{
	TCHAR  Msg[1024];
	int  len = wvsprintf(Msg, lpFmt, va_list(1 + &lpFmt));
	OutputDebugString(Msg);
	return len;
}
// 获取各种值  
BOOL GetLSP()
{
	int    errorcode;
	ProtoInfo = NULL;
	ProtoInfoSize = 0;
	TotalProtos = 0;
	if (WSCEnumProtocols(NULL, ProtoInfo, &ProtoInfoSize, &errorcode) == SOCKET_ERROR)
	{
		if (errorcode != WSAENOBUFS)
		{
			PutDbgStr(L"First WSCEnumProtocols Error!");
			return FALSE;
		}
	}
	if ((ProtoInfo = (LPWSAPROTOCOL_INFOW)GlobalAlloc(GPTR, ProtoInfoSize)) == NULL)
	{
		PutDbgStr(L"GlobalAlloc Error!");
		return FALSE;
	}
	if ((TotalProtos = WSCEnumProtocols(NULL, ProtoInfo, &ProtoInfoSize, &errorcode)) == SOCKET_ERROR)
	{
		PutDbgStr(L"Second WSCEnumProtocols Error!");
		return FALSE;
	}
	return TRUE;
}
// 释放内存  
void FreeLSP()
{
	GlobalFree(ProtoInfo);
}
/********************************* 改写WSP函数，只有WSPConnect被改写成调用ProxyConnect函数，其它的直接调用下层WSP函数 ****************************************/


// --- SOCKS5代理部分 ---
// 连接socks5代理  
int ProxyConnect(SOCKET s, const struct sockaddr *name, int namelen)
{
	int rc = 0;
	// 这里应该先保存下socket的阻塞/非阻塞类型，在最后面跟据这里的值将它还原，但是不知道怎样获取此类型  
	// 修改socket为阻塞类型  
	if (rc = WSAEventSelect(s, 0, NULL))//这一个可以不用执行  
	{
		PutDbgStr(L"Error %d : WSAEventSelect Failure!", WSAGetLastError());
	}
	else
	{
		PutDbgStr(L"Message : WSAEventSelect successfully!");
	}
	unsigned long nonBlock = 0;
	if (rc = ioctlsocket(s, FIONBIO, &nonBlock))// 这个真正修改为阻塞类型  
	{
		PutDbgStr(L"Error %d : Set Blocking Failure!", WSAGetLastError());
	}
	else
	{
		PutDbgStr(L"Message : Set Blocking successfully!");
	}
	//连接代理服务器  
	sockaddr_in serveraddr;
	memset(&serveraddr, 0, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;

	// !< TODO:添加配置
	inet_pton(AF_INET, "127.0.0.1", (void*)&serveraddr.sin_addr);
	serveraddr.sin_port = htons(10801); // 端口号  

	WSABUF DataBuf;
	char buffer[4];
	memset(buffer, 0, sizeof(buffer));
	DataBuf.len = 4;
	DataBuf.buf = buffer;
	int err = 0;
	if ((rc = NextProcTable.lpWSPConnect(s, (struct sockaddr *)&serveraddr, sizeof(struct sockaddr), &DataBuf, NULL, NULL, NULL, &err)) != 0)
	{
		PutDbgStr(L"Error %d : attempting to connect to SOCKS server!", err);
		return rc;
	}
	else
	{
		PutDbgStr(L"Message : Connect to SOCKS server successfully!");
	}
	//发送请求来协商版本和认证方法  
	//VER   NMETHODS    METHODS  
	//1     1           1 to 255  
	char verstring[257];
	verstring[0] = 0x05;    //VER (1 Byte)  
	verstring[1] = 0x01;    //NMETHODS (1 Byte)  
	verstring[2] = 0x00;    //METHODS (allow 1 - 255 bytes, current 1 byte)  
	if ((rc = send(s, verstring, 3, 0)) < 0)
	{
		PutDbgStr(L"Error %d : attempting to send SOCKS method negotiation!", WSAGetLastError());
		return rc;
	}
	else
	{
		PutDbgStr(L"Message : send SOCKS method negotiation successfully!");
	}
	//接收代理服务器返回信息  
	//VER   METHOD  
	//1     1  
	/*当前定义的方法有：
	· X’00’ 不需要认证
	· X’01’ GSSAPI
	· X’02’ 用户名/密码
	· X’03’ -- X’7F’ 由IANA分配
	· X’80’ -- X’FE’ 为私人方法所保留的
	· X’FF’ 没有可以接受的方法*/
	if ((rc = recv(s, verstring, 257, 0)) < 0)
	{
		PutDbgStr(L"Error %d : attempting to receive SOCKS method negotiation reply!", WSAGetLastError());
		return rc;
	}
	else
	{
		PutDbgStr(L"Message : receive SOCKS method negotiation reply successfully!");
	}
	if (rc < 2)//返回2字节  
	{
		PutDbgStr(L"Error : Short reply from SOCKS server!");
		rc = ECONNREFUSED;
		return rc;
	}
	else
	{
		PutDbgStr(L"Message : reply from SOCKS server larger than 2");
	}
	// 代理服务器选择方法  
	// 判断我们的方法是否可行  
	if (verstring[1] == 0xff)
	{
		PutDbgStr(L"Error : SOCKS server refused authentication methods!");
		rc = ECONNREFUSED;
		return rc;
	}
	else if (verstring[1] == 0x02)// 方法2 ： 用户名/密码  
	{
		//另外处理  
		PutDbgStr(L"Error : SOCKS server need username/password!");
	}
	else if (verstring[1] == 0x00)// 方法0： 不需要认证  
	{
		//发送SOCKS请求  
		//VER   CMD RSV     ATYP    DST.ADDR    DST.PROT  
		//1     1   X'00'   1       Variable    2  
		/* VER 协议版本: X’05’
		· CMD
		· CONNECT：X’01’
		· BIND：X’02’
		· UDP ASSOCIATE：X’03’
		· RSV 保留
		· ATYP 后面的地址类型
		· IPV4：X’01’
		· 域名：X’03’
		· IPV6：X’04’'
		· DST.ADDR 目的地址
		· DST.PORT 以网络字节顺序出现的端口号
		SOCKS服务器会根据源地址和目的地址来分析请求，然后根据请求类型返回一个或多个应答。*/
		struct sockaddr_in sin;
		sin = *(const struct sockaddr_in *)name;
		char buf[10];
		buf[0] = 0x05; // 版本 SOCKS5  
		buf[1] = 0x01; // 连接请求  
		buf[2] = 0x00; // 保留字段  
		buf[3] = 0x01; // IPV4  
		memcpy(&buf[4], &sin.sin_addr.S_un.S_addr, 4);
		memcpy(&buf[8], &sin.sin_port, 2);
		//发送  
		if ((rc = send(s, buf, 10, 0)) < 0)
		{
			PutDbgStr(L"Error %d : attempting to send SOCKS connect command!", WSAGetLastError());
			return rc;
		}
		else
		{
			PutDbgStr(L"Message : send SOCKS connect command successfully!");
		}
		//应答  
		//VER   REP RSV     ATYP    BND.ADDR    BND.PORT  
		//1     1   X'00'   1       Variable    2  
		/*VER 协议版本: X’05’
		· REP 应答字段:
		· X’00’ 成功
		· X’01’ 普通的SOCKS服务器请求失败
		· X’02’ 现有的规则不允许的连接
		· X’03’ 网络不可达
		· X’04’ 主机不可达
		· X’05’ 连接被拒
		· X’06’ TTL超时
		· X’07’ 不支持的命令
		· X’08’ 不支持的地址类型
		· X’09’ – X’FF’ 未定义
		· RSV 保留
		· ATYP 后面的地址类型
		· IPV4：X’01’
		· 域名：X’03’
		· IPV6：X’04’
		· BND.ADDR 服务器绑定的地址
		· BND.PORT 以网络字节顺序表示的服务器绑定的段口
		标识为RSV的字段必须设为X’00’。*/
		if ((rc = recv(s, buf, 10, 0)) < 0) // 用了天翼的网络之后，这里就接收不到返回信息了，不解  
		{
			PutDbgStr(L"Error %d : attempting to receive SOCKS connection reply!", WSAGetLastError());
			rc = ECONNREFUSED;
			return rc;
		}
		else
		{
			PutDbgStr(L"Message : receive SOCKS connection reply successfully!");
		}
		if (rc < 10)
		{
			PutDbgStr(L"Message : Short reply from SOCKS server!");
			return rc;
		}
		else
		{
			PutDbgStr(L"Message : reply from SOCKS larger than 10!");
		}
		//连接不成功  
		if (buf[0] != 0x05)
		{
			PutDbgStr(L"Message : Socks V5 not supported!");
			return ECONNABORTED;
		}
		else
		{
			PutDbgStr(L"Message : Socks V5 is supported!");
		}
		if (buf[1] != 0x00)
		{
			PutDbgStr(L"Message : SOCKS connect failed!");
			switch ((int)buf[1])
			{
			case 1:
				PutDbgStr(L"General SOCKS server failure!");
				return ECONNABORTED;
			case 2:
				PutDbgStr(L"Connection denied by rule!");
				return ECONNABORTED;
			case 3:
				PutDbgStr(L"Network unreachable!");
				return ENETUNREACH;
			case 4:
				PutDbgStr(L"Host unreachable!");
				return EHOSTUNREACH;
			case 5:
				PutDbgStr(L"Connection refused!");
				return ECONNREFUSED;
			case 6:
				PutDbgStr(L"TTL Expired!");
				return ETIMEDOUT;
			case 7:
				PutDbgStr(L"Command not supported!");
				return ECONNABORTED;
			case 8:
				PutDbgStr(L"Address type not supported!");
				return ECONNABORTED;
			default:
				PutDbgStr(L"Unknown error!");
				return ECONNABORTED;
			}
		}
		else
		{
			PutDbgStr(L"Message : SOCKS connect Success!");
		}
	}
	else
	{
		PutDbgStr(L"Error : Method not supported! verstring[1]=%d", verstring[1]);
	}
	//修改socket为非阻塞类型  
	nonBlock = 1;
	if (rc = ioctlsocket(s, FIONBIO, &nonBlock))
	{
		PutDbgStr(L"Error %d : Set Non-Blocking Failure!", WSAGetLastError());
		return rc;
	}
	else
	{
		PutDbgStr(L"Message : Set Non-Blocking Successful!");
	}
	PutDbgStr(L"Message : Success!");
	return 0;
}

int ProxySendTo(SOCKET s, const struct sockaddr *name, int namelen, short port)
{
	int rc = 0;
	// 这里应该先保存下socket的阻塞/非阻塞类型，在最后面跟据这里的值将它还原，但是不知道怎样获取此类型  
	// 修改socket为阻塞类型  
	if (rc = WSAEventSelect(s, 0, NULL))//这一个可以不用执行  
	{
		PutDbgStr(L"Error %d : WSAEventSelect-UDP Failure!", WSAGetLastError());
	}
	else
	{
		PutDbgStr(L"Message : WSAEventSelect-UDP successfully!");
	}
	unsigned long nonBlock = 0;
	if (rc = ioctlsocket(s, FIONBIO, &nonBlock))// 这个真正修改为阻塞类型  
	{
		PutDbgStr(L"Error %d : Set Blocking-UDP Failure!", WSAGetLastError());
	}
	else
	{
		PutDbgStr(L"Message : Set Blocking-UDP successfully!");
	}
	//连接代理服务器  
	sockaddr_in serveraddr;
	memset(&serveraddr, 0, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;

	// !< TODO:添加配置
	inet_pton(AF_INET, "127.0.0.1", (void*)&serveraddr.sin_addr);
	serveraddr.sin_port = htons(10801); // 端口号  

	WSABUF DataBuf;
	char buffer[4];
	memset(buffer, 0, sizeof(buffer));
	DataBuf.len = 4;
	DataBuf.buf = buffer;
	int err = 0;
	if ((rc = NextProcTable.lpWSPConnect(s, (struct sockaddr *)&serveraddr, sizeof(struct sockaddr), &DataBuf, NULL, NULL, NULL, &err)) != 0)
	{
		PutDbgStr(L"Error %d : attempting to connect to SOCKS-UDP server!", err);
		return rc;
	}
	else
	{
		PutDbgStr(L"Message : Connect to SOCKS-UDP server successfully!");
	}
	// !< 发送UDP穿透请求
	char abyUdpAssociateBuf[1024] = { 0 };
	const int SOCK5_PROXY_VERSION = 0x05;
	const int CMD_UDP_ASSOCIATE = 0x03;
	const int RESERVED = 0;
	const int IP_TYPE = 0x01;
	abyUdpAssociateBuf[0] = SOCK5_PROXY_VERSION;
	abyUdpAssociateBuf[1] = CMD_UDP_ASSOCIATE;
	abyUdpAssociateBuf[2] = RESERVED;
	abyUdpAssociateBuf[3] = IP_TYPE;
	int nAddr = inet_addr("127.0.0.1");
	short nPort = htons((short)port);
	memcpy(&abyUdpAssociateBuf[4], &nAddr, 4);
	memcpy(&abyUdpAssociateBuf[8], &nPort, 2);
	if ((rc = send(s, abyUdpAssociateBuf, 10, 0)) < 0)
	{
		PutDbgStr(L"Error %d : attempting to send SOCKS-UDP method negotiation!", WSAGetLastError());
		return rc;
	}
	else
	{
		PutDbgStr(L"Message : send SOCKS-UDP method negotiation successfully!");
	}
	//接收代理服务器返回信息  
	//VER   METHOD  
	//1     1  
	/*当前定义的方法有：
	· X’00’ 不需要认证
	· X’01’ GSSAPI
	· X’02’ 用户名/密码
	· X’03’ -- X’7F’ 由IANA分配
	· X’80’ -- X’FE’ 为私人方法所保留的
	· X’FF’ 没有可以接受的方法*/
	if ((rc = recv(s, verstring, 257, 0)) < 0)
	{
		PutDbgStr(L"Error %d : attempting to receive SOCKS-UDP method negotiation reply!", WSAGetLastError());
		return rc;
	}
	else
	{
		PutDbgStr(L"Message : receive SOCKS-UDP method negotiation reply successfully!");
	}
	if (rc < 2)//返回2字节  
	{
		PutDbgStr(L"Error : Short reply from SOCKS-UDP server!");
		rc = ECONNREFUSED;
		return rc;
	}
	else
	{
		PutDbgStr(L"Message : reply from SOCKS-UDP server larger than 2");
	}
	// 代理服务器选择方法  
	// 判断我们的方法是否可行  
	if (verstring[1] == 0xff)
	{
		PutDbgStr(L"Error : SOCKS-UDP server refused authentication methods!");
		rc = ECONNREFUSED;
		return rc;
	}
	else if (verstring[1] == 0x02)// 方法2 ： 用户名/密码  
	{
		//另外处理  
		PutDbgStr(L"Error : SOCKS-UDP server need username/password!");
	}
	else if (verstring[1] == 0x00)// 方法0： 不需要认证  
	{
		//发送SOCKS请求  
		//VER   CMD RSV     ATYP    DST.ADDR    DST.PROT  
		//1     1   X'00'   1       Variable    2  
		/* VER 协议版本: X’05’
		· CMD
		· CONNECT：X’01’
		· BIND：X’02’
		· UDP ASSOCIATE：X’03’
		· RSV 保留
		· ATYP 后面的地址类型
		· IPV4：X’01’
		· 域名：X’03’
		· IPV6：X’04’'
		· DST.ADDR 目的地址
		· DST.PORT 以网络字节顺序出现的端口号
		SOCKS服务器会根据源地址和目的地址来分析请求，然后根据请求类型返回一个或多个应答。*/
		struct sockaddr_in sin;
		sin = *(const struct sockaddr_in *)name;
		char buf[10];
		buf[0] = 0x05; // 版本 SOCKS5  
		buf[1] = 0x01; // 连接请求  
		buf[2] = 0x00; // 保留字段  
		buf[3] = 0x01; // IPV4  
		memcpy(&buf[4], &sin.sin_addr.S_un.S_addr, 4);
		memcpy(&buf[8], &sin.sin_port, 2);
		//发送  
		if ((rc = send(s, buf, 10, 0)) < 0)
		{
			PutDbgStr(L"Error %d : attempting to send SOCKS-UDP connect command!", WSAGetLastError());
			return rc;
		}
		else
		{
			PutDbgStr(L"Message : send SOCKS-UDP connect command successfully!");
		}
		//应答  
		//VER   REP RSV     ATYP    BND.ADDR    BND.PORT  
		//1     1   X'00'   1       Variable    2  
		/*VER 协议版本: X’05’
		· REP 应答字段:
		· X’00’ 成功
		· X’01’ 普通的SOCKS服务器请求失败
		· X’02’ 现有的规则不允许的连接
		· X’03’ 网络不可达
		· X’04’ 主机不可达
		· X’05’ 连接被拒
		· X’06’ TTL超时
		· X’07’ 不支持的命令
		· X’08’ 不支持的地址类型
		· X’09’ – X’FF’ 未定义
		· RSV 保留
		· ATYP 后面的地址类型
		· IPV4：X’01’
		· 域名：X’03’
		· IPV6：X’04’
		· BND.ADDR 服务器绑定的地址
		· BND.PORT 以网络字节顺序表示的服务器绑定的段口
		标识为RSV的字段必须设为X’00’。*/
		if ((rc = recv(s, buf, 10, 0)) < 0) // 用了天翼的网络之后，这里就接收不到返回信息了，不解  
		{
			PutDbgStr(L"Error %d : attempting to receive SOCKS-UDP connection reply!", WSAGetLastError());
			rc = ECONNREFUSED;
			return rc;
		}
		else
		{
			PutDbgStr(L"Message : receive SOCKS-UDP connection reply successfully!");
		}
		if (rc < 10)
		{
			PutDbgStr(L"Message : Short reply from SOCKS-UDP server!");
			return rc;
		}
		else
		{
			PutDbgStr(L"Message : reply from SOCKS-UDP larger than 10!");
		}
		//连接不成功  
		if (buf[0] != 0x05)
		{
			PutDbgStr(L"Message : SOCKS-UDP V5 not supported!");
			return ECONNABORTED;
		}
		else
		{
			PutDbgStr(L"Message : SOCKS-UDP V5 is supported!");
		}
		if (buf[1] != 0x00)
		{
			PutDbgStr(L"Message : SOCKS-UDP connect failed!");
			switch ((int)buf[1])
			{
			case 1:
				PutDbgStr(L"General SOCKS-UDP server failure!");
				return ECONNABORTED;
			case 2:
				PutDbgStr(L"SOCKS-UDP Connection denied by rule!");
				return ECONNABORTED;
			case 3:
				PutDbgStr(L"SOCKS-UDP Network unreachable!");
				return ENETUNREACH;
			case 4:
				PutDbgStr(L"SOCKS-UDP Host unreachable!");
				return EHOSTUNREACH;
			case 5:
				PutDbgStr(L"SOCKS-UDP Connection refused!");
				return ECONNREFUSED;
			case 6:
				PutDbgStr(L"SOCKS-UDP TTL Expired!");
				return ETIMEDOUT;
			case 7:
				PutDbgStr(L"SOCKS-UDP Command not supported!");
				return ECONNABORTED;
			case 8:
				PutDbgStr(L"SOCKS-UDP Address type not supported!");
				return ECONNABORTED;
			default:
				PutDbgStr(L"SOCKS-UDP Unknown error!");
				return ECONNABORTED;
			}
		}
		else
		{
			PutDbgStr(L"Message : SOCKS-UDP connect Success!");
		}
	}
	else
	{
		PutDbgStr(L"Error : SOCKS-UDP Method not supported! verstring[1]=%d", verstring[1]);
	}
	//修改socket为非阻塞类型  
	nonBlock = 1;
	if (rc = ioctlsocket(s, FIONBIO, &nonBlock))
	{
		PutDbgStr(L"Error %d : SOCKS-UDP Set Non-Blocking Failure!", WSAGetLastError());
		return rc;
	}
	else
	{
		PutDbgStr(L"Message : SOCKS-UDP Set Non-Blocking Successful!");
	}
	PutDbgStr(L"Message : SOCKS-UDP Success!");
	return 0;
}
//WSPConnect  
int WSPAPI WSPConnect(
	SOCKET s,
	const struct sockaddr *name,
	int namelen,
	LPWSABUF lpCallerData,
	LPWSABUF lpCalleeData,
	LPQOS lpSQOS,
	LPQOS lpGQOS,
	LPINT lpErrno)
{
	// !< TODO:添加过滤规则等处理
	TCHAR FullPath[MAX_PATH] = { 0x00 };
	TCHAR ProcessName[_MAX_FNAME] = { 0x00 };
	TCHAR drive[_MAX_DRIVE] = { 0x00 };
	TCHAR dir[_MAX_DIR] = { 0x00 };
	TCHAR ext[_MAX_EXT] = { 0x00 };
	GetModuleFileName(NULL, FullPath, MAX_PATH);
	_wsplitpath_s(FullPath, drive, dir, ProcessName, ext);
	PutDbgStr(L"WSPConnect Process:%ws", ProcessName);

	// !< 1.程序过滤
	if (wcscmp(ProcessName, L"chrome") != 0)
	{
		return NextProcTable.lpWSPConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS, lpErrno);
	}

	// !< 2.目标地址过滤
	char remoteip[64];
	inet_ntop(AF_INET, (void*)name, remoteip, ARRAYSIZE(remoteip));
	if (strcmp(remoteip, "127.0.0.1") == 0)
	{
	}

	return ProxyConnect(s, name, namelen);
}

//WSPSendTo  
int WINAPI WSPSendTo(
	__in   SOCKET s,
	__in   LPWSABUF lpBuffers,
	__in   DWORD dwBufferCount,
	__out  LPDWORD lpNumberOfBytesSent,
	__in   DWORD dwFlags,
	__in   const struct sockaddr *lpTo,
	__in   int iTolen,
	__in   LPWSAOVERLAPPED lpOverlapped,
	__in   LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
	__in   LPWSATHREADID lpThreadId,
	__out  LPINT lpErrno
)
{
	// !< TODO:添加过滤规则等处理
	TCHAR FullPath[MAX_PATH] = { 0x00 };
	TCHAR ProcessName[_MAX_FNAME] = { 0x00 };
	TCHAR drive[_MAX_DRIVE] = { 0x00 };
	TCHAR dir[_MAX_DIR] = { 0x00 };
	TCHAR ext[_MAX_EXT] = { 0x00 };
	GetModuleFileName(NULL, FullPath, MAX_PATH);
	_wsplitpath_s(FullPath, drive, dir, ProcessName, ext);
	PutDbgStr(L"WSPSendTo Process:%ws", ProcessName);

	// !< 1.程序过滤
	if (wcscmp(ProcessName, L"chrome") != 0)
	{
		return NextProcTable.lpWSPSendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iTolen, lpOverlapped, lpCompletionRoutine, lpThreadId, lpErrno);
	}

	// !< 2.目标地址过滤
	char remoteip[64];
	inet_ntop(AF_INET, (void*)lpTo, remoteip, ARRAYSIZE(remoteip));
	if (strcmp(remoteip, "127.0.0.1") == 0)
	{
	}

	return socksProxy(s, lpTo, iTolen);
}

//WSPSocket  
SOCKET WINAPI WSPSocket(
	__in   int af,
	__in   int type,
	__in   int protocol,
	__in   LPWSAPROTOCOL_INFO lpProtocolInfo,
	__in   GROUP g,
	DWORD dwFlags,
	__out  LPINT lpErrno
)
{
	return NextProcTable.lpWSPSocket(af, type, protocol, lpProtocolInfo, g, dwFlags, lpErrno);
}
//WSPBind  
int WINAPI WSPBind(
	__in   SOCKET s,
	__in   const struct sockaddr *name,
	__in   int namelen,
	__out  LPINT lpErrno
)
{
	return NextProcTable.lpWSPBind(s, name, namelen, lpErrno);
}
//WSPSend  
int WINAPI WSPSend(
	__in   SOCKET s,
	__in   LPWSABUF lpBuffers,
	__in   DWORD dwBufferCount,
	__out  LPDWORD lpNumberOfBytesSent,
	__in   DWORD dwFlags,
	__in   LPWSAOVERLAPPED lpOverlapped,
	__in   LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
	__in   LPWSATHREADID lpThreadId,
	__out  LPINT lpErrno
)
{
	return NextProcTable.lpWSPSend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine, lpThreadId, lpErrno);
}
//WSPRecv  
int WINAPI WSPRecv(
	__in     SOCKET s,
	__inout  LPWSABUF lpBuffers,
	__in     DWORD dwBufferCount,
	__out    LPDWORD lpNumberOfBytesRecvd,
	__inout  LPDWORD lpFlags,
	__in     LPWSAOVERLAPPED lpOverlapped,
	__in     LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
	__in     LPWSATHREADID lpThreadId,
	__out    LPINT lpErrno
)
{
	return NextProcTable.lpWSPRecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine, lpThreadId, lpErrno);
}
//WSPRecvFrom  
int WINAPI WSPRecvFrom(
	__in     SOCKET s,
	__inout  LPWSABUF lpBuffers,
	__in     DWORD dwBufferCount,
	__out    LPDWORD lpNumberOfBytesRecvd,
	__inout  LPDWORD lpFlags,
	__out    struct sockaddr *lpFrom,
	__inout  LPINT lpFromlen,
	__in     LPWSAOVERLAPPED lpOverlapped,
	__in     LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
	__in     LPWSATHREADID lpThreadId,
	__inout  LPINT lpErrno
)
{
	return NextProcTable.lpWSPRecvFrom(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine, lpThreadId, lpErrno);
}
//WSPStartup  
int WSPAPI WSPStartup(
	WORD wversionrequested,
	LPWSPDATA         lpwspdata,
	LPWSAPROTOCOL_INFOW lpProtoInfo,
	WSPUPCALLTABLE upcalltable,
	LPWSPPROC_TABLE lpproctable
)
{
	PutDbgStr(L"LSP-Proxy WSPStartup ...");
	int           i;
	int           errorcode;
	int           filterpathlen;
	DWORD         layerid = 0;
	DWORD         nextlayerid = 0;
	TCHAR         *filterpath;
	HINSTANCE     hfilter;
	LPWSPSTARTUP  wspstartupfunc = NULL;
	if (lpProtoInfo->ProtocolChain.ChainLen <= 1)
	{
		PutDbgStr(L"ChainLen<=1");
		return FALSE;
	}
	GetLSP();
	for (i = 0; i < TotalProtos; i++)
	{
		if (memcmp(&ProtoInfo[i].ProviderId, &ProviderGuid, sizeof(GUID)) == 0)
		{
			layerid = ProtoInfo[i].dwCatalogEntryId;
			break;
		}
	}
	for (i = 0; i < lpProtoInfo->ProtocolChain.ChainLen; i++)
	{
		if (lpProtoInfo->ProtocolChain.ChainEntries[i] == layerid)
		{
			nextlayerid = lpProtoInfo->ProtocolChain.ChainEntries[i + 1];
			break;
		}
	}
	filterpathlen = MAX_PATH;
	filterpath = (TCHAR*)GlobalAlloc(GPTR, filterpathlen);
	for (i = 0; i < TotalProtos; i++)
	{
		if (nextlayerid == ProtoInfo[i].dwCatalogEntryId)
		{
			if (WSCGetProviderPath(&ProtoInfo[i].ProviderId, filterpath, &filterpathlen, &errorcode) == SOCKET_ERROR)
			{
				PutDbgStr(L"WSCGetProviderPath Error!");
				return WSAEPROVIDERFAILEDINIT;
			}
			break;
		}
	}
	if (!ExpandEnvironmentStrings(filterpath, filterpath, MAX_PATH))
	{
		PutDbgStr(L"ExpandEnvironmentStrings Error!");
		return WSAEPROVIDERFAILEDINIT;
	}
	if ((hfilter = LoadLibrary(filterpath)) == NULL)
	{
		PutDbgStr(L"LoadLibrary Error! TotalProtos=%d filterpath=%ws layer=%d, nextlayer=%d", TotalProtos, filterpath, layerid, nextlayerid);
		return WSAEPROVIDERFAILEDINIT;
	}
	if ((wspstartupfunc = (LPWSPSTARTUP)GetProcAddress(hfilter, "WSPStartup")) == NULL)
	{
		PutDbgStr(L"GetProcessAddress Error!");
		return WSAEPROVIDERFAILEDINIT;
	}
	if ((errorcode = wspstartupfunc(wversionrequested, lpwspdata, lpProtoInfo, upcalltable, lpproctable)) != ERROR_SUCCESS)
	{
		PutDbgStr(L"wspstartupfunc Error!");
		return errorcode;
	}
	NextProcTable = *lpproctable;// 保存原来的入口函数表  
								 //改写函数  
	lpproctable->lpWSPSendTo = WSPSendTo;
	lpproctable->lpWSPSend = WSPSend;
	lpproctable->lpWSPBind = WSPBind;
	lpproctable->lpWSPConnect = WSPConnect;
	lpproctable->lpWSPRecv = WSPRecv;
	lpproctable->lpWSPRecvFrom = WSPRecvFrom;
	lpproctable->lpWSPSocket = WSPSocket;
	FreeLSP();
	return 0;
}

// DLL入口函数  
BOOL APIENTRY DllMain(HMODULE /* hModule */, DWORD ul_reason_for_call, LPVOID /* lpReserved */)
{
	TCHAR   processname[MAX_PATH];
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		GetModuleFileName(NULL, processname, MAX_PATH);
		PutDbgStr(L"%s Loading IPFilter ...", processname);
	}
	return TRUE;
}