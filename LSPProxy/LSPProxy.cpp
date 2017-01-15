// LSPProxy.cpp : 定义控制台应用程序的入口点。
//
#include "stdafx.h"
#include <Ws2spi.h>  
#include <Sporder.h>        // 定义了WSCWriteProviderOrder函数  
#include <windows.h>  
#include <stdio.h>  
#pragma comment(lib, "Ws2_32.lib")  
#pragma comment(lib, "Rpcrt4.lib")    // 实现了UuidCreate函数  


// !< 与LSPBase中定义的GUID一致, 在便利LSP协议处理层的时候有用.
GUID ProviderGuid = { 0xd3c21122, 0x85e1, 0x48f3,{ 0x9a,0xb6,0x23,0xd9,0x0c,0x73,0x77,0xef } };

LPWSAPROTOCOL_INFOW GetProvider(LPINT lpnTotalProtocols)
{
	DWORD dwSize = 0;
	int nError;
	LPWSAPROTOCOL_INFOW pProtoInfo = NULL;

	// 取得需要的长度  
	if (::WSCEnumProtocols(NULL, pProtoInfo, &dwSize, &nError) == SOCKET_ERROR)
	{
		if (nError != WSAENOBUFS)
			return NULL;
	}

	pProtoInfo = (LPWSAPROTOCOL_INFOW)::GlobalAlloc(GPTR, dwSize);
	*lpnTotalProtocols = ::WSCEnumProtocols(NULL, pProtoInfo, &dwSize, &nError);
	return pProtoInfo;
}
void FreeProvider(LPWSAPROTOCOL_INFOW pProtoInfo)
{
	::GlobalFree(pProtoInfo);
}
BOOL InstallProvider(WCHAR *pwszPathName)
{
	WCHAR wszLSPName[] = L"LSPBase";
	LPWSAPROTOCOL_INFOW pProtoInfo;
	int nProtocols;
	WSAPROTOCOL_INFOW OriginalProtocolInfo[3];
	DWORD             dwOrigCatalogId[3];
	int nArrayCount = 0;
	DWORD dwLayeredCatalogId;        // 我们分层协议的目录ID号  
	int nError;

	// 找到我们的下层协议，将信息放入数组中  
	// 枚举所有服务程序提供者  
	pProtoInfo = GetProvider(&nProtocols);
	BOOL bFindUdp = FALSE;
	BOOL bFindTcp = FALSE;
	BOOL bFindRaw = FALSE;
	for (int i = 0; i < nProtocols; i++)
	{
		if (pProtoInfo[i].iAddressFamily == AF_INET)
		{
			if (!bFindUdp && pProtoInfo[i].iProtocol == IPPROTO_UDP)
			{
				memcpy(&OriginalProtocolInfo[nArrayCount], &pProtoInfo[i], sizeof(WSAPROTOCOL_INFOW));
				OriginalProtocolInfo[nArrayCount].dwServiceFlags1 =
					OriginalProtocolInfo[nArrayCount].dwServiceFlags1 & (~XP1_IFS_HANDLES);

				dwOrigCatalogId[nArrayCount++] = pProtoInfo[i].dwCatalogEntryId;
				bFindUdp = TRUE;
			}
			if (!bFindTcp && pProtoInfo[i].iProtocol == IPPROTO_TCP)
			{
				memcpy(&OriginalProtocolInfo[nArrayCount], &pProtoInfo[i], sizeof(WSAPROTOCOL_INFOW));
				OriginalProtocolInfo[nArrayCount].dwServiceFlags1 =
					OriginalProtocolInfo[nArrayCount].dwServiceFlags1 & (~XP1_IFS_HANDLES);

				dwOrigCatalogId[nArrayCount++] = pProtoInfo[i].dwCatalogEntryId;
				bFindTcp = TRUE;
			}
			if (!bFindRaw && pProtoInfo[i].iProtocol == IPPROTO_IP)
			{
				memcpy(&OriginalProtocolInfo[nArrayCount], &pProtoInfo[i], sizeof(WSAPROTOCOL_INFOW));
				OriginalProtocolInfo[nArrayCount].dwServiceFlags1 =
					OriginalProtocolInfo[nArrayCount].dwServiceFlags1 & (~XP1_IFS_HANDLES);

				dwOrigCatalogId[nArrayCount++] = pProtoInfo[i].dwCatalogEntryId;
				bFindRaw = TRUE;
			}
		}
	}
	// 安装我们的分层协议，获取一个dwLayeredCatalogId  
	// 随便找一个下层协议的结构复制过来即可  
	WSAPROTOCOL_INFOW LayeredProtocolInfo;
	memcpy(&LayeredProtocolInfo, &OriginalProtocolInfo[0], sizeof(WSAPROTOCOL_INFOW));
	// 修改协议名称，类型，设置PFL_HIDDEN标志  
	wcscpy_s(LayeredProtocolInfo.szProtocol, wszLSPName);
	LayeredProtocolInfo.ProtocolChain.ChainLen = LAYERED_PROTOCOL; // 0;  
	LayeredProtocolInfo.dwProviderFlags |= PFL_HIDDEN;
	// 安装  
	if (::WSCInstallProvider(&ProviderGuid,
		pwszPathName, &LayeredProtocolInfo, 1, &nError) == SOCKET_ERROR)
	{
		printf("path=%ws, error=%d\n", pwszPathName, nError);
		return FALSE;
	}
	// 重新枚举协议，获取分层协议的目录ID号  
	FreeProvider(pProtoInfo);
	pProtoInfo = GetProvider(&nProtocols);
	for (int i = 0; i < nProtocols; i++)
	{
		if (memcmp(&pProtoInfo[i].ProviderId, &ProviderGuid, sizeof(ProviderGuid)) == 0)
		{
			dwLayeredCatalogId = pProtoInfo[i].dwCatalogEntryId;
			break;
		}
	}
	// 安装协议链  
	// 修改协议名称，类型  
	WCHAR wszChainName[WSAPROTOCOL_LEN + 1];
	for (int i = 0; i < nArrayCount; i++)
	{
		swprintf(wszChainName, ARRAYSIZE(wszChainName), L"%ws over %ws", wszLSPName, OriginalProtocolInfo[i].szProtocol);
		wcscpy_s(OriginalProtocolInfo[i].szProtocol, wszChainName);
		if (OriginalProtocolInfo[i].ProtocolChain.ChainLen == 1)
		{
			OriginalProtocolInfo[i].ProtocolChain.ChainEntries[1] = dwOrigCatalogId[i];
		}
		else
		{
			for (int j = OriginalProtocolInfo[i].ProtocolChain.ChainLen; j > 0; j--)
			{
				OriginalProtocolInfo[i].ProtocolChain.ChainEntries[j]
					= OriginalProtocolInfo[i].ProtocolChain.ChainEntries[j - 1];
			}
		}
		OriginalProtocolInfo[i].ProtocolChain.ChainLen++;
		OriginalProtocolInfo[i].ProtocolChain.ChainEntries[0] = dwLayeredCatalogId;
	}
	// 获取一个Guid，安装之  
	GUID ProviderChainGuid;
	if (::UuidCreate(&ProviderChainGuid) == RPC_S_OK)
	{
		if (::WSCInstallProvider(&ProviderChainGuid,
			pwszPathName, OriginalProtocolInfo, nArrayCount, &nError) == SOCKET_ERROR)
		{
			return FALSE;
		}
	}
	else
		return FALSE;
	// 重新排序Winsock目录，将我们的协议链提前  
	// 重新枚举安装的协议  
	FreeProvider(pProtoInfo);
	pProtoInfo = GetProvider(&nProtocols);
	PDWORD dwIds = (PDWORD)malloc(sizeof(DWORD) * nProtocols);
	int nIndex = 0;
	// 添加我们的协议链  
	for (int i = 0; i < nProtocols; i++)
	{
		if ((pProtoInfo[i].ProtocolChain.ChainLen > 1) &&
			(pProtoInfo[i].ProtocolChain.ChainEntries[0] == dwLayeredCatalogId))
			dwIds[nIndex++] = pProtoInfo[i].dwCatalogEntryId;
	}
	// 添加其它协议  
	for (int i = 0; i < nProtocols; i++)
	{
		if ((pProtoInfo[i].ProtocolChain.ChainLen <= 1) ||
			(pProtoInfo[i].ProtocolChain.ChainEntries[0] != dwLayeredCatalogId))
			dwIds[nIndex++] = pProtoInfo[i].dwCatalogEntryId;
	}
	// 重新排序Winsock目录  
	if ((nError = ::WSCWriteProviderOrder(dwIds, nIndex)) != ERROR_SUCCESS)
	{
		return FALSE;
	}
	FreeProvider(pProtoInfo);
	return TRUE;
}
BOOL RemoveProvider()
{
	LPWSAPROTOCOL_INFOW pProtoInfo;
	int nProtocols;
	DWORD dwLayeredCatalogId;
	// 根据Guid取得分层协议的目录ID号  
	pProtoInfo = GetProvider(&nProtocols);
	int nError;
	int i;
	for (i = 0; i < nProtocols; i++)
	{
		if (memcmp(&ProviderGuid, &pProtoInfo[i].ProviderId, sizeof(ProviderGuid)) == 0)
		{
			dwLayeredCatalogId = pProtoInfo[i].dwCatalogEntryId;
			break;
		}
	}
	if (i < nProtocols)
	{
		// 移除协议链  
		for (i = 0; i < nProtocols; i++)
		{
			if ((pProtoInfo[i].ProtocolChain.ChainLen > 1) &&
				(pProtoInfo[i].ProtocolChain.ChainEntries[0] == dwLayeredCatalogId))
			{
				::WSCDeinstallProvider(&pProtoInfo[i].ProviderId, &nError);
			}
		}

		// 移除分层协议  
		::WSCDeinstallProvider(&ProviderGuid, &nError);
	}
	else return FALSE;
	return TRUE;
}
void main(int argc, char *argv[])
{
	bool bInstall = false;
	if (argc >= 2 && strcmp(argv[1], "-install") == 0)
	{
		bInstall = true;
	}
	if (bInstall)
	{
		TCHAR szPathName[256];
		TCHAR* p;
		if (::GetFullPathName(L"LSPBase.dll", 256, szPathName, &p) != 0)
		{
			if (LoadLibrary(szPathName) == NULL)
			{
				printf("Failed load library. error=%d\n", GetLastError());
			}
			if (InstallProvider(szPathName))
			{
				printf("Install successully. \n");
				return;
			}
		}
		printf("Install failed. ERROR=%d\n", GetLastError());
		return;
	}
	else
	{
		if (RemoveProvider())
			printf("Remove successully. \n");
		else
			printf("Remove failed. ERROR=%d\n", GetLastError());
		return;
	}
}