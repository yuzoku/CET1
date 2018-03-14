#include "keymngserverop.h"
#include "keymng_shmop.h"
#include <time.h>
#include "icdbapi.h"
#include "keymng_dbop.h"

int MngServer_InitInfo(MngServer_Info * svrInfo)
{
	strcpy(svrInfo->serverId, "0001");
	strcpy(svrInfo->serverip, "127.0.0.1");
	svrInfo->serverport = 9999;
	svrInfo->maxnode = 100;
	svrInfo->shmkey = ftok("/home", 8);
	KeyMng_ShmInit(svrInfo->shmkey, svrInfo->maxnode, &svrInfo->shmhdl);

	// 数据库初始化
	svrInfo->dbpoolnum = 20;
	strcpy(svrInfo->dbuse, "SECMNG");
	strcpy(svrInfo->dbpasswd, "SECMNG");
	strcpy(svrInfo->dbsid, "orcl");
	int ret = IC_DBApi_PoolInit(svrInfo->dbpoolnum, svrInfo->dbsid, svrInfo->dbuse, svrInfo->dbpasswd);
	if (ret != 0)
	{
		printf("IC_DBApi_PoolInit error...\n");
		return -1;
	}

	return 0;
}

int MngServer_Agree(MngServer_Info * svrInfo, MsgKey_Req * msgkeyReq, unsigned char ** outData, int * datalen)
{
	// 身份合法, 拿出r1随机数, 和自己生产r2生产秘钥
	MsgKey_Res resMsg;
	memset(&resMsg, 0, sizeof(MsgKey_Res));
	GetRandString(sizeof(resMsg.r2) - 1, &resMsg.r2);
	// 合并r1 and r2, 合并的方式必须一样...
	int j = 0;
	char tmpBuf[127] = { 0 };
	for (int i = 0; i < strlen(resMsg.r2); ++i)
	{
		tmpBuf[j++] = msgkeyReq->r1[i];
		tmpBuf[j++] = resMsg.r2[i];
	}
	// md5算法计算字符串 -> 得到秘钥
	printf("Sever secKey: %s\n", tmpBuf);

	// 秘钥写入共享内存
	NodeSHMInfo shmInfo;
	strcpy(shmInfo.clientId, msgkeyReq->clientId);
	strcpy(shmInfo.serverId, msgkeyReq->serverId);
	strcpy(shmInfo.seckey, tmpBuf);
	// 需要读数据库的数据 seckeyID
	shmInfo.status = 0;

	// .....数据库操作
	// 1. 取出一条连接
	ICDBHandle handle;
	int ret = IC_DBApi_ConnGet(&handle, 10, 10);
	if (ret != 0)
	{
		printf("IC_DBApi_ConnGet fail...\n");
		return -1;
	}
	// 2. 开启事务
	IC_DBApi_BeginTran(handle);
	// 3. 先从数据库中读keysnid
	KeyMngsvr_DBOp_GetKeyID(handle, &resMsg.seckeyid);
	shmInfo.seckeyid = resMsg.seckeyid;
	// 4. 将秘钥信息写入数据库表中
	ret = KeyMngsvr_DBOp_WriteSecKey(handle, &shmInfo);
	if (ret != 0)
	{
		printf("KeyMngsvr_DBOp_WriteSecKey fail...\n");
		IC_DBApi_Rollback(handle);
		if (ret == IC_DB_CONNECT_ERR)
		{
			IC_DBApi_ConnFree(handle, 0);
		}
		return -1;
	}
	IC_DBApi_Commit(handle);
	// 5. 将拿出的连接放回
	IC_DBApi_ConnFree(handle, 1);

	// 准备秘钥响应结构体MsgKey_Res(初始化)
	strcpy(resMsg.clientId, msgkeyReq->clientId);
	strcpy(resMsg.serverId, msgkeyReq->serverId);
	resMsg.rv = 0;	// sucess : 0, fail: -1
	// resMsg.seckeyid = xxx;	// 读数据库
	// MsgKey_Res编码, 得到一个序列化之后的字符串char*
	// 将char* 传出
	MsgEncode(&resMsg, ID_MsgKey_Res, outData, datalen);
	KeyMng_ShmWrite(svrInfo->shmhdl, svrInfo->maxnode, &shmInfo);

	return 0;
}

void GetRandString(int len, char * buf)
{
	int flag = -1;
	srand(time(NULL));
	char chars[] = ";':[]{}+_)(*&^%$#@!";
	for (int i = 0; i < len; ++i)
	{
		flag = rand() % 4;
		switch (flag)
		{
		case 3:
			buf[i] = 'A' + rand() % 26;
			break;
		case 2:
			buf[i] = 'a' + rand() % 26;
			break;
		case 1:
			buf[i] = chars[rand() % strlen(chars)];
			break;
		case 0:
			buf[i] = '0' + rand() % 10;
			break;
		default:
			break;
		}
	}
}
