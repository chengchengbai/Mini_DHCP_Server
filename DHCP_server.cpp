// ConsoleApplication2.cpp : 定义控制台应用程序的入口点。
//
#include "stdafx.h"
#include  "dhcp.h"

using namespace std;


int udp_broadcast_send1(char *data, int len)//发送函数
{
	
	WORD wVersionRequested = MAKEWORD(2, 2);
	WSADATA wsaData;
	if (0 != WSAStartup(wVersionRequested, &wsaData))
	{
		printf("WSAStartup failed with error: %d\n", GetLastError());
		return 0;
	}
	if (2 != HIBYTE(wsaData.wVersion) || 2 != LOBYTE(wsaData.wVersion))
	{
		printf("Socket version not supported.\n");
		WSACleanup();
		return 0;
	}
	SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (INVALID_SOCKET == sock)
	{
		printf("socket failed with error: %d\n", WSAGetLastError());
		WSACleanup();
		return 0;
	}
	SOCKADDR_IN addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.S_un.S_addr = htonl(INADDR_BROADCAST);
	addr.sin_port = htons(67);
	BOOL bBoardcast = TRUE;
	if (SOCKET_ERROR == setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (char*)&bBoardcast, sizeof(bBoardcast)))
	{
		printf("setsockopt failed with error code: %d\n", WSAGetLastError());
		if (INVALID_SOCKET != sock)
		{
			closesocket(sock);
			sock = INVALID_SOCKET;
		}
		WSACleanup();
	}
	printf("Client start to boardcast ...\n");
	//char buf[] = { "Hello, this is boardcast!" };
	/*for (int i = 0; i < len;i++){
	printf("%d ", data[i]);
	}
	printf("\n");*/
	if (SOCKET_ERROR == sendto(sock, data, len, 0, (LPSOCKADDR)&addr, sizeof(addr)))
	{
		printf("sendto failed with error: %d\n", WSAGetLastError());
	}
	else
	{
		cout << "DHCP Request (UDP) send succeeded! " << endl;
		closesocket(sock);//******
		WSACleanup();//****
		return 1;
	}

	closesocket(sock);
	WSACleanup();
	return 0;
}



void DHCP_REPLY(u_int8_t *buf, int len1)//构建DHCPREQUEST的回应报文
{
	u_int8_t buffer[max_size]={0};
	u_int8_t *buffer_p = buffer;
	struct dhcp_packet *DHCP = (struct dhcp_packet *)buffer_p;
	int i;
	int j;
	int flag=1;//1为ACK 0为NACK
	/**判断IP是否满足,决定是发送ACK还是NACK**/
	/**从option字段来**/
	struct dhcp_packet *DHCP_S = (struct dhcp_packet *)buf;
	int type;
	int length;
	int data;
	i = 0;
	while (i + 238 + 4<len1){
		type = DHCP_S->options[i];
		i++;
		length = DHCP_S->options[i];
		i++;
		if (type == 50){//50为请求IP选项
			DHCP->yiaddr.S_un.S_un_b.s_b1 = DHCP_S->options[i];
			DHCP->yiaddr.S_un.S_un_b.s_b2 = DHCP_S->options[i+1];
			DHCP->yiaddr.S_un.S_un_b.s_b3 = DHCP_S->options[i+2];
			DHCP->yiaddr.S_un.S_un_b.s_b4 = DHCP_S->options[i+3];
			i = i + 4;
			break;
		}
		else {
			i = i + length;
		}
	}
	if (i+238+4>=len1){//不包含请求IP选项
		flag = 0;
		printf("error:无效包，option字段不包含有效字符\n");
		return;
	}

	struct dhcp_packet *DHCP_buf = (struct dhcp_packet *)buf;
	/**MAC地址**/
	for (i = 0; i < 16; i++){
		DHCP->chaddr[i] = DHCP_buf->chaddr[i];
		//printf("MAC:%d", DHCP_buf->chaddr[i]);
	}

	int s_IP_no=-1;
	j=0;
	if (debug)
	printf("DHCP_REQUEST请求ip为：%d %d %d %d\n",DHCP->yiaddr.S_un.S_un_b.s_b1,DHCP->yiaddr.S_un.S_un_b.s_b2,DHCP->yiaddr.S_un.S_un_b.s_b3,DHCP->yiaddr.S_un.S_un_b.s_b4);
	for (i=0;i<ip_sum;i++){
		if (DHCP->yiaddr.S_un.S_un_b.s_b1 ==ip[i].ip.S_un.S_un_b.s_b1&&
			DHCP->yiaddr.S_un.S_un_b.s_b2 == ip[i].ip.S_un.S_un_b.s_b2&&
			DHCP->yiaddr.S_un.S_un_b.s_b3 == ip[i].ip.S_un.S_un_b.s_b3&&
			DHCP->yiaddr.S_un.S_un_b.s_b4 == ip[i].ip.S_un.S_un_b.s_b4){
				s_IP_no=i;
				if(ip[i].flag==true){
					break;
				}
				for (j=0;j<16;j++){//判断是不是目前ip对应的客户端mac地址
					if (DHCP_S->chaddr[j]!=ip[i].c_mac[j]){break;}
				}
				if (j!=16){
					flag=0;
				}
				break;
				
		}
	}
	if (i==ip_sum){
		printf("error:请求无效ip\n");
		return ;
	}


	

	/**构建报文**/
	
	DHCP->op = 2;//client-->server:1 server-->client:2
	DHCP->htype = 1;
	DHCP->hlen = 6;
	DHCP->hops = 0;
	DHCP->xid = DHCP_buf->xid;//客户端设置
	DHCP->secs = DHCP_buf->secs;//客户端设置
	DHCP->flags = 0x8000;
	DHCP->ciaddr.S_un.S_un_b.s_b1 = 0;
	DHCP->ciaddr.S_un.S_un_b.s_b2 = 0;
	DHCP->ciaddr.S_un.S_un_b.s_b3 = 0;
	DHCP->ciaddr.S_un.S_un_b.s_b4 = 0;
	/*DHCP->yiaddr.S_un.S_un_b.s_b1 = ip[i].ip.S_un.S_un_b.s_b1;
	DHCP->yiaddr.S_un.S_un_b.s_b2 = ip[i].ip.S_un.S_un_b.s_b2;
	DHCP->yiaddr.S_un.S_un_b.s_b3 = ip[i].ip.S_un.S_un_b.s_b3;
	DHCP->yiaddr.S_un.S_un_b.s_b4 = ip[i].ip.S_un.S_un_b.s_b4;*/
	DHCP->siaddr.S_un.S_un_b.s_b1 = 0;
	DHCP->siaddr.S_un.S_un_b.s_b2 = 0;
	DHCP->siaddr.S_un.S_un_b.s_b3 = 0;
	DHCP->siaddr.S_un.S_un_b.s_b4 = 0;
	DHCP->giaddr.S_un.S_un_b.s_b1 = 0;
	DHCP->giaddr.S_un.S_un_b.s_b2 = 0;
	DHCP->giaddr.S_un.S_un_b.s_b3 = 0;
	DHCP->giaddr.S_un.S_un_b.s_b4 = 0;
	
	/**服务端名**/
	for (i = 0; i < 64; i++){
		DHCP->sname[i] = 0;
	}
	DHCP->sname[0] = 'D';
	DHCP->sname[1] = 'D';
	DHCP->sname[2] = 'D';
	DHCP->sname[3] = 'D';
	for (i = 0; i < 128; i++){
		DHCP->file[i] = 0;
	}
	DHCP->cookie[0] = 0x63;
	DHCP->cookie[1] = 0x82;
	DHCP->cookie[2] = 0x53;
	DHCP->cookie[3] = 0x63;
	int len;
	len = 0;
	/**报文类型**/
	DHCP->options[len] = 53;
	DHCP->options[len + 1] = 1;
	if (flag){//ACK
		ip[s_IP_no].flag=false;
		for (j=0;j<16;j++){
			ip[s_IP_no].c_mac[j]=DHCP->chaddr[j];
		}
		ip[s_IP_no].start_time=time(NULL);
		DHCP->options[len + 2] = 5;
	}
	else {
		DHCP->options[len+2]=6;
	}
	len = len + 3;
	/**服务器标识**/
	DHCP->options[len] = 54;
	DHCP->options[len + 1] = 4;
	DHCP->options[len + 2] = 192;
	DHCP->options[len + 3] = 168;
	DHCP->options[len + 4] = 5;
	DHCP->options[len + 5] = 2;
	len = len + 6;
	/**有效租约期为maxsec**/
	DHCP->options[len] = 51;
	DHCP->options[len + 1] = 4;
	DHCP->options[len + 2] = 0x00;
	DHCP->options[len + 3] = 0x00;
	DHCP->options[len + 4] = 0x0e;
	DHCP->options[len + 5] = 0x10;
	len = len + 6;
	/**子网掩码**/
	DHCP->options[len] = 1;
	DHCP->options[len + 1] = 4;
	DHCP->options[len + 2] = 255;
	DHCP->options[len + 3] = 255;
	DHCP->options[len + 4] = 255;
	DHCP->options[len + 5] = 0;
	len = len + 6;
	/**网关地址**/
	DHCP->options[len] = 3;
	DHCP->options[len + 1] = 4;
	DHCP->options[len + 2] = 192;
	DHCP->options[len + 3] = 168;
	DHCP->options[len + 4] = 5;
	DHCP->options[len + 5] = 2;
	len = len + 6;
	
	
	/**DNS服务器地址**/
	DHCP->options[len] = 6;
	DHCP->options[len + 1] = 8;
	DHCP->options[len + 2] = 192;
	DHCP->options[len + 3] = 168;
	DHCP->options[len + 4] = 5;
	DHCP->options[len + 5] = 1;
	DHCP->options[len + 6] = 114;
	DHCP->options[len + 7] = 114;
	DHCP->options[len + 8] = 114;
	DHCP->options[len + 9] = 114;
	len = len + 10;
	/**域名后缀**/
	DHCP->options[len] = 15;
	DHCP->options[len + 1] = 10;
	DHCP->options[len + 2] = 0x77;
	DHCP->options[len + 3] = 0x6f;
	DHCP->options[len + 4] = 0x72;
	DHCP->options[len + 5] = 0x6b;
	DHCP->options[len + 6] = 0x67;
	DHCP->options[len + 7] = 0x72;
	DHCP->options[len + 8] = 0x6f;
	DHCP->options[len + 9] = 0x75;
	DHCP->options[len + 10] = 0x70;
	DHCP->options[len + 11] = 0x00;
	len = len + 12;
	

	/*通过udp发送*/
	if (flag)
	printf("发送ACK成功\n");
	else
	printf("发送NACK成功\n");
	Sleep(2000);
	udp_broadcast_send1((char*)buffer, 548);//28 + 16 + 64 + 128 + 4 + len);
}
int search_free_ip()//寻找空闲ip
{
	int i;
	for (i = 0; i < ip_sum; i++)
	{
		if (ip[i].flag == true)
		{
			return i;
		}
	}
	return -1;
}
void DHCP_OFFER(u_int8_t *buf, int len1)//构建DHCPOFFER报文
{
	int i;
	i = search_aviliable_ip();
	if (i == -1){//ip已用完
		//send_nack();
		printf("error:ip用完\n");
		return;
	}
	struct dhcp_packet *DHCP_buf = (struct dhcp_packet *)buf;
	/**构建报文**/
	u_int8_t buffer[max_size]={0};
	u_int8_t *buffer_p = buffer;
	struct dhcp_packet *DHCP = (struct dhcp_packet *)buffer_p;
	DHCP->op = 2;//client-->server:1 server-->client:2
	DHCP->htype = 1;
	DHCP->hlen = 6;
	DHCP->hops = 0;
	DHCP->xid =DHCP_buf->xid;//客户端设置
	DHCP->secs = 0;//客户端设置
	DHCP->flags = 0x8000;
	DHCP->ciaddr.S_un.S_un_b.s_b1 = 0;
	DHCP->ciaddr.S_un.S_un_b.s_b2 = 0;
	DHCP->ciaddr.S_un.S_un_b.s_b3 = 0;
	DHCP->ciaddr.S_un.S_un_b.s_b4 = 0;
	DHCP->yiaddr.S_un.S_un_b.s_b1 = ip[i].ip.S_un.S_un_b.s_b1;
	DHCP->yiaddr.S_un.S_un_b.s_b2 = ip[i].ip.S_un.S_un_b.s_b2;
	DHCP->yiaddr.S_un.S_un_b.s_b3 = ip[i].ip.S_un.S_un_b.s_b3;
	DHCP->yiaddr.S_un.S_un_b.s_b4 = ip[i].ip.S_un.S_un_b.s_b4;
	DHCP->siaddr.S_un.S_un_b.s_b1 = 0;
	DHCP->siaddr.S_un.S_un_b.s_b2 = 0;
	DHCP->siaddr.S_un.S_un_b.s_b3 = 0;
	DHCP->siaddr.S_un.S_un_b.s_b4 = 0;
	DHCP->giaddr.S_un.S_un_b.s_b1 = 0;
	DHCP->giaddr.S_un.S_un_b.s_b2 = 0;
	DHCP->giaddr.S_un.S_un_b.s_b3 = 0;
	DHCP->giaddr.S_un.S_un_b.s_b4 = 0;
	/**MAC地址**/
	for (i = 0; i < 16; i++){
		DHCP->chaddr[i] =DHCP_buf->chaddr[i];
		//printf("MAC:%d", DHCP_buf->chaddr[i]);
	}
	/**服务端名**/
	for (i = 0; i < 64; i++){
		DHCP->sname[i] = 0;
	}
	DHCP->sname[0] = 'D';
	DHCP->sname[1] = 'D';
	DHCP->sname[2] = 'D';
	DHCP->sname[3] = 'D';
	for (i = 0; i < 128; i++){
		DHCP->file[i] = 0;
	}
	DHCP->cookie[0] = 0x63;
	DHCP->cookie[1] = 0x82;
	DHCP->cookie[2] = 0x53;
	DHCP->cookie[3] = 0x63;
	int len;
	len = 0;
	/**报文类型**/
	DHCP->options[len] = 53;
	DHCP->options[len + 1] = 1;
	DHCP->options[len + 2] = 2;
	len = len + 3;
	/**服务器标识**/
	DHCP->options[len] = 54;
	DHCP->options[len + 1] = 4;
	DHCP->options[len + 2] = 192;
	DHCP->options[len + 3] = 168;
	DHCP->options[len + 4] = 5;
	DHCP->options[len + 5] = 2;
	len = len + 6;
	/**有效租约期为maxsec**/
	DHCP->options[len] = 51;
	DHCP->options[len + 1] = 4;
	DHCP->options[len + 2] = 0x00;
	DHCP->options[len + 3] = 0x00;
	DHCP->options[len + 4] = 0x0e;
	DHCP->options[len + 5] = 0x10;
	len = len + 6;
	/**子网掩码**/
	DHCP->options[len] = 1;
	DHCP->options[len + 1] = 4;
	DHCP->options[len + 2] = 255;
	DHCP->options[len + 3] = 255;
	DHCP->options[len + 4] = 255;
	DHCP->options[len + 5] = 0;
	len = len + 6;
	/**网关地址**/
	DHCP->options[len] = 3;
	DHCP->options[len + 1] = 4;
	DHCP->options[len + 2] = 192;
	DHCP->options[len + 3] = 168;
	DHCP->options[len + 4] = 5;
	DHCP->options[len + 5] = 2;
	len = len + 6;
	
	
	/**DNS服务器地址**/
	DHCP->options[len] = 6;
	DHCP->options[len + 1] = 8;
	DHCP->options[len + 2] = 192;
	DHCP->options[len + 3] = 168;
	DHCP->options[len + 4] = 5;
	DHCP->options[len + 5] = 1;
	DHCP->options[len + 6] = 114;
	DHCP->options[len + 7] = 114;
	DHCP->options[len + 8] = 114;
	DHCP->options[len + 9] = 114;
	len = len + 10;
	/**域名后缀**/
	DHCP->options[len] = 15;
	DHCP->options[len + 1] = 10;
	DHCP->options[len + 2] = 0x77;
	DHCP->options[len + 3] = 0x6f;
	DHCP->options[len + 4] = 0x72;
	DHCP->options[len + 5] = 0x6b;
	DHCP->options[len + 6] = 0x67;
	DHCP->options[len + 7] = 0x72;
	DHCP->options[len + 8] = 0x6f;
	DHCP->options[len + 9] = 0x75;
	DHCP->options[len + 10] = 0x70;
	DHCP->options[len + 11] = 0x00;
	len = len + 12;
	
	/*通过udp发送*/
	Sleep(2000);
	udp_broadcast_send1((char*)buffer, 548);//28 + 16 + 64 + 128 + 4 + len);
}

int  Analyse_dhcp_packet(u_int8_t *buf, int len)//解析数据
{
	int i;
	struct dhcp_packet *DHCP = (struct dhcp_packet *)buf;
	if (len <= 238+4){
		printf("长度过小，无效包\n");
		return -1;
	}
	int type;
	int length;
	int data;
	i = 0;
	/**寻找DHCP报文option字中的DHCP消息类型**/
	while (i + 238 + 4<len){
		type = DHCP->options[i];
		if (type<0){
			printf("error：DHCP中options中含无效字段\n");
			return 0;
		}
		i++;
		length = DHCP->options[i];
		i++;
		if (type == 53){
			data = DHCP->options[i];
			i++;
			switch (data){
			case(1) : {return 1; }//DISCOVER
			case(3) : {return 2; }//DISQUEUE
			case(4) : {return 3; }//DHCPDECLINE
			case(7) : {return 4; }//DHCPRELEASE
			case(8) : {return 5; }//DHCPINFORM
			default:{printf("error：DHCP协议类型为无效字段\n"); return 0; }
			}
			break;
		}
		else {
			i = i + length;
		}
	}
	printf("error：DHCP option字段无DHCP协议类型,无效数据\n");
	return 0;
}

void recved()//接收数据
{
	DWORD ver;
	WSADATA wsaData;
	ver = MAKEWORD(2, 2);
	WSAStartup(ver, &wsaData);
	SOCKET st = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in addr;

	memset(&addr, 0, sizeof(addr));   // 初始化结构 addr
	addr.sin_family = AF_INET; // 代表要使用一个 TCP/IP 的地址

	addr.sin_port = htons(67); //host to net short

	addr.sin_addr.s_addr = htonl(INADDR_ANY); // 做为接收方，不需要指定具体的 IP 地址，接收的主机是什么 IP ，我就在什么 IP 上收数据
	DWORD TimeOut = 1000 * 5;//设置发送超时10秒
	int rc = 0;
	if (bind(st, (struct sockaddr *)&addr, sizeof(addr)) > -1)

	{

		char buf[100000] = { 0 };

		struct sockaddr_in sendaddr;

		memset(&sendaddr, 0, sizeof(sendaddr));

		int len = sizeof(sendaddr);

		while (1)

		{
			if (::setsockopt(st, SOL_SOCKET, SO_RCVTIMEO, (char *)&TimeOut, sizeof(TimeOut)) == SOCKET_ERROR)
			{
				cout << "设置失败" << endl;
			}
			memset(buf, 0, sizeof(buf));

			// 接收 udp 数据
			rc = recvfrom(st, buf, sizeof(buf), 0, NULL, NULL);
			if (rc<0){
				printf("recvfrom failed with error %d\n", WSAGetLastError());
				closesocket(st); // 使用完 socket 要将其关闭
				WSACleanup();    // 释放 win_socket 内部的相关资源
				return;
			}
			closesocket(st); // 使用完 socket 要将其关闭
			WSACleanup();    // 释放 win_socket 内部的相关资源
			int k;
			k = Analyse_dhcp_packet((u_int8_t *)buf, sizeof(buf));
			//printf("k:%d\n",k);
			if (debug){
				printf("服务端---接收到");
				switch (k){
				case(1) : {printf("DHCP_DISCOVER"); break; }
				case(2) : {printf("DHCP_REQUEST"); break; }
				case(3) : {printf("DHCP_DECLINE"); break; }
				case(4) : {printf("DHCP_RELEASE"); break; }
				case(5) : {printf("DHCP_INFORM"); break; }
				}
				printf("包\n\n");
			}
			switch (k){
			case(1) : { //DHCP_DISCOVER
				DHCP_OFFER((u_int8_t *)buf, sizeof(buf));
				break;
			}
			case(2) : {//DHCP_REQUEST
				DHCP_REPLY((u_int8_t *)buf, sizeof(buf));
				break;
			}
			case(3) : {/*DHCP_DECLINE()*/break; }
			case(4) : {/*DHCP_RELEASE()*/break; }
			case(5) : {/*DHCP_INFORM()*/break; }
			case(0) : {/**/break; };
			default:{printf("error:包中无有效数据\n"); }
			}
			//return k;
			return;
		}

	}
	else {
		printf("bind failed with error %d\n", WSAGetLastError());
		closesocket(st); // 使用完 socket 要将其关闭
		WSACleanup();    // 释放 win_socket 内部的相关资源
		return;
	}

	closesocket(st); // 使用完 socket 要将其关闭
	WSACleanup();    // 释放 win_socket 内部的相关资源
	return;
}



void INIT_IP()//ip池初始化
{
	int i;
	int j;
	for (i = 0; i<ip_sum; i++){
		ip[i].flag = true;
		ip[i].ip.S_un.S_un_b.s_b1 = 192;
		ip[i].ip.S_un.S_un_b.s_b2 = 168;
		ip[i].ip.S_un.S_un_b.s_b3 = 5;
		ip[i].ip.S_un.S_un_b.s_b4 = i + 3;
		ip[i].dns.S_un.S_un_b.s_b1 = 192;
		ip[i].dns.S_un.S_un_b.s_b2 = 168;
		ip[i].dns.S_un.S_un_b.s_b3 = 5;
		ip[i].dns.S_un.S_un_b.s_b4 = 1;
		for (j=0;j<16;j++){
			ip[i].c_mac[j]=0;
		}
		ip[i].start_time = 0;
		ip[i].ptime = 0;
	}
}
void Maintain_ip()//维护ip池
{
	int i;
	int j;
	for (i = 0; i<ip_sum; i++){
		if (ip[i].flag == true){
			ip[i].ptime = time(NULL);
			if (ip[i].ptime >= ip[i].start_time + maxsec){//判断ip的当前时间是否超过续租的时间
				ip[i].flag = true;
				ip[i].start_time = 0;
				ip[i].ptime = 0;
				for (j=0;j<16;j++){
					ip[i].c_mac[j]=0;
				}
			}
		}
	}
}
int _tmain(int argc, _TCHAR* argv[])
{
	
	//服务端
	/**初始化ip池**/
	INIT_IP();
	while (1)
	{
		//是否接收到请求
		recved();
		Maintain_ip();//维护ip池
	}
	return 0;
}

