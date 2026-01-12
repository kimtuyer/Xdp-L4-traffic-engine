#include <stdio.h>

#include "define.h"
#include "Global.h"
#include "PacketMonitor.h"
//#include "PacketCapture.h"
//#include "PacketDetect.h"
vector<char*> Payloadlist;
//vector<char*> PacketBuffer;
vector<Packet>local_buffer;
//Concurrency::concurrent_queue<Packet> PacketBuffer;
map<uint32_t, int> IPList;

//std::vector<map<uint32_t, pair<Packet, int>>> worker_queues;
//concurrency::concurrent_queue<uint32_t> blacklist_queue;
//mutex m1[NUM_WORKER_THREADS];



#ifdef __LINUX__
#else
bool LoadNpcapDlls()
{
	wchar_t npcap_dir[512];
	unsigned int len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
		return FALSE;
	}
	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
		return FALSE;
	}

	return TRUE;
}
#endif
#ifdef __OOP__
#else


unsigned short CalcChecksumIp(IpHeader* pIpHeader)
{
	unsigned char ihl = (pIpHeader->verIhl & 0x0F) << 2; //*4와 동일
	unsigned short wData[30] = { 0 };
	unsigned int dwSum = 0;

	memcpy(wData, (BYTE*)pIpHeader, ihl);
	//((IpHeader*)wData)->checksum = 0x0000;

	for (int i = 0; i < ihl / 2; i++)
	{
		if (i != 5)
			dwSum += wData[i];

		if (dwSum & 0xFFFF0000)
		{
			dwSum &= 0x0000FFFF;
			dwSum++;
		}
	}

	return ~(dwSum & 0x0000FFFF);
}

unsigned short CalcChecksumTcp(IpHeader* pIpHeader, TcpHeader* pTcpHeader)
{
	PseudoHeader	pseudoHeader = { 0 };
	unsigned short* pwPseudoHeader = (unsigned short*)&pseudoHeader;
	unsigned short* pwDatagram = (unsigned short*)pTcpHeader;
	int				nPseudoHeaderSize = 6; //WORD 6개 배열
	int				nSegmentSize = 0; //헤더 포함

	UINT32			dwSum = 0;
	int				nLengthOfArray = 0;

	pseudoHeader.srcIp = *(unsigned int*)pIpHeader->srcIp;
	pseudoHeader.dstIp = *(unsigned int*)pIpHeader->dstIp;
	pseudoHeader.zero = 0;
	pseudoHeader.protocol = 6;
	pseudoHeader.length = htons(ntohs(pIpHeader->length) - 20);


	nSegmentSize = ntohs(pseudoHeader.length);

	if (nSegmentSize % 2)
		nLengthOfArray = nSegmentSize / 2 + 1;
	else
		nLengthOfArray = nSegmentSize / 2;

	for (int i = 0; i < nPseudoHeaderSize; i++)
	{
		dwSum += pwPseudoHeader[i];
		if (dwSum & 0xFFFF0000)
		{
			dwSum &= 0x0000FFFF;
			dwSum++;
		}
	}

	for (int i = 0; i < nLengthOfArray; i++)
	{
		if (i != 8)
			dwSum += pwDatagram[i];
		if (dwSum & 0xFFFF0000)
		{
			dwSum &= 0x0000FFFF;
			dwSum++;
		}
	}

	return (USHORT)~(dwSum & 0x0000FFFF);
}

void packet_Reset(const TcpHeader* pTcp,const pcap_t* adhandle)
{
	unsigned char frameData[1514] = { 0 };
	int msgSize = 0;
	EtherHeader* pEtherHeader = (EtherHeader*)frameData;
	pEtherHeader->dstMac[0] = 0x00; pEtherHeader->dstMac[1] = 0x0C;
	pEtherHeader->dstMac[2] = 0x29; pEtherHeader->dstMac[3] = 0x72;
	pEtherHeader->dstMac[4] = 0x01; pEtherHeader->dstMac[5] = 0x51;

	pEtherHeader->srcMac[0] = 0x00; pEtherHeader->srcMac[1] = 0x50;
	pEtherHeader->srcMac[2] = 0x56; pEtherHeader->srcMac[3] = 0xC0;
	pEtherHeader->srcMac[4] = 0x00; pEtherHeader->srcMac[5] = 0x01;

	pEtherHeader->type = htons(0x0800);

	IpHeader* pIpHeader = (IpHeader*)(frameData + sizeof(EtherHeader));
	pIpHeader->verIhl = 0x45;
	pIpHeader->tos = 0x00;
	pIpHeader->length = htons(40);
	pIpHeader->id = 0x3412;
	pIpHeader->fragOffset = htons(0x4000); //DF
	pIpHeader->ttl = 0xFF;
	pIpHeader->protocol = 6; // TCP
	pIpHeader->checksum = 0x0000;

	pIpHeader->srcIp[0] = 192;
	pIpHeader->srcIp[1] = 168;
	pIpHeader->srcIp[2] = 41;
	pIpHeader->srcIp[3] = 1;

	pIpHeader->dstIp[0] = 192;
	pIpHeader->dstIp[1] = 168;
	pIpHeader->dstIp[2] = 41;
	pIpHeader->dstIp[3] = 128;

	int ipHeaderLen = 20;
	TcpHeader* pTcpHeader =
		(TcpHeader*)(frameData + sizeof(EtherHeader) + ipHeaderLen);

	pTcpHeader->srcPort = htons(ntohs(pTcp->srcPort)); //반드시 일치
	pTcpHeader->dstPort = htons(25000);
	pTcpHeader->seq = (pTcp->seq); // 반드시 일치 , pTcp->seq 값은 이미 Net-order 순서이므로 변환없이 그대로 복사
	pTcpHeader->ack = 0;
	pTcpHeader->data = 0x50;
	pTcpHeader->flags = 0x04; //RST
	pTcpHeader->windowSize = 0;
	pTcpHeader->checksum = 0x0000;
	pTcpHeader->urgent = 0;


	pIpHeader->checksum = CalcChecksumIp(pIpHeader);
	pTcpHeader->checksum = CalcChecksumTcp(pIpHeader, pTcpHeader);

	/* Send down the packet */
	if (pcap_sendpacket(const_cast<pcap_t*>(adhandle),	// Adapter
		frameData, // buffer with the packet
		sizeof(EtherHeader) + sizeof(IpHeader) + sizeof(TcpHeader)
	) != 0)
	{
		fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(const_cast<pcap_t*>(adhandle)));
	}



}

void packet_detect(const int ThreadID,const pcap_t* adhandle)
{

	auto last_check_time = std::chrono::steady_clock::now();

	int size = 500;
	map<uint32_t, pair<Packet, int>> local_IPList;

#ifdef __VER2__
	while (1)
	{

		auto now = std::chrono::steady_clock::now();
		if (chrono::duration_cast<std::chrono::seconds>(now - last_check_time).count() >= 1) {
			last_check_time = now;

			//printf("--- 1초 경과: 카운트 리셋 ---\n");

			{
				lock_guard<mutex> local_m(m1[ThreadID]);
				if(worker_queues[ThreadID].empty()==false)
					local_IPList.swap(worker_queues[ThreadID]);
			}

			for (auto it= local_IPList.begin(); it!=local_IPList.end();)
			{
				int packet_count = (*it).second.second;

				/*if (packet_count < 100)
					continue;*/

				auto packet = (*it).second.first;

				if (packet.m_pkt_data == nullptr || packet.m_pheader == nullptr)
					continue;

				EtherHeader* pEther = (EtherHeader*)packet.m_pkt_data;
				IpHeader* pIpHeader = (IpHeader*)(packet.m_pkt_data + sizeof(EtherHeader));


				int ipHeaderLen = (pIpHeader->verIhl & 0x0F) * 4;
				TcpHeader* pTcp =
					(TcpHeader*)(packet.m_pkt_data + sizeof(EtherHeader) + ipHeaderLen);


				printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n",
					pIpHeader->srcIp[0], pIpHeader->srcIp[1],
					pIpHeader->srcIp[2], pIpHeader->srcIp[3],
					ntohs(pTcp->srcPort),
					pIpHeader->dstIp[0], pIpHeader->dstIp[1],
					pIpHeader->dstIp[2], pIpHeader->dstIp[3],
					ntohs(pTcp->dstPort)
				);

				int tcpHeaderSize = ((pTcp->data >> 4 & 0x0F) * 4);
				char* pPayload = (char*)(packet.m_pkt_data + sizeof(EtherHeader) +
					ipHeaderLen + tcpHeaderSize);

				int Segmentsize = ntohs(pIpHeader->length) - ipHeaderLen - tcpHeaderSize;
				printf("Segment size: %d(Frame length: %d)\n",
					Segmentsize,
					packet.m_pheader->len);


				//클라->서버 ,서버->클라, 클라->서버 ACK 보내는 마지막 패킷 캡쳐
				if (pTcp->flags == 0x010) // Flags 비트 값이 0x010 (ACK)일 경우에만 읽고 탐지
				{
					packet_Reset(pTcp, adhandle);
					blacklist_queue.push((*it).first);
				}
				it = local_IPList.erase(it);
				//if (Segmentsize == 0) //클라->서버 ,서버->클라, 클라->서버 ACK 보내는 마지막 패킷 캡쳐
				//{

				//	packet_Reset(pTcp, adhandle);

				//}
			}
			if (local_IPList.empty())
				Sleep(TIME_WAIT);
		}
	}

#else
	while (1)
	{
		Packet packet;
		if (PacketBuffer.try_pop(packet) == false)
			Sleep(1);
		else
		{
			/*



			*/			
			if (packet.m_pkt_data == nullptr || packet.m_pheader == nullptr)
				return;

			EtherHeader* pEther = (EtherHeader*)packet.m_pkt_data;
			IpHeader* pIpHeader = (IpHeader*)(packet.m_pkt_data + sizeof(EtherHeader));

			/*if (pEther->type != 0x0008)
				return;

			if (pIpHeader->protocol != 6)
				return;*/
			
			int ipHeaderLen = (pIpHeader->verIhl & 0x0F) * 4;
			TcpHeader* pTcp =
				(TcpHeader*)(packet.m_pkt_data + sizeof(EtherHeader) + ipHeaderLen);

			/*	if (ntohs(pTcp->srcPort) != 25000 &&
					ntohs(pTcp->dstPort) != 25000)
					return;*/

			printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n",
				pIpHeader->srcIp[0], pIpHeader->srcIp[1],
				pIpHeader->srcIp[2], pIpHeader->srcIp[3],
				ntohs(pTcp->srcPort),
				pIpHeader->dstIp[0], pIpHeader->dstIp[1],
				pIpHeader->dstIp[2], pIpHeader->dstIp[3],
				ntohs(pTcp->dstPort)
			);

			/*
				sourceIP 로 각 패킷 전송자 식별해서 저장
				해당 ip가 초당 몇개의 패킷을 전송하는지!
			
			*/
			/*string sIP;
			sIP.push_back(pIpHeader->srcIp[0]);
			sIP.push_back(pIpHeader->srcIp[1]);
			sIP.push_back(pIpHeader->srcIp[2]);
			sIP.push_back(pIpHeader->srcIp[3]);

			if (IPList.contains(sIP) == false)
				IPList.insert({ sIP,1 });
			else
			{
				IPList[sIP]++;

				 

			}*/
			int tcpHeaderSize = ((pTcp->data >> 4 & 0x0F) * 4);
			char* pPayload = (char*)(packet.m_pkt_data + sizeof(EtherHeader) +
				ipHeaderLen + tcpHeaderSize);

			int Segmentsize = ntohs(pIpHeader->length) - ipHeaderLen - tcpHeaderSize;
			printf("Segment size: %d(Frame length: %d)\n",
				Segmentsize,
				packet.m_pheader->len);

		/*	char szMessage[2048] = { 0 };
			memcpy_s(szMessage, sizeof(szMessage), pPayload,
				ntohs(pIpHeader->length) - ipHeaderLen - tcpHeaderSize);
			puts(szMessage);*/
			if(Segmentsize==0) //클라->서버 ,서버->클라, 클라->서버 ACK 보내는 마지막 패킷 캡쳐
				packet_Reset(pTcp,adhandle);

			/*char szMessage[2048] = { 0 };
			memcpy_s(szMessage, sizeof(szMessage), pPayload,
				ntohs(pIpHeader->length) - ipHeaderLen - tcpHeaderSize);
			puts(szMessage);*/

		}

	}
#endif // __Ver2__

}

void packet_handler(u_char* param,
	const struct pcap_pkthdr* header,
	const u_char* pkt_data)
{
	CaptureContext* ctx = (CaptureContext*)param;
	EtherHeader* pEther = (EtherHeader*)pkt_data;
	IpHeader* pIpHeader = (IpHeader*)(pkt_data + sizeof(EtherHeader));

	uint32_t src_ip = *(uint32_t*)(pIpHeader->srcIp);
	uint32_t ip{};

	int ipHeaderLen = (pIpHeader->verIhl & 0x0F) * 4;
	TcpHeader* pTcp = (TcpHeader*)(pkt_data + sizeof(EtherHeader) + ipHeaderLen);

	//이미 차단된 계정이 다시 접속을 시도할경우? 도 생각해서 차단해야함!	
	if (ctx->local_blacklist.contains(src_ip))
	{
		//차단된 계정이 다시 접속을 시도해 연결 수립하는 ack 패킷은 다시 캡쳐 후 탐지해서 차단!
		if (pTcp->flags != 0x010)
			return;

	}
	auto now = std::chrono::steady_clock::now();

	while (blacklist_queue.try_pop(ip))
	{	
		auto last_check_time = std::chrono::steady_clock::now();

		//1초이상 경과시 다음에 처리
		if (chrono::duration_cast<std::chrono::seconds>(now - last_check_time).count() >= 1)
		{
			break;
		}
		
		ctx->local_blacklist.insert(ip);				
	}


	if (pEther->type != 0x0008)
		return;

	if (pIpHeader->protocol != 6)
		return;
	
	if (pTcp->flags == 0x004) //RST 패킷, 즉 툴이 보내는 종료패킷은 제외!
		return;

	//if (pIpHeader->id == 0x3412)
	//	return; //툴 자신이 생성해 보낸 패킷은 제외!

	//일단 내 포트폴리오 게임서버 포트로 설정 ,클라는 각각 당연히 포트가 다를것.
	if (ntohs(pTcp->srcPort) != 25000 &&  ntohs(pTcp->dstPort) != 25000) //ntohs(pTcp->srcPort) != 25000 &&
		return;

	Packet data(const_cast<pcap_pkthdr*>(header), const_cast<u_char*>(pkt_data));

	int worker_index = src_ip % NUM_WORKER_THREADS;

	{
		std::lock_guard<mutex> lock(m1[worker_index]);
		if (worker_queues[worker_index].contains(src_ip))
		{
			//클라->서버 ,서버->클라, 클라->서버 ACK 보내는 마지막 패킷 캡쳐
			if (pTcp->flags == 0x010) // Flags 비트 값이 0x010 (ACK)일 경우에만 패킷데이터 업데이트!
			{

				worker_queues[worker_index][src_ip].first = data;
				worker_queues[worker_index][src_ip].second++;
			}
			else
			{
				// Flags 비트 값이 0x010 (ACK) 가 아닐 경우엔 카운트만 증가
				worker_queues[worker_index][src_ip].second++;
			}

		}
		else
		{

			worker_queues[worker_index].insert({ src_ip ,{data,1} });
		}

	}


#ifdef __VER2__
#else
	if (local_buffer.size() < 500)
		local_buffer.push_back(data);

	for (auto data : local_buffer)
		PacketBuffer.push(data);
	local_buffer.clear();
#endif // __VER2__

	/*char szMessage[2048] = { 0 };
	memcpy_s(szMessage, sizeof(szMessage), pPayload,
		ntohs(pIpHeader->length) - ipHeaderLen - tcpHeaderSize);
	puts(szMessage);*/
}
#endif

PcapManager PcapAdmin;

int main()
{


#ifdef __LINUX__
#else
	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		exit(1);
	}
#endif //__LINUX__
	if (PcapAdmin.SetDevice() == false)
	{
		return -1;
	}
	else
	{

		PacketMonitor pMonitor(PcapAdmin.GetConfig());
		pMonitor.Run();
		/*if (pMonitor.Initialize())
			pMonitor.Run();
		else
			return -1;*/


	}


#ifdef __OOP__
#else
	pcap_if_t* alldevs{};
	pcap_if_t* d{};
	int inum;
	int i = 0;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];

	Payloadlist.reserve(1000);
	worker_queues.resize(NUM_WORKER_THREADS);
	CaptureContext my_context;
#endif // __OOP__
	
#ifdef __OOP__
#else


	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure Npcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* Open the device */
	/* Open the adapter */



	//if ((adhandle = pcap_open_live(d->name,	// name of the device
	//	65536,			// portion of the packet to capture. 
	//	// 65536 grants that the whole packet will be captured on all the MACs.
	//	1,				// promiscuous mode (nonzero means promiscuous)
	//	1,			// read timeout , defaut= 1000
	//	errbuf			// error buffer
	//)) == NULL)
	//{
	//	fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Npcap\n", d->name);
	//	/* Free the device list */
	//	pcap_freealldevs(alldevs);
	//	return -1;
	//}


	/* 1. pcap_open_live 대신 pcap_create로 핸들을 생성합니다. */
	if ((adhandle = pcap_create(d->name, errbuf)) == NULL) {
		fprintf(stderr, "\nUnable to create the adapter handle. %s\n", d->name);
		pcap_freealldevs(alldevs);
		return -1;
	}
	// pcap 핸들 생성 후 활성화 전에 설정
	if (pcap_set_buffer_size(adhandle, 64 * 1024 * 1024) != 0) {
		fprintf(stderr, "Warning: Failed to set buffer size.\n");
	} // 64MB로 설정

	/* 3. 필요한 다른 설정을 합니다. */
	pcap_set_snaplen(adhandle, 65536); // 캡처할 패킷 부분 (스냅 길이)
	pcap_set_promisc(adhandle, 1);     // 무차별 모드
	pcap_set_timeout(adhandle, 1);     // 읽기 타임아웃 (1ms)


	/* 4. pcap_activate로 디바이스를 활성화합니다. */
	int activate_status = pcap_activate(adhandle);
	if (activate_status != 0) {
		// 활성화 실패 처리 (activate_status 값에 따라 에러 타입 확인 가능)
		fprintf(stderr, "\nUnable to activate the adapter. %s: %s\n", d->name, pcap_geterr(adhandle));
		pcap_close(adhandle);
		pcap_freealldevs(alldevs);
		return -1;
	}
	printf("\nlistening on %s...\n", d->description);

	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);



	// 커널 버퍼에 최소 16KB가 쌓일 때까지 리턴하지 않음 (Context Switching 감소)
	if (pcap_setmintocopy(adhandle, 16 * 1024) != 0) {
		fprintf(stderr, "Warning: pcap_setmintocopy failed.\n");
	}	/* start the capture */

	////캡쳐한 패킷 버퍼에서 뽑아내 추출하는 스레드풀 생성
	//const int threadCnt = std::thread::hardware_concurrency();
	std::vector<thread> ThreadPool;
	for (int i = 0; i < NUM_WORKER_THREADS; i++)
		ThreadPool.push_back(thread(packet_detect, i, PcapAdmin.GetHandle()));

	pcap_loop(const_cast<pcap_t*>(PcapAdmin.GetHandle()), 0, packet_handler, (u_char*)&my_context);

	for (int i = 0; i < NUM_WORKER_THREADS; i++)
		if (ThreadPool[i].joinable())
			ThreadPool[i].join();

	pcap_close(adhandle);
#endif // __OOP__
	return 0;
}
