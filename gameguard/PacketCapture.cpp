#include "PacketCapture.h"
//#include "Global.h"

PacketCapture::PacketCapture(SharedContext& context):ctx(context)
{
}
PacketCapture::~PacketCapture()
{
}

void PacketCapture::packet_capture(const pcap_pkthdr* header, const u_char* pkt_data)
{
	//CaptureContext* ctx = (CaptureContext*)param;
	EtherHeader* pEther = (EtherHeader*)pkt_data;
	IpHeader* pIpHeader = (IpHeader*)(pkt_data + sizeof(EtherHeader));

	uint32_t src_ip = *(uint32_t*)(pIpHeader->srcIp);
	//uint32_t ip{};
	uint64_t srcMacKey = MacToUint64(pEther->srcMac); // MAC -> uint64 변환

	int ipHeaderLen = (pIpHeader->verIhl & 0x0F) * 4;
	TcpHeader* pTcp = (TcpHeader*)(pkt_data + sizeof(EtherHeader) + ipHeaderLen);

	if (ctx.g_syn_count < 5000)
	{
		// ACK 비율 확인
		if (ctx.g_ack_count < (ctx.g_syn_count * 0.1))
		{
			// SYN은 3000개인데 ACK가 300개도 안 옴 -> 공격 의심!
			// First Packet Drop 모드 ON
			ctx.g_emergency_mode = true;
		}


	}
	////이미 차단된 계정이 다시 접속을 시도할경우? 도 생각해서 차단해야함!
	//if (local_blacklist.contains(src_ip))
	//{
	//	//차단된 계정이 다시 접속을 시도해 연결 수립하는 ack 패킷은 다시 캡쳐 후 탐지해서 차단!
	//	//syn 패킷 공격을 할 경우도 고려해야함.		
	//	if (pTcp->flags != 0x010)
	//	{
	//		if (!(pTcp->flags & 0x02))
	//		{

	//		}
	//		else
	//			return;
	//	}
	//}
	//auto now = std::chrono::steady_clock::now();

	//while (ctx.blacklist_queue.try_pop(ip))
	//{
	//	auto last_check_time = std::chrono::steady_clock::now();

	//	//1초이상 경과시 다음에 처리
	//	if (chrono::duration_cast<std::chrono::seconds>(now - last_check_time).count() >= 1)
	//	{
	//		break;
	//	}

	//	local_blacklist.insert(ip);
	//}

	if (pEther->type != 0x0008)
		return;

	if (pIpHeader->protocol != 6)
		return;

	if (pTcp->flags == 0x004) //RST 패킷, 즉 툴이 보내는 종료패킷은 제외!
		return;

	//if (pIpHeader->id == 0x3412)
	//	return; //툴 자신이 생성해 보낸 패킷은 제외!

	//일단 내 포트폴리오 게임서버 포트로 설정 ,클라는 각각 당연히 포트가 다를것.
	if (ntohs(pTcp->srcPort) != ctx.config.server_port && ntohs(pTcp->dstPort) != ctx.config.server_port) //ntohs(pTcp->srcPort) != 25000 &&
		return;

	Packet data(const_cast<pcap_pkthdr*>(header), const_cast<u_char*>(pkt_data));

	int worker_index = src_ip % NUM_WORKER_THREADS;
	auto& target_worker = ctx.workers[worker_index];

	int syn_count = (pTcp->flags & 0x02) ? 1 : 0;
	int ack_count = (pTcp->flags == 0x010) ? 1 : 0;

	if (syn_count == 1)
		ctx.g_syn_count++;
	if (ack_count == 1)
		ctx.g_ack_count++;
	{
		std::lock_guard<mutex> lock(target_worker->q_mutex);
		if (target_worker->packetlist.contains(src_ip))
		{
			target_worker->packetlist[src_ip].second.TotalCount++;

			//클라->서버 ,서버->클라, 클라->서버 ACK 보내는 마지막 패킷 캡쳐
			if (ack_count==1) // Flags 비트 값이 0x010 (ACK)일 경우에만 패킷데이터 업데이트!
			{
				target_worker->packetlist[src_ip].first = data;
			}
			else if (syn_count==1) //SYN Flag , SYN Flood 고려
			{
				target_worker->packetlist[src_ip].second.syn_count++;

			}		
		}
		else
		{							
			target_worker->packetlist.insert({ src_ip ,{data,PacketCount(1,syn_count)}});
		}

		// 2. ★ MAC 기반 카운팅 추가 ★
		target_worker->mac_stat[srcMacKey]++;
	}
	target_worker->q_cv.notify_one();
}

void PacketCapture::packet_handler(u_char* user, const pcap_pkthdr* header, const u_char* pkt_data)
{
	// user로 들어온 포인터를 PacketMonitor 클래스 포인터로 캐스팅
	PacketCapture* self = reinterpret_cast<PacketCapture*>(user);

	// 실제 멤버 함수 호출
	self->packet_capture(header, pkt_data);
}

void PacketCapture::Run()
{
	pcap_loop(const_cast<pcap_t*>(PcapAdmin.GetHandle()), 0, packet_handler, (u_char*)this);

}
