#pragma once
#include "define.h"
#include "Global.h"
#include "PcapManager.h"
#include "DataLoader.h"
#include "SharedContext.h"
class PacketCapture
{
public:

	PacketCapture(SharedContext&);
	~PacketCapture();

	void packet_capture(const struct pcap_pkthdr* header, const u_char* pkt_data);
	static void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
	void Run();

private:
	//set<uint32_t> local_blacklist;
	//std::vector<map<uint32_t, pair<Packet, int>>>& m_pWorker_queues;
	//concurrency::concurrent_queue<uint32_t>& m_pBlacklist_queue;
	//const NetworkConfig& m_config;
	SharedContext& ctx; // 참조
	bool bRunnig{ true };
};

