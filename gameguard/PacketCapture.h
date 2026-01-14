#pragma once
#include "define.h"
#include "Global.h"
#include "PcapManager.h"
#include "DataLoader.h"
#include "SharedContext.h"
class PacketDetect;
class PacketCapture
{
public:
	PacketCapture(SharedContext &, PacketDetect *, int mode);
	~PacketCapture();

	void packet_capture(const struct pcap_pkthdr *header, const u_char *pkt_data);

	static void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
	void Run();

	void _RunPcap();
	static int nfq_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
							struct nfq_data *nfa, void *data);
	void _RunNetfilter(int queue_num);
    void SetupIptables(int num_queues, int port);
	void CleanupIptables();
	void _packet_AddSumCnt(unsigned char *pkt_data);

	bool LoadXDP(const char* bpf_file, const char* if_name);
	void UnloadXDP(const char* if_name);
	private:
	// set<uint32_t> local_blacklist;
	// std::vector<map<uint32_t, pair<Packet, int>>>& m_pWorker_queues;
	// concurrency::concurrent_queue<uint32_t>& m_pBlacklist_queue;
	// const NetworkConfig& m_config;
	SharedContext &ctx; // 참조
	bool bRunnig{true};
	int m_mode;
	PacketDetect *m_pDetect;
	std::vector<thread> ThreadPool;

};
