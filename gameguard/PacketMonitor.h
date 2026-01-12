#pragma once
#include "define.h"
#include "PcapManager.h"
#include "DataLoader.h"
#include "SharedContext.h"

class PacketDetect;
class PacketCapture;
class PacketMonitor
{
public:

	//PacketMonitor();
	PacketMonitor(const NetworkConfig& config);
	~PacketMonitor();

	bool Initialize();
	void Run();

	

private:
	//const NetworkConfig& m_config; // 설정 정보 저장소
	set<uint32_t> local_blacklist;

	//mutex m1[NUM_WORKER_THREADS];


	/*std::vector<map<uint32_t, pair<Packet, int>>> worker_queues;
	concurrency::concurrent_queue<uint32_t> blacklist_queue;*/

	unique_ptr<PacketCapture> m_packetCapture;
	unique_ptr<PacketDetect> m_packetDetect;

	bool bRunnig{true};

	unique_ptr<SharedContext> m_context;
};

