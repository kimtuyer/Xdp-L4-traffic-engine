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
	PacketMonitor(const NetworkConfig& config,int mode);
	~PacketMonitor();

	bool Initialize();
	void Run();

	bool LoadXDP(const char* bpf_file, const char* if_name);
	void UnloadXDP(const char* if_name);
    static void signal_handler(int signal);
	

private:
     static PacketMonitor* instance;
	//const NetworkConfig& m_config; // 설정 정보 저장소
	set<uint32_t> local_blacklist;

	unique_ptr<PacketCapture> m_packetCapture;
	unique_ptr<PacketCapture> m_netfilterCapture;

	unique_ptr<PacketDetect> m_packetDetect;

	bool bRunnig{true};

	unique_ptr<SharedContext> m_context;
	bpf_object* m_bpf_obj;

	int m_mode{0};
};

