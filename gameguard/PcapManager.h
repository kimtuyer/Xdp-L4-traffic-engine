#pragma once
#include "define.h"
#include "DataLoader.h"

class PcapManager
{

public:
	PcapManager();
	~PcapManager();

	bool SetDevice();
	bool CreateHandle(const pcap_if_t* d, const pcap_if_t* alldevs, char errbuf[PCAP_ERRBUF_SIZE]);

	const NetworkConfig& GetConfig();
	
	const pcap_t* GetHandle()
	{
		return adhandle;
	}

	//const NetworkConfig GetConfig();


private:
	pcap_t* adhandle{};
	NetworkConfig m_config; // 설정 정보 저장소

};

