#pragma once
#include "define.h"
#include <nlohmann/json.hpp>
// 실제 패킷 변조에 사용할 바이너리 데이터와 원본 문자열을 모두 가짐
struct NetworkConfig {
    // 1. 서버 정보 (IP, Port)
    std::string server_ip_str;
    uint32_t server_ip_addr; // inet_pton으로 변환된 정수값 (Network Byte Order)
    uint16_t server_port;

    //std::string host_ip_str;
    //uint32_t host_ip_addr; // inet_pton으로 변환된 정수값 (Network Byte Order)
    //uint16_t host_port;


    // 2. 맥 주소 정보 (RST 패킷 만들 때 필수)
    //std::string src_mac_str; // 내 PC (Attacker)
    //u_char src_mac[6];

    std::string gateway_mac_str; // 공유기 or 서버
    u_char gateway_mac[6];

    // 3. 기타 설정
    std::string device_name; // 캡처할 장치 이름 (선택적)
};

class DataLoader
{
public:
	static bool Load(const std::string& path, NetworkConfig& out_config);
private:

	static void ParseMacAddress(const std::string& mac_str, u_char* out_mac);
};

