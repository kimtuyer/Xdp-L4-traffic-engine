#include "DataLoader.h"
#include <arpa/inet.h> // inet_pton 사용을 위해 필수
//#include <ws2tcpip.h> // inet_pton
#include <fstream>
#include <iostream>
#include <filesystem>
using json = nlohmann::json;

bool DataLoader::Load(const std::string& path, NetworkConfig& out_config) {
    std::ifstream file(path);

    std::cout << "현재 작업 경로: " << std::filesystem::current_path() << std::endl;

    if (!file.is_open()) {
        std::cerr << "[Config] 파일을 찾을 수 없습니다: " << path << std::endl;
        return false;
    }

    try {
        json j;
        file >> j; // 파싱 시작

        // 1. 서버 IP/Port 읽기
        out_config.server_ip_str = j["server_info"]["ip"];
        out_config.server_port = j["server_info"]["port"];

        //// 2. 클라 IP/Port 읽기
        //out_config.host_ip_str = j["host_info"]["ip"];
        //out_config.host_port = j["host_info"]["port"];

        // 문자열 IP -> uint32_t (Network Byte Order) 변환
        inet_pton(AF_INET, out_config.server_ip_str.c_str(), &out_config.server_ip_addr);

        //// 문자열 IP -> uint32_t (Network Byte Order) 변환
        //inet_pton(AF_INET, out_config.host_ip_str.c_str(), &out_config.host_ip_addr);

        // 2. MAC 주소 읽기
       /* out_config.src_mac_str = j["network_interface"]["src_mac"];*/
        out_config.gateway_mac_str = j["network_interface"]["gateway_mac"];

        // 문자열 MAC -> u_char[6] 변환
        //ParseMacAddress(out_config.src_mac_str, out_config.src_mac);
        ParseMacAddress(out_config.gateway_mac_str, out_config.gateway_mac);

        std::cout << "[Config] 설정 로드 완료!" << std::endl;
        return true;

    }
    catch (const json::exception& e) {
        std::cerr << "[Config] 파싱 에러: " << e.what() << std::endl;
        return false;
    }
}

void DataLoader::ParseMacAddress(const std::string& mac_str, u_char* out_mac) {
    // sscanf를 이용해 16진수 파싱
    unsigned int temp[6];
    if (sscanf(mac_str.c_str(), "%x:%x:%x:%x:%x:%x",
        &temp[0], &temp[1], &temp[2], &temp[3], &temp[4], &temp[5]) == 6) {

        for (int i = 0; i < 6; ++i) {
            out_mac[i] = (u_char)temp[i];
        }
    }
    else {
        std::cerr << "[Config] 잘못된 MAC 주소 형식: " << mac_str << std::endl;
    }
}