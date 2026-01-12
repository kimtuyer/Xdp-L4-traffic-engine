#include "PacketDetect.h"
#include <cinttypes>
// #include "Global.h"

PacketDetect::PacketDetect(SharedContext &context) : g_ctx(context)
{
    for (int i = 0; i < NUM_WORKER_THREADS; i++)
        ThreadPool.push_back(thread(&PacketDetect::packet_detect, this, i, PcapAdmin.GetHandle()));
}

PacketDetect::~PacketDetect()
{
    for (int i = 0; i < NUM_WORKER_THREADS; i++)
        if (ThreadPool[i].joinable())
            ThreadPool[i].join();
}

void PacketDetect::packet_detect(const int ThreadID, const pcap_t *adhandle)
{
    auto last_check_time = std::chrono::steady_clock::now();

    // int size = 500;
    unordered_map<uint32_t, pair<Packet, PacketCount>> local_IPList;
    unordered_map<uint32_t, pair<Packet, PacketCount>> accomulate_stat;

    auto &my_ctx = g_ctx.workers[ThreadID];

    while (bRunnig)
    {
        {
            std::unique_lock<std::mutex> lock(my_ctx->q_mutex);

            // (조건: 내 큐가 비어있지 않거나, 종료 신호가 왔을 때)
            my_ctx->q_cv.wait(lock, [&]
                              { return !my_ctx->packetlist.empty() || !bRunnig; });

            if (!bRunnig)
                break;

            // 1초 주기로 ip별 패킷 카운트 수 초기화
            auto now = std::chrono::steady_clock::now();
            if (chrono::duration_cast<std::chrono::seconds>(now - last_check_time).count() >= 1)
            {
                last_check_time = now;
                accomulate_stat.clear();
                my_ctx->mac_stat.clear();
            }
            // printf("--- 1초 경과: 카운트 리셋 ---\n");

            local_IPList.swap(my_ctx->packetlist);

            lock.unlock(); // 락 해제
        }

        for (auto [ip, data] : local_IPList)
        {
            accomulate_stat[ip].second.TotalCount += data.second.TotalCount;
            accomulate_stat[ip].second.syn_count += data.second.syn_count;

            auto packet = data.first;

            if (packet.m_pkt_data.empty())
                continue;

            accomulate_stat[ip].first = packet;

            u_char *raw_ptr = packet.m_pkt_data.data();

            // EtherHeader* pEther = (EtherHeader*)raw_ptr;
            IpHeader *pIpHeader = (IpHeader *)(raw_ptr + sizeof(EtherHeader));

            if (packet.m_pkt_data.size() < sizeof(EtherHeader) + 20)
            {
                continue; // 최소한의 IP 헤더 길이도 안 되면 패스
            }

            int ipHeaderLen = (pIpHeader->verIhl & 0x0F) * 4;
            TcpHeader *pTcp =
                (TcpHeader *)(raw_ptr + sizeof(EtherHeader) + ipHeaderLen);

            printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n",
                   pIpHeader->srcIp[0], pIpHeader->srcIp[1],
                   pIpHeader->srcIp[2], pIpHeader->srcIp[3],
                   ntohs(pTcp->srcPort),
                   pIpHeader->dstIp[0], pIpHeader->dstIp[1],
                   pIpHeader->dstIp[2], pIpHeader->dstIp[3],
                   ntohs(pTcp->dstPort));

            int tcpHeaderSize = ((pTcp->data >> 4 & 0x0F) * 4);
            // char* pPayload = (char*)(raw_ptr + sizeof(EtherHeader) +
            // 	ipHeaderLen + tcpHeaderSize);

            int Segmentsize = ntohs(pIpHeader->length) - ipHeaderLen - tcpHeaderSize;
            printf("Segment size: %d(Frame length: %d)\n",
                   Segmentsize,
                   packet.m_pheader.len);

            if (g_ctx.g_emergency_mode)
            {
                // SYN 패킷일 경우에 확인
                if (!(pTcp->flags & 0x02))
                    continue;

                // 1. 이미 검증된 IP인가? (Whitelist / Established)
                if (my_ctx->whitelist.contains(ip))
                {
                    continue; // 통과
                }

                // 2. 재전송 대기 목록(Greylist)에 있는가?
                if (my_ctx->greylist.contains(ip))
                {

                    my_ctx->greylist.erase(ip);   // 대기 목록에서 제거
                    my_ctx->whitelist.insert(ip); // 정식 유저로 승격
                    continue;                     // 통과 (서버가 처리하게 둠)
                }

                // 3. 처음 보는 IP인가? -> First Drop 실행
                else
                {
                    // [서버 보호] 서버에게 RST를 보내서 백로그 비우기
                    printf("Packet Reset Try!");
                    packet_Reset(pTcp, raw_ptr, adhandle);

                    // [대기열 등록] "너 한 번만 더 보내봐. 그럼 믿어줄게"
                    my_ctx->greylist[ip] = std::chrono::steady_clock::now();
                    continue;
                }
            }
            else
            {
                // [검사 1] SYN Flood 감지 (우선순위 높음)
                // TCP 헤더의  SYN Flag 검사
                if (accomulate_stat[ip].second.syn_count > 10)
                {
                    // 만약 syn_count > 20 -> BLACKLIST
                    packet_Reset(pTcp, raw_ptr, adhandle);
                    // ctx.blacklist_queue.push(ip);
                    local_blacklist.insert(ip);
                    continue;
                }

                // 클라->서버 ,서버->클라, 클라->서버 ACK 보내는 마지막 패킷 캡쳐
                if (pTcp->flags == 0x010) // Flags 비트 값이 0x010 (ACK)일 경우에만 읽고 탐지
                {
                    // [검사 2] 이미 블랙리스트 등록된 ip 감지
                    if (local_blacklist.contains(ip))
                    {
                        packet_Reset(pTcp, raw_ptr, adhandle);
                        // ctx.blacklist_queue.push(ip);
                        local_blacklist.insert(ip);
                        continue;
                    }
                    // [검사 3] 과도한 트래픽(DDoS) 감지
                    // if (accomulate_stat[ip].second.TotalCount > 100)
                    {
                        printf("Packet Reset Try!");

                        packet_Reset(pTcp, raw_ptr, adhandle);
                        // ctx.blacklist_queue.push(ip);
                        local_blacklist.insert(ip);
                        continue;
                    }
                }
            }
        }
        local_IPList.clear();

        // [검사 4] MAC 기반 SYN Flood 탐지 (IP Spoofing 방어)
        // 주의: 실제 환경에선 Gateway MAC일 수 있으므로 임계값을 아주 높게 잡거나,
        // 내부망 테스트용임을 인지해야 함.
        for (auto const &[macKey, count] : my_ctx->mac_stat)
        {
            if (count > 500) // 예: 한 MAC에서 초당 500개 이상? 수상함
            {
                // 해당 MAC에서 들어오는 모든 패킷 차단 로직 필요
                // 하지만 IP가 계속 바뀌므로 blacklist_queue(IP)에 넣는 건 의미가 없음.
                // 여기서는 "경고"를 띄우거나, "글로벌 방어 모드"를 켜는 트리거로 써야 함.
                // printf("[Warning] MAC Flood Detected! MAC: %lx, Count: %d\n", macKey, count);
                printf("[Warning] MAC Flood Detected! MAC: %" PRIx64 ", Count: %d\n", macKey, count);

                // ★ 대응 전략:
                // IP가 위조되었으므로 특정 IP를 차단하는 건 불가능.
                // 따라서 잠시동안 "모든 SYN 패킷"에 대해 엄격한 검사(SYN Cookie 등)를 수행하거나
                // 현재 테스트 환경이라면 해당 MAC을 블랙리스트에 등록할 수 있음.
            }
        }
    }
}

void PacketDetect::packet_Reset(const TcpHeader *pTcp, const u_char *pktdata, const pcap_t *adhandle)
{
    EtherHeader *pEther = (EtherHeader *)pktdata;
    IpHeader *pSrcIpHeader = (IpHeader *)(pktdata + sizeof(EtherHeader));

    unsigned char frameData[60] = {0}; // 최소 패킷 사이즈
    EtherHeader *pEtherHeader = (EtherHeader *)frameData;
    IpHeader *pIpHeader = (IpHeader *)(frameData + sizeof(EtherHeader));
    TcpHeader *pTcpHeader = (TcpHeader *)(frameData + sizeof(EtherHeader) + 20);

    // 1. Ethernet 설정: 나(VM) -> 클라이언트(Windows)
    memcpy(pEtherHeader->srcMac, g_ctx.config.gateway_mac, 6); // 내 리눅스 MAC
    memcpy(pEtherHeader->dstMac, pEther->srcMac, 6);          // 캡처된 패킷의 소스(클라) MAC
    pEtherHeader->type = htons(0x0800);

    // 2. IP 설정: 서버 -> 클라이언트
    pIpHeader->verIhl = 0x45;
    pIpHeader->length = htons(40);
    pIpHeader->protocol = 6;
    pIpHeader->ttl = 128;
    memcpy(pIpHeader->srcIp, &g_ctx.config.server_ip_addr, 4); // 서버 IP (가짜 출발지)
    memcpy(pIpHeader->dstIp, pSrcIpHeader->srcIp, 4);          // 클라이언트 IP
    pIpHeader->checksum = CalcChecksumIp(pIpHeader);

    // 3. TCP 설정 (가장 중요)
    pTcpHeader->srcPort = htons(g_ctx.config.server_port);     // 서버 포트
    pTcpHeader->dstPort = pTcp->srcPort;                       // 클라이언트 포트
    
    // 캡처한 패킷의 ACK를 나의 SEQ로 사용 (상대방이 기다리는 번호)
    pTcpHeader->seq = pTcp->ack; 
    pTcpHeader->ack = 0;
    pTcpHeader->data = 0x50; 
    pTcpHeader->flags = 0x04; // RST
    pTcpHeader->windowSize = 0;
    pTcpHeader->checksum = CalcChecksumTcp(pIpHeader, pTcpHeader);

    // 4. 전송
    pcap_sendpacket(const_cast<pcap_t *>(adhandle), frameData, 54);
//     EtherHeader *pEther = (EtherHeader *)pktdata;
//     IpHeader *pSrcIpHeader = (IpHeader *)(pktdata + sizeof(EtherHeader));

//     unsigned char frameData[1514] = {0};
//     IpHeader *pIpHeader = (IpHeader *)(frameData + sizeof(EtherHeader));
//     int ipHeaderLen = 20;

//     TcpHeader *pTcpHeader =
//         (TcpHeader *)(frameData + sizeof(EtherHeader) + ipHeaderLen);
//     EtherHeader *pEtherHeader = (EtherHeader *)frameData;
// #ifdef __DATA_LOADING__

//     // MAC 주소 설정
//     memcpy(pEtherHeader->srcMac, pEther->srcMac, 6);           // 패킷에 담긴 클라 mac 주소
//     memcpy(pEtherHeader->dstMac, g_ctx.config.gateway_mac, 6); // 전송할 서버 mac 주소

//     // IP 설정
//     // m_config.server_ip_addr은 이미 Network Order로 변환되어 있으므로 그대로 복사
//     memcpy(pIpHeader->dstIp, &g_ctx.config.server_ip_addr, 4);
//     memcpy(pIpHeader->srcIp, pSrcIpHeader->srcIp, 4);

//     // Port 설정
//     pTcpHeader->dstPort = htons(g_ctx.config.server_port);
// #else

//     int msgSize = 0;
//     pEtherHeader->dstMac[0] = 0x00;
//     pEtherHeader->dstMac[1] = 0x0C;
//     pEtherHeader->dstMac[2] = 0x29;
//     pEtherHeader->dstMac[3] = 0x72;
//     pEtherHeader->dstMac[4] = 0x01;
//     pEtherHeader->dstMac[5] = 0x51;

//     pEtherHeader->srcMac[0] = 0x00;
//     pEtherHeader->srcMac[1] = 0x50;
//     pEtherHeader->srcMac[2] = 0x56;
//     pEtherHeader->srcMac[3] = 0xC0;
//     pEtherHeader->srcMac[4] = 0x00;
//     pEtherHeader->srcMac[5] = 0x01;
// #endif // __DATA_LOADING__

//     pEtherHeader->type = htons(0x0800);

//     // IpHeader* pIpHeader = (IpHeader*)(frameData + sizeof(EtherHeader));
//     pIpHeader->verIhl = 0x45;
//     pIpHeader->tos = 0x00;
//     pIpHeader->length = htons(40);
//     pIpHeader->id = 0x3412;
//     pIpHeader->fragOffset = htons(0x4000); // DF
//     pIpHeader->ttl = 0xFF;
//     pIpHeader->protocol = 6; // TCP
//     pIpHeader->checksum = 0x0000;

// #ifdef __DATA_LOADING__
// #else
//     pIpHeader->srcIp[0] = 192;
//     pIpHeader->srcIp[1] = 168;
//     pIpHeader->srcIp[2] = 41;
//     pIpHeader->srcIp[3] = 1;

//     pIpHeader->dstIp[0] = 192;
//     pIpHeader->dstIp[1] = 168;
//     pIpHeader->dstIp[2] = 41;
//     pIpHeader->dstIp[3] = 128;
//     pTcpHeader->dstPort = htons(25000);
// #endif

//     pTcpHeader->srcPort = htons(ntohs(pTcp->srcPort)); // 반드시 일치
//     pTcpHeader->seq = (pTcp->seq);                     // 반드시 일치 , pTcp->seq 값은 이미 Net-order 순서이므로 변환없이 그대로 복사
//     pTcpHeader->ack = 0;
//     pTcpHeader->data = 0x50;
//     pTcpHeader->flags = 0x04; // RST
//     pTcpHeader->windowSize = 0;
//     pTcpHeader->checksum = 0x0000;
//     pTcpHeader->urgent = 0;

//     pIpHeader->checksum = CalcChecksumIp(pIpHeader);
//     pTcpHeader->checksum = CalcChecksumTcp(pIpHeader, pTcpHeader);

//     /* Send down the packet */
//     if (pcap_sendpacket(const_cast<pcap_t *>(adhandle), // Adapter
//                         frameData,                      // buffer with the packet
//                         sizeof(EtherHeader) + sizeof(IpHeader) + sizeof(TcpHeader)) != 0)
//     {
//         fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(const_cast<pcap_t *>(adhandle)));
//     }
}