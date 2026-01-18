#include "PcapManager.h"

PcapManager::PcapManager()
{
}

PcapManager::~PcapManager()
{
    	pcap_close(adhandle);
}

bool PcapManager::SetDevice(char* selectDeviceName )
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *d{};
    pcap_if_t *alldevs{};
    int i = 0, inum = 0;

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
        return false;
    }

    printf("Enter the interface number (1-%d):", i);
    std::cin >> inum;
    // scanf_s("%d", &inum);

    if (inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* Jump to the selected adapter */
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    /* 찾은 드라이버 이름을 인자로 받은 버퍼에 복사 (예: ens33) */
    strcpy(selectDeviceName, d->name);

    return CreateHandle(d, alldevs, errbuf);
}

bool PcapManager::CreateHandle(const pcap_if_t *d, const pcap_if_t *alldevs, char errbuf[PCAP_ERRBUF_SIZE])
{
    /* 1. pcap_open_live 대신 pcap_create로 핸들을 생성합니다. */
    if ((adhandle = pcap_create(d->name, errbuf)) == NULL)
    {
        fprintf(stderr, "\nUnable to create the adapter handle. %s\n", d->name);
        pcap_freealldevs(const_cast<pcap_if_t *>(alldevs));
        return false;
    }
    // pcap 핸들 생성 후 활성화 전에 설정
    if (pcap_set_buffer_size(adhandle, 64 * 1024 * 1024) != 0)
    {
        fprintf(stderr, "Warning: Failed to set buffer size.\n");
    } // 64MB로 설정

    /* 3. 필요한 다른 설정을 합니다. */
    pcap_set_snaplen(adhandle, 65536); // 캡처할 패킷 부분 (스냅 길이)
    pcap_set_promisc(adhandle, 1);     // 무차별 모드
    pcap_set_timeout(adhandle, 1);     // 읽기 타임아웃 (1ms)
    pcap_set_immediate_mode(adhandle, 1);
    /* 4. pcap_activate로 디바이스를 활성화합니다. */
    int activate_status = pcap_activate(adhandle);
    if (activate_status != 0)
    {
        // 활성화 실패 처리 (activate_status 값에 따라 에러 타입 확인 가능)
        fprintf(stderr, "\nUnable to activate the adapter. %s: %s\n", d->name, pcap_geterr(adhandle));
        pcap_close(adhandle);
        pcap_freealldevs(const_cast<pcap_if_t *>(alldevs));
        return false;
    }
    printf("\nlistening on %s...\n", d->description);

    /* At this point, we don't need any more the device list. Free it */
    pcap_freealldevs(const_cast<pcap_if_t *>(alldevs));

    //// 커널 버퍼에 최소 16KB가 쌓일 때까지 리턴하지 않음 (Context Switching 감소)
    // if (pcap_setmintocopy(adhandle, 16 * 1024) != 0) {
    //	fprintf(stderr, "Warning: pcap_setmintocopy failed.\n");
    // }	/* start the capture */

    if (!DataLoader::Load("config.json", m_config))
    {
        printf("Can not Loading Config.json!");
        return false;
    }

    // struct bpf_program fcode;
    // std::string filter_exp = "tcp port " + std::to_string(m_config.server_port); // "tcp port 25000"

    //// 1. 필터 규칙 컴파일
    // if (pcap_compile(adhandle, &fcode, filter_exp.c_str(), 1, 0xffffff) < 0) {
    //	fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(adhandle));
    //	//fprintf(stderr, "Unable to compile packet filter. Check the syntax.\n");
    //	return false;
    // }

    //// 2. 필터 적용 (이 시점부터 25000번 포트가 아닌 패킷은 아예 handler로 안 넘어옴)
    // if (pcap_setfilter(adhandle, &fcode) < 0) {
    //	fprintf(stderr, "Error setting the filter.\n");
    //	return false;
    // }

    // printf("[Info] Kernel Filter Applied: %s\n", filter_exp.c_str());

    return true;
}

const NetworkConfig &PcapManager::GetConfig()
{
    	return m_config;
    // TODO: insert return statement here
}
