
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdbool.h>
#include <cjson/cJSON.h>
#include <pcap.h>
#include <iostream>
#include <cstdlib>
#include <csignal>
#if 0
  struct inotify_event{
  int wd;
  uint32_t mask;
  uint32_t cookie;
  uint32_t len;

  char name[];

  
  }

#endif

#define MAX_EVENTS 100
#pragma pack(push, 1)
typedef struct EtherHeader
{
    unsigned char dstMac[6];
    unsigned char srcMac[6];
    unsigned short type;
} EtherHeader;

typedef struct IpHeader
{
    unsigned char verIhl;
    unsigned char tos;
    unsigned short length;
    unsigned short id;
    unsigned short fragOffset;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short checksum;
    unsigned char srcIp[4];
    unsigned char dstIp[4];
} IpHeader;

typedef struct TcpHeader
{
    unsigned short srcPort;
    unsigned short dstPort;
    unsigned int seq;
    unsigned int ack;
    unsigned char data;
    unsigned char flags;
    unsigned short windowSize;
    unsigned short checksum;
    unsigned short urgent;
} TcpHeader;

typedef struct UdpHeader
{
    unsigned short srcPort;
    unsigned short dstPort;
    unsigned short length;
    unsigned short checksum;
} UdpHeader;

typedef struct PseudoHeader
{
    unsigned int srcIp;
    unsigned int dstIp;
    unsigned char zero;
    unsigned char protocol;
    unsigned short length;
} PseudoHeader;

#pragma pack(pop)

// 1. 구조체 정의 (C 스타일)
typedef struct
{
    uint16_t server_port1;
    uint16_t server_port2;
    uint16_t server_port3;
    uint16_t server_port4;
} ServerConfig;

// 파일을 읽어 버퍼에 저장하는 헬퍼 함수
char *read_file_to_string(const char *path)
{
    FILE *file = fopen(path, "rb");
    if (!file)
        return NULL;

    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *buffer = (char *)malloc(length + 1);
    if (buffer)
    {
        fread(buffer, 1, length, file);
        buffer[length] = '\0';
    }
    fclose(file);
    return buffer;
}

// 2. Load 함수 변환
bool LoadConfig(const char *path, ServerConfig *out_config)
{
    // C언어에서는 현재 경로 출력을 위해 별도의 OS 함수가 필요합니다 (예: getcwd)
    printf("[Config] 파일 로드 시도: %s\n", path);

    char *json_data = read_file_to_string(path);
    if (json_data == NULL)
    {
        fprintf(stderr, "[Config] 파일을 찾을 수 없습니다: %s\n", path);
        return false;
    }

    // JSON 파싱 시작
    cJSON *root = cJSON_Parse(json_data);
    if (root == NULL)
    {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL)
        {
            fprintf(stderr, "[Config] 파싱 에러: %s\n", error_ptr);
        }
        free(json_data);
        return false;
    }

    // 데이터 읽기 (serverport1)
    cJSON *port1 = cJSON_GetObjectItemCaseSensitive(root, "serverport1");
    if (cJSON_IsNumber(port1))
    {
        out_config->server_port1 = (uint16_t)port1->valueint;
    }
    // 데이터 읽기 (serverport1)
    port1 = cJSON_GetObjectItemCaseSensitive(root, "serverport2");
    if (cJSON_IsNumber(port1))
    {
        out_config->server_port2 = (uint16_t)port1->valueint;
    }
    // 데이터 읽기 (serverport1)
    port1 = cJSON_GetObjectItemCaseSensitive(root, "serverport3");
    if (cJSON_IsNumber(port1))
    {
        out_config->server_port3 = (uint16_t)port1->valueint;
    }
    // 데이터 읽기 (serverport1)
    port1 = cJSON_GetObjectItemCaseSensitive(root, "serverport4");
    if (cJSON_IsNumber(port1))
    {
        out_config->server_port4 = (uint16_t)port1->valueint;
    }

    // 정리
    cJSON_Delete(root);
    free(json_data);

    printf("[Config] 설정 로드 완료!\n");
    return true;
}

int SetListenSocket(int serverport)
{
    int listen_sock;
    struct sockaddr_in serv_addr;
    listen_sock = socket(AF_INET, SOCK_STREAM, 0);

    // 주소 재사용 설정 (서버 재시작 시 포트 점유 에러 방지)
    int opt = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(serverport); // 포트 번호

    if (bind(listen_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1)
    {
        perror("bind fail");
        exit(1);
    }
    listen(listen_sock, 5);

    return listen_sock;
}
void setnonblocking(int fd)
{
    int opts = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, opts | O_NONBLOCK);
}

// 서버 종료 시 TC 필터를 깨끗하게 지워주는 함수
void cleanupTC(int signum)
{
    std::cout << "\n[System] Cleaning up TC filters..." << std::endl;
    // egress 필터만 삭제
    system("sudo tc filter del dev ens33 egress");
    exit(signum);
}
int main(int args, char **argv)
{
    // int fd = -1;
    // int wd1 = -1;
    // int wd2 = -1;

    // 1. 종료 시그널 등록 (Ctrl+C 등 클릭 시 cleanupTC 호출)
    signal(SIGINT, cleanupTC);
    signal(SIGTERM, cleanupTC);

    // 2. TC 로드 (시스템 명령어를 활용해 효율적으로 로드)
    std::cout << "[System] Loading TC Egress Rewrite Program..." << std::endl;

    // 기존에 설정되어 있을지 모를 qdisc와 filter 초기화
    system("sudo tc qdisc del dev ens33 clsact 2> /dev/null");

    // clsact 추가 및 필터 등록
    if (system("sudo tc qdisc add dev ens33 clsact") != 0 ||
        system("sudo tc filter add dev ens33 egress bpf obj tc_rewrite.o sec classifier") != 0)
    {
        std::cerr << "[Error] Failed to load TC program. Check sudo privileges." << std::endl;
        return 1;
    }

    std::cout << "[System] TC Program Loaded. Starting Chat Server..." << std::endl;

    int serverNumber = 0, serverport;
    ServerConfig serverConfig;

    printf("Server Number Input(1~4): ");
    fflush(stdout); // 입력을 받기 전 출력 버퍼를 비워 화면에 즉시 표시
    scanf("%d", &serverNumber);

    if (LoadConfig("serverinfo.json", &serverConfig) == false)
    {
        printf("Load Config Fail!\n");
        return -1;
    }
    else
    {
        switch (serverNumber)
        {
        case 1:
            serverport = serverConfig.server_port1;
            break;
        case 2:
            serverport = serverConfig.server_port2;
            break;
        case 3:
            serverport = serverConfig.server_port3;
            break;
        case 4:
            serverport = serverConfig.server_port4;
            break;

        default:
            break;
        }
    }

    char buf[1024];
    int ret;
    int epfd;
    struct epoll_event ev, events[MAX_EVENTS];
    int listen_sock, conn_sock, connectList[MAX_EVENTS];

    memset(connectList, 0, sizeof(connectList));
    listen_sock = SetListenSocket(serverport);
    printf("Chat Server Listening on Port %d\n", serverport);
    setnonblocking(listen_sock);

    struct sockaddr_in client_addr;
    socklen_t addrlen = sizeof(client_addr);

    epfd = epoll_create1(0);
    if (epfd == -1)
    {

        perror("epoll_create1 fail!");
        exit(EXIT_FAILURE);
    }

    ev.events = EPOLLIN;
    ev.data.fd = listen_sock;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, listen_sock, &ev) == -1)
    {
        perror("epoll_ctl: listen_sock");
        exit(EXIT_FAILURE);
    }

    int connectCnt = 0;
    while (1)
    {
        ret = epoll_wait(epfd, events, MAX_EVENTS, -1);

        for (int n = 0; n < ret; ++n)
        {
            if (events[n].data.fd == listen_sock)
            {
                if (MAX_EVENTS == connectCnt)
                {
                    perror("Don't connect Max User");
                    continue;
                }
                while (1)
                {
                    conn_sock = accept(listen_sock, (struct sockaddr *)&client_addr, &addrlen);
                    if (conn_sock > 0)
                    {
                        setnonblocking(conn_sock);
                        ev.events = EPOLLIN | EPOLLET;
                        ev.data.fd = conn_sock;
                        if (epoll_ctl(epfd, EPOLL_CTL_ADD, conn_sock,
                                      &ev) == -1)
                        {
                            perror("epoll_ctl: conn_sock");
                            exit(EXIT_FAILURE);
                        }
                        dprintf(conn_sock, "Welcome to My Epoll Server! Your FD is %d\n", conn_sock);
                        connectList[connectCnt] = conn_sock;
                        connectCnt++;
                    }
                    else
                    {
                        // 더 이상 접속한 사람이 없을 때 (EAGAIN) 루프 탈출
                        if (errno == EAGAIN || errno == EWOULDBLOCK)
                            break;

                        perror("accept error");
                        break;
                    }
                }
            }
            else
            {
                // 데이터 수신 처리 (read)
                int client_fd = events[n].data.fd;
                while (1)
                {
                    int nread = read(client_fd, buf, sizeof(buf));
                    if (nread > 0)
                    {
                        // 수신 데이터 처리 (예: 에코)
                        // 포맷 스트링 %s를 사용하여 안전하게 출력
                        printf("[Client %d] Message: %s\n", client_fd, buf);
                        dprintf(client_fd, "<<< :");
                        write(client_fd, buf, nread);

                        for (int n = 0; n < connectCnt; ++n)
                        {
                            int otherclient_fd = connectList[n];
                            if (client_fd == otherclient_fd)
                                continue;
                            dprintf(otherclient_fd, "<<< :");

                            write(otherclient_fd, buf, nread);
                        }
                    }
                    else if (nread == 0)
                    {
                        // 연결 종료 처리
                        close(client_fd);
                        if (client_fd < 0 || client_fd > MAX_EVENTS - 1)
                        {
                            perror("close error");
                            break;
                        }
                        printf("Client :%d connect close", client_fd);

                        for (int n = 0; n < connectCnt; ++n)
                        {
                            if (connectList[n] == client_fd)
                            {

                                connectList[n] = 0;
                                connectList[n] = connectList[connectCnt - 1];
                                connectList[connectCnt - 1] = 0;
                                connectCnt--;
                                break;
                            }
                            else
                                perror("Not Find client_fd error");
                        }

                        break;
                    }
                    else
                    {
                        if (errno == EAGAIN)
                            break; // 다 읽었음
                        perror("read error");
                        close(client_fd);
                        break;
                    }
                }
            }
        }
    }
}
