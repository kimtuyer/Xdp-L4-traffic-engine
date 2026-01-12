
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

void BroadCasting()
{
}
int SetListenSocket()
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
    serv_addr.sin_port = htons(25000); // 포트 번호

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
int main(int args, char **argv)
{
    // int fd = -1;
    // int wd1 = -1;
    // int wd2 = -1;
    char buf[1024];
    int ret;
    int epfd;
    struct epoll_event ev, events[MAX_EVENTS];
    int listen_sock, conn_sock, connectList[MAX_EVENTS];

    memset(connectList, 0, sizeof(connectList));
    listen_sock = SetListenSocket();
    setnonblocking(listen_sock);

    struct sockaddr_in client_addr;
    socklen_t addrlen = sizeof(client_addr);
    // fd=inotify_init();
    // if(fd==-1)
    // {
    //     printf("fail\n");
    //     return -1;
    // }
    // wd1=inotify_add_watch(fd,".", IN_CREATE | IN_DELETE);
    // wd2=inotify_add_watch(fd,"../file_basic", IN_CREATE | IN_DELETE);

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
