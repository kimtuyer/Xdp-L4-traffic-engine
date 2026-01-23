# 1. 컴파일러 및 옵션
CC = gcc
CXX = g++
CLANG = clang
CFLAGS = -Wall -g -I/usr/include/cjson
CXXFLAGS = -Wall -g -std=c++20
# libbpf, libelf 등 필요한 라이브러리 링크
LDFLAGS = -lpcap -lpthread -lnetfilter_queue -lbpf -lelf -lcjson -lm

# 2. 빌드 대상 정의
C_TARGETS = open read fcntl epoll
CPP_TARGET = GameGuard
CHAT_TARGET = chatserver
BPF_TARGET = filter.bpf.o tc_rewrite.o  # TC용 바이트코드 추가

# 3. 소스 및 디렉토리 정의
GAMEGUARD_DIR = gameguard
GAMEGUARD_SRCS = $(wildcard $(GAMEGUARD_DIR)/*.cpp)
GAMEGUARD_OBJS = $(GAMEGUARD_SRCS:.cpp=.o)

# 4. 전체 빌드 규칙
all: $(BPF_TARGET) $(C_TARGETS) $(CPP_TARGET) $(CHAT_TARGET)

# [eBPF] 커널 코드 컴파일 규칙 (filter.bpf.c, tc_rewrite.c 둘 다 처리)
%.bpf.o: $(GAMEGUARD_DIR)/%.bpf.c
	$(CLANG) -O2 -g -target bpf -c $< -o $@

tc_rewrite.o: tc_rewrite.c
	$(CLANG) -O2 -g -target bpf -c $< -o $@

# [C] 기존 C 파일 빌드
$(C_TARGETS): %: %.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# [CPP] GameGuard 빌드 (여러 오브젝트 합치기)
$(CPP_TARGET): $(GAMEGUARD_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

# [CPP] chatserver 빌드 (단일 소스 빌드 가정)
$(CHAT_TARGET): chatserver.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

# .cpp 파일을 .o 파일로 만드는 일반 규칙
%.o: %.cpp $(GAMEGUARD_DIR)/define.h
	$(CXX) $(CXXFLAGS) -c -o $@ $<

# 클린업
clean:
	rm -f $(C_TARGETS) $(CPP_TARGET) $(CHAT_TARGET) $(BPF_TARGET) $(GAMEGUARD_DIR)/*.o *.o