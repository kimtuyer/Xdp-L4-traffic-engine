# 1. 컴파일러 및 옵션
CC = gcc
CXX = g++
CFLAGS = -Wall -g
CXXFLAGS = -Wall -g -std=c++20
LDFLAGS = -lpcap -lpthread

# 2. 빌드 대상 정의
C_TARGETS = open read fcntl epoll
CPP_TARGET = GameGuard

# 3. gameguard 폴더 내 소스 파일들
# 폴더 경로를 명시하여 빌드 대상에 포함합니다.
GAMEGUARD_DIR = gameguard
GAMEGUARD_SRCS = $(wildcard $(GAMEGUARD_DIR)/*.cpp)
GAMEGUARD_OBJS = $(GAMEGUARD_SRCS:.cpp=.o)

all: $(C_TARGETS) $(CPP_TARGET)

# 기존 C 파일 빌드 (패턴 매칭)
$(C_TARGETS): %: %.c
	$(CC) $(CFLAGS) -o $@ $<

# GameGuardian 빌드
$(CPP_TARGET): $(GAMEGUARD_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

# .cpp 파일을 .o 파일로 만드는 규칙
%.o: %.cpp gameguard/define.h
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f $(C_TARGETS) $(CPP_TARGET) $(GAMEGUARD_DIR)/*.o *.o