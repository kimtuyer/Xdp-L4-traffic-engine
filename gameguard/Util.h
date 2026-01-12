#pragma once
#include "define.h"
#include <cstring> // memcpy 사용을 위해 필수
#include <cstdint> // uint32_t 사용을 위해 필수

inline uint64_t MacToUint64(const u_char *mac)
{
    uint64_t result = 0;
    // MAC 주소 6바이트를 복사 (하위 6바이트 사용)
    memcpy(&result, mac, 6);
    return result;
}

inline unsigned short CalcChecksumIp(IpHeader *pIpHeader)
{
    unsigned char ihl = (pIpHeader->verIhl & 0x0F) << 2; //*4와 동일
    unsigned short wData[30] = {0};
    unsigned int dwSum = 0;

    std::memcpy(wData, (unsigned char *)pIpHeader, ihl); // BYTE 대신 unsigned char
    //((IpHeader*)wData)->checksum = 0x0000;

    for (int i = 0; i < ihl / 2; i++)
    {
        if (i != 5)
            dwSum += wData[i];

        if (dwSum & 0xFFFF0000)
        {
            dwSum &= 0x0000FFFF;
            dwSum++;
        }
    }

    return ~(dwSum & 0x0000FFFF);
}

inline unsigned short CalcChecksumTcp(IpHeader *pIpHeader, TcpHeader *pTcpHeader)
{
    PseudoHeader pseudoHeader = {0};
    unsigned short *pwPseudoHeader = (unsigned short *)&pseudoHeader;
    unsigned short *pwDatagram = (unsigned short *)pTcpHeader;
    int nPseudoHeaderSize = 6; // WORD 6개 배열
    int nSegmentSize = 0;      // 헤더 포함

    uint32_t dwSum = 0;
    int nLengthOfArray = 0;

    pseudoHeader.srcIp = *(unsigned int *)pIpHeader->srcIp;
    pseudoHeader.dstIp = *(unsigned int *)pIpHeader->dstIp;
    pseudoHeader.zero = 0;
    pseudoHeader.protocol = 6;
    pseudoHeader.length = htons(ntohs(pIpHeader->length) - 20);

    nSegmentSize = ntohs(pseudoHeader.length);

    if (nSegmentSize % 2)
        nLengthOfArray = nSegmentSize / 2 + 1;
    else
        nLengthOfArray = nSegmentSize / 2;

    for (int i = 0; i < nPseudoHeaderSize; i++)
    {
        dwSum += pwPseudoHeader[i];
        if (dwSum & 0xFFFF0000)
        {
            dwSum &= 0x0000FFFF;
            dwSum++;
        }
    }

    for (int i = 0; i < nLengthOfArray; i++)
    {
        if (i != 8)
            dwSum += pwDatagram[i];
        if (dwSum & 0xFFFF0000)
        {
            dwSum &= 0x0000FFFF;
            dwSum++;
        }
    }

    return (unsigned short)~(dwSum & 0x0000FFFF); // USHORT 대신 unsigned short
}