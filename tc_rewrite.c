#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/stddef.h> // offsetof를 위해 추가
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// 에러 방지를 위해 직접 정의 (IPPROTO_TCP는 보통 6입니다)
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
// Ethernet 프로토콜 번호 정의
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

static __always_inline void update_tcp_csum16(struct tcphdr *tcph, __u16 old_val, __u16 new_val)
{
    // TCP 체크섬은 1의 보수 합입니다.
    // 포트 번호가 바뀌었을 때의 차이만큼만 반영합니다.
    __u32 csum = bpf_ntohs(tcph->check);
    __u32 old_v = bpf_ntohs(old_val);
    __u32 new_v = bpf_ntohs(new_val);

    // RFC 1624 방식의 Incremental Update
    csum = ~csum & 0xFFFF;
    csum += ~old_v & 0xFFFF;
    csum += new_v;

    // 16비트 캐리 처리
    csum = (csum & 0xFFFF) + (csum >> 16);
    csum = (csum & 0xFFFF) + (csum >> 16);

    tcph->check = bpf_htons(~csum & 0xFFFF);
}
SEC("classifier")
int tc_egress_port_rewrite(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return BPF_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return BPF_OK;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return BPF_OK;

    if (iph->protocol != IPPROTO_TCP)
        return BPF_OK;

    struct tcphdr *tcph = (void *)(iph + 1);
    if ((void *)(tcph + 1) > data_end)
        return BPF_OK;

    if (tcph->source == bpf_htons(22) || tcph->dest == bpf_htons(22))
    {
        return BPF_OK;
    }

    // 서버 포트(25001~25004)가 출발지인 경우만 25000으로 변경
    __u16 src_port = bpf_ntohs(tcph->source);
    if (src_port >= 25001 && src_port <= 25004)
    {
        __u16 old_port = tcph->source;
        __u16 new_port = bpf_htons(25000);

        // 1. 포트 변경
        tcph->source = new_port;
        // TCP 체크섬 위치 오프셋 계산 (Ethernet + IP + TCP Checksum Offset)
        __u32 csum_off = sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct tcphdr, check);
        
        bpf_l4_csum_replace(skb, csum_off, old_port, new_port, sizeof(new_port));
        
        // update_tcp_csum16(tcph, old_port, new_port);

        // 커널에게 체크섬 재계산을 요청 (기존 체크섬을 0으로 밀어버림)
        // skb->ip_summed = CHECKSUM_NONE;
        // 2. TC는 L4 체크섬 보조 함수인 bpf_l4_csum_replace를 지원합니다.

        // 데이터 경계 확인 (안전한 접근을 위해)
        // if (data + csum_off + 2 > data_end)
        //   return BPF_OK;

        // 포트가 16비트(2바이트)이므로 BPF_F_MARK_MANGLED_0 플래그와 함께 사용
        // bpf_trace_printk("Port Rewritten: %d -> 25000\n", src_port);
    }

    return BPF_OK; // 패킷 통과
}

char _license[] SEC("license") = "GPL";