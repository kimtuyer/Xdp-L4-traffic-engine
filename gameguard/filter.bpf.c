#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

// 1. 블랙리스트 IP를 저장할 eBPF 맵 정의
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);        // 최대 1만개 IP 차단
    __uint(key_size, sizeof(__u32));   // IP 주소
    __uint(value_size, sizeof(__u32)); // 차단 여부 (보통 1)
} blacklist_map SEC(".maps");

SEC("xdp")
int xdp_filter_main(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // 2. 이더넷 헤더 파싱
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // 3. IPv4 패킷만 처리
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)(iph + 1);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    // ★ SSH(22) 포트로 가는 패킷은 블랙리스트 검사 전 무조건 통과
    if (tcp->dest == __constant_htons(22))
    {
        return XDP_PASS;
    }

    // 4. 블랙리스트 맵에서 소스 IP 조회
    __u32 src_ip = iph->saddr;
    __u32 *value = bpf_map_lookup_elem(&blacklist_map, &src_ip);

    if (value)
    {
        // ★ 마법의 구간: 블랙리스트에 있으면 유저모드로 안 보내고 즉시 삭제!
        return XDP_DROP;
    }

    // 정상 패킷은 기존대로 Netfilter 스택으로 보냄
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";