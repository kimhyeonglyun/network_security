#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "myheader.h"

// MAC 주소 출력 함수
void print_mac(u_char *mac)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// HTTP Payload 출력 함수
void print_http_message(const u_char *data, int len)
{
    if (len <= 0)
        return;

    printf("\n[HTTP Message]\n");

    // 출력 가능한 문자만 그대로 출력
    for (int i = 0; i < len; i++)
    {
        if (isprint(data[i]) || data[i] == '\n' ||
            data[i] == '\r' || data[i] == '\t')
            printf("%c", data[i]);
        else
            printf(".");
    }

    printf("\n");
}

// 패킷을 하나 수신할 때마다 호출되는 콜백 함수
void got_packet(u_char *args,
                const struct pcap_pkthdr *header,
                const u_char *packet)
{
    // Ethernet Header 추출
    struct ethheader *eth = (struct ethheader *)packet;

    // IP 패킷이 아니면 무시
    if (ntohs(eth->ether_type) != 0x0800)
        return;

    // IP Header 추출
    struct ipheader *ip =
        (struct ipheader *)(packet + sizeof(struct ethheader));

    // TCP 패킷만 처리
    if (ip->iph_protocol != IPPROTO_TCP)
        return;

    // IP Header 길이(byte)
    int ip_header_len = ip->iph_ihl * 4;

    // IP 패킷 전체 길이
    int ip_total_len = ntohs(ip->iph_len);

    // TCP Header 위치 계산
    struct tcpheader *tcp =
        (struct tcpheader *)(packet +
        sizeof(struct ethheader) +
        ip_header_len);

    // TCP Header 길이(byte)
    int tcp_header_len = TH_OFF(tcp) * 4;

    // HTTP Payload 길이 계산
    int tcp_payload_len =
        ip_total_len - ip_header_len - tcp_header_len;

    // HTTP Payload 시작 위치
    const u_char *payload =
        packet +
        sizeof(struct ethheader) +
        ip_header_len +
        tcp_header_len;

    printf("\n==============================\n");

    // Ethernet Header 출력
    printf("[Ethernet Header]\n");
    printf("Source MAC      : ");
    print_mac(eth->ether_shost);

    printf("\nDestination MAC : ");
    print_mac(eth->ether_dhost);
    printf("\n\n");

    // IP Header 출력
    printf("[IP Header]\n");
    printf("Source IP       : %s\n",
           inet_ntoa(ip->iph_sourceip));

    printf("Destination IP  : %s\n",
           inet_ntoa(ip->iph_destip));

    // TCP Header 출력
    printf("\n[TCP Header]\n");
    printf("Source Port     : %d\n",
           ntohs(tcp->tcp_sport));

    printf("Destination Port: %d\n",
           ntohs(tcp->tcp_dport));

    // HTTP(80, 8080)인 경우 Payload 출력
    if (ntohs(tcp->tcp_sport) == 80 ||
        ntohs(tcp->tcp_dport) == 80 ||
        ntohs(tcp->tcp_sport) == 8080 ||
        ntohs(tcp->tcp_dport) == 8080)
    {
        print_http_message(payload, tcp_payload_len);
    }

    printf("==============================\n");
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;

    // TCP 패킷만 캡처하도록 필터 설정
    char filter_exp[] = "tcp";

    bpf_u_int32 net = 0;

    // 네트워크 인터페이스 열기
    handle = pcap_open_live(
        "enp0s3",
        BUFSIZ,
        1,
        1000,
        errbuf);

    if (handle == NULL)
    {
        printf("%s\n", errbuf);
        return 1;
    }

    // 필터 컴파일
    pcap_compile(handle, &fp, filter_exp, 0, net);

    // 필터 적용
    if (pcap_setfilter(handle, &fp) != 0)
    {
        pcap_perror(handle, "Filter Error");
        return 1;
    }

    // 패킷을 계속 캡처하며 got_packet() 호출
    pcap_loop(handle, -1, got_packet, NULL);

    // 종료
    pcap_close(handle);

    return 0;
}