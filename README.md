# BPFDoor POC

2025 SKT 해킹 사고 악성코드 BPFDoor 실습위한 악성코드

환경

| 역할 | 운영체제 | 파일명 |
|------|----------|--------|
| **공격자** | Kali | client.py |
| **피해자** | Ubuntu | bpfdoorpoc.c |

## BPF(Berkely Packet Filter)

BPF(Berkely Packet Filter)는 리눅스 커널 레벨에서 네트워크 패킷을 효율적으로 필터링하여 사용자 영역으로 전달하는 인터페이스다. 네트워크 보안과 성능 향상을 위한 도구로 많이 사용되며, 최근 악성코드가 이를 악용해 주목받고 있다.

## BPFDoor

BPFDoor는 BPF의 기능을 악용한 악성코드로, 커널 수준에서 특정 공격자의 패킷만 선별적으로 수신하도록 설정하여 로컬 방화벽을 우회하는 데 사용된다.

## 동작 방식

| 단계 | 설명 |
|------|------|
| **Raw Socket 생성** | 커널 내부에서 네트워크 인터페이스 수준의 패킷 직접 수신 |
| **BPF 필터 등록** | 커널에 BPF 조건(예: magic packet 조건)을 등록 |
| **Magic Packet 수신** | 특정 식별자(magic header/salt/hash)가 있는 패킷을 raw socket 통신으로 수신 |
| **패킷 프로토콜 구분** | IP header의 protocol 필드를 보고 TCP/UDP/ICMP 분기 |
| **MD5 + salt 비교** | 공격자의 유효 패킷인지 해시로 추가 검증 |
| **백도어 실행** | 리버스쉘, 바인드쉘, 모니터링 등 기능 실행 |

## Raw Socket

Raw Socket은 네트워크 인터페이스 카드(NIC)에서 직접 네트워크 패킷을 수신할 수 있게 하는 소켓 방식이다. 일반적인 TCP/IP 스택을 거치지 않고 직접 NIC 수준에서 패킷을 처리하므로 운영체제의 방화벽 규칙에 영향을 받지 않는다.

## Why Raw Socket?

일반적인 네트워크 애플리케이션은 SOCK_STREAM 또는 SOCK_DGRAM 소켓을 사용할 때, 운영체제의 방화벽(iptables, ufw, selinux) 규칙을 따라야 한다. 하지만 Raw Socket은 커널 레벨에서 생성되며, 방화벽 규칙에 구애받지 않고 모든 NIC 트래픽을 직접 감시할 수 있어, 공격자의 입장에서는 매우 효과적인 침투 수단이 된다.

## Magic Packet 

Magic Packet은 특정한 형식의 패킷으로, 공격자만이 식별할 수 있는 구조를 가진다. 이는 일반적인 로그나 방화벽 필터링에서 탐지되지 않아 은밀한 침투에 이상적인 수단이다.


일반적인 SYN ACK 패킷은 정상적인 TCP 연결 과정에서 사용되며 방화벽과 시스템 로그에 남아 탐지된다. 반면, Magic Packet은 특수한 구조와 Raw Socket을 활용하여 커널 레벨에서 처리되기 때문에 일반적인 방화벽 및 시스템 로그에서 탐지되지 않는다.

이 차이는 Raw Socket의 특성과 BPF의 선택적 필터링 기능 덕분이다. Magic Packet은 커널 수준에서 직접 패킷을 수신하므로 TCP/IP 스택이나 방화벽 규칙을 우회할 수 있어 탐지되지 않는 것이다.

## Magic Packet의 구성


Magic Packet Payload 구조:

[marker] + [공격자 IP] + [MD5(salt + 공격자IP)]

marker는 구분자로 기능하며, IP 문자열과 salt를 결합한 후 MD5로 해싱하여 유효성을 검증하는 데 사용된다.

## 피해자 서버의 동작 과정

```
int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
```

- 이 소켓은 Ethernet 프레임 전체를 수신
- 커널의 TCP/IP 스택을 거치지 않고 직접 패킷 수신 가능

## 악성코드로 악용된 BPF 필터 설정

```
void apply_bpf_filter(int sd) {
 struct sock_filter filter[] = {
...
        //IPv6 UDP dest port 위치
      { 0x28, 0, 0, 0x00000038 },       

        //dest port == 53 → ACCEPT
      { 0x15, 8, 9, 0x00000035 },       

      //IP 프로토콜 위치 (IPv4: 23번), UDP = 17
     { 0x30, 0, 0, 0x00000017 },       

      //ACCEPT (return 262144 bytes)
    { 0x6, 0, 0, 0x00040000 },      
  
     //DROP
       { 0x6, 0, 0, 0x00000000 },        // ret #0
   };
```

- BPF 필터는 "Magic Packet "을 판별
- 특정 포트(53 Port), 특정 바이트(9999), IP 프로토콜 등 포함
- Magic Packet 판별 조건이  참(True)일 경우 리버스쉘 실행

## 공격 Payload 생성(Magic Packet)

```
payload = "9999" + 공격자IP + MD5(salt + 공격자IP);
unsigned char *magic = MD5(payload); // 유효성 인증값 생성
```

- 9999: Magic Packet 식별값(marker)
- 공격자IP 및 인증 해시 포함
- packet payload를 salt와 조합해 인증 역할 수행
- 공격자만 리버스쉘에 접근하게 MD5 + salt 값을 설정

##  BPFDoor 공격 흐름도

![1-7](https://github.com/user-attachments/assets/f92c1406-c23a-40e9-b00d-4f28f445dd14)


## 대응 방안

BPF Filter 및 Raw Socket 점검

```
sudo ss -0bp | grep -E "smartd|hald-addon|dbus-daemon|hpas"
```

Magic Packet 필터 여부 확인
```
sudo ss -0pb | grep -E "0xnumbers"
```

리스닝 포트 비정상 여부 점검
```
nestat -lncp
```

