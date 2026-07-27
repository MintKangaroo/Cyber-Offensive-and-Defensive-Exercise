"""CI 프로브: 컨테이너 내에서 pp_twin:502 로 실제 Modbus FC3 읽기(트윈이 진짜 Modbus 를 말하는지)."""
import socket
import struct
import sys

s = socket.create_connection(("pp_twin", 502), timeout=5)
pdu = struct.pack(">BHH", 3, 0, 4)                       # FC3 read 4 holding regs
s.sendall(struct.pack(">HHHB", 1, 0, len(pdu) + 1, 1) + pdu)  # MBAP length = unit(1)+PDU
h = s.recv(7)
ln = struct.unpack(">HHHB", h)[2]
body = b""
while len(body) < ln - 1:
    body += s.recv(ln - 1 - len(body))
s.close()
vals = struct.unpack(">HHHH", body[2:])
print("pp_twin Modbus FC3 [RPM,FLOW,ACTUAL,TEMP] =", vals)
sys.exit(0 if vals[0] > 0 else 1)   # RPM > 0 이면 트윈이 정상 응답
