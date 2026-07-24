# NET-004 방어 노트 (Blue)

## 무슨 일이 있었나
공격자가 게이트웨이 IP(`10.0.0.1`)를 자신의 MAC으로 ARP announce 해 캐시를 오염시켰다
(ATT&CK **T1557** Adversary-in-the-Middle). 결과적으로 같은 IP가 두 MAC에서 관측된다.

## 탐지
- **IP↔MAC 1:N 이상 징후**: 하나의 IP(특히 게이트웨이)를 여러 MAC이 주장하면 스푸핑.
- **Gratuitous ARP 급증**: 요청 없는 ARP reply가 반복되면 의심.
- 공격자는 보통 자기 원래 IP도 남기므로, 게이트웨이를 주장하는 MAC이 다른 IP도 가진 경우가 단서.

## 완화
- **Dynamic ARP Inspection(DAI)** + DHCP snooping으로 스위치에서 위조 ARP 차단.
- 중요 자산에 **static ARP** 엔트리, 포트 보안(MAC 제한).
