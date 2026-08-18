"""위성 우주 프로토콜 패키지(space) — 실 CCSDS Space Packet 기반 TT&C.

ground_station 트윈이 HTTP 목이 아니라 **진짜 CCSDS 를 말하는 위성 링크**가 되도록
Telemetry, Tracking & Command(TT&C) 프로토콜을 구현한다. 실 우주 표준(CCSDS 133.0-B)의
Space Packet 1차 헤더 비트 패킹을 정확히 따르므로, 표준을 아는 도구가 그대로 붙는다.
"""
