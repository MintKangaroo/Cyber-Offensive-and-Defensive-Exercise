"""
NET-002 배포 - 네트워크 토폴로지를 그래프(JSON)로 표현. 노드=호스트, 엣지=허용된 방화벽 규칙.
실제 pcap/네트워크 장비 없이 세그멘테이션/피벗팅 개념을 그래프 탐색으로 훈련한다.
"""
import json

# 고정 토폴로지(모든 팀 공통 - 이 문제는 팀별 유니크 값이 필요 없음, 경로 자체가 답)
NETWORK_MAP = {
    "hosts": ["dmz", "web_frontend", "jump_host", "app_server", "internal_db", "backup_server"],
    "firewall_rules": [
        {"src": "dmz", "dst": "web_frontend", "allowed": True},
        {"src": "web_frontend", "dst": "app_server", "allowed": True},
        {"src": "dmz", "dst": "jump_host", "allowed": True},
        {"src": "jump_host", "dst": "app_server", "allowed": True},
        {"src": "app_server", "dst": "internal_db", "allowed": True},
        {"src": "dmz", "dst": "internal_db", "allowed": False},   # 직접 경로는 차단됨
        {"src": "web_frontend", "dst": "internal_db", "allowed": False},
        {"src": "app_server", "dst": "backup_server", "allowed": True},
    ],
    "start": "dmz",
    "target": "internal_db",
}


def generate_map(path: str) -> None:
    with open(path, "w") as f:
        json.dump(NETWORK_MAP, f, indent=2)


if __name__ == "__main__":
    generate_map("network_map.json")
    print("생성 완료: network_map.json")
