"""WEB-009 배포용 취약 서비스 - 블랙리스트 WAF 우회 + 블라인드 SQL 인젝션.

/api/product?id= 는 정수 컨텍스트로 SQL 에 그대로 삽입된다. 앞단의 문자 블랙리스트 WAF가
공백/따옴표/`=`/`;`/`--`/`#` 등을 막으므로 순진한 페이로드(`1' OR '1'='1`, `1 AND ...`)는
400 으로 거부된다. 응답은 {"found": true/false} 뿐이라 출력이 없다(블라인드 불리언).

우회: 공백은 인라인 주석 `/**/`, 비교는 `=` 대신 `>`, 문자열 리터럴 없이 컬럼 함수
(unicode/substr)로 플래그를 한 글자씩 이진탐색해 추출한다.

PATCH_WEB_009=true 면 파라미터 바인딩 + 정수 검증으로 안전화된다.
플래그는 CHALLENGE_SECRET 기반 정적 값으로 secrets 테이블 token 컬럼에 저장된다.
"""
import hashlib
import os
import sqlite3
from fastapi import FastAPI, HTTPException

app = FastAPI(title="WEB-009 Challenge Deploy (TRAINING ONLY)")

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요.")
PATCHED = os.environ.get("PATCH_WEB_009", "false").lower() == "true"
DB_PATH = os.environ.get("DB_PATH", "/app/chal.db")

# 문자 블랙리스트 WAF: 순진한 SQLi 문법을 차단(대소문자 무시).
WAF_BLOCKED = [" ", "\t", "\n", "\r", "'", '"', "=", ";", "--", "#", "\\"]


def static_flag() -> str:
    sig = hashlib.sha256(f"WEB-009:{CHALLENGE_SECRET}".encode()).hexdigest()[:16]
    return f"flag{{waf_blind_sqli_{sig}}}"


def init_db() -> None:
    con = sqlite3.connect(DB_PATH)
    con.execute("DROP TABLE IF EXISTS products")
    con.execute("CREATE TABLE products(id INTEGER, name TEXT)")
    con.executemany("INSERT INTO products VALUES (?,?)",
                    [(1, "satellite-uplink"), (2, "ground-relay"), (3, "downlink-array")])
    con.execute("DROP TABLE IF EXISTS secrets")
    con.execute("CREATE TABLE secrets(k TEXT, token TEXT)")
    con.execute("INSERT INTO secrets VALUES ('flag', ?)", (static_flag(),))
    con.commit()
    con.close()


init_db()


def waf_blocks(raw: str) -> bool:
    low = raw.lower()
    return any(tok in low for tok in WAF_BLOCKED)


@app.get("/health")
def health():
    return {"status": "ok", "patched": PATCHED}


@app.get("/api/product")
def product(id: str):
    """제품 존재 여부 조회(불리언 응답)."""
    if PATCHED:
        # 안전판: 정수 검증 + 파라미터 바인딩
        try:
            pid = int(id)
        except ValueError:
            raise HTTPException(400, "invalid id")
        con = sqlite3.connect(DB_PATH)
        try:
            row = con.execute("SELECT name FROM products WHERE id = ? LIMIT 1", (pid,)).fetchone()
        finally:
            con.close()
        return {"found": row is not None}

    # 취약판: WAF(문자 블랙리스트) 통과 시 입력을 쿼리에 그대로 삽입
    if waf_blocks(id):
        raise HTTPException(400, "WAF: request blocked")
    query = f"SELECT name FROM products WHERE id = {id} LIMIT 1"
    con = sqlite3.connect(DB_PATH)
    try:
        row = con.execute(query).fetchone()
    except Exception:
        row = None
    finally:
        con.close()
    return {"found": row is not None}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8109)
