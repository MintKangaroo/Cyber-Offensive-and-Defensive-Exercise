"""WEB-019 배포용 서비스 — 스마트시티 통합관제 GraphQL(introspection + IDOR).

통합관제 GraphQL API 가 introspection 을 켜둬 스키마(숨은 쿼리/필드)를 그대로 노출한다.
citizen(id) 쿼리에 인가 검사가 없어(IDOR) 공개 목록에 없는 '관제실 계정'(id 0)의 note 필드에
담긴 비상 대응 토큰(flag)을 읽을 수 있다.

PATCH_WEB_019=true 면 introspection 을 끄고 citizen 조회에 인가(제한 계정 차단)를 적용한다.
"""
import hashlib
import os

from fastapi import FastAPI, Request
from graphql import build_schema, graphql_sync
from graphql import validate, parse
from graphql.validation import NoSchemaIntrospectionCustomRule

app = FastAPI(title="WEB-019 Smart City GraphQL (TRAINING ONLY)")

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요."
    )
PATCHED = os.environ.get("PATCH_WEB_019", "false").lower() == "true"


def static_flag() -> str:
    sig = hashlib.sha256(f"WEB-019:{CHALLENGE_SECRET}".encode()).hexdigest()[:16]
    return f"flag{{smartcity_graphql_{sig}}}"


SCHEMA = build_schema("""
type Citizen { id: ID!, name: String!, district: String!, note: String }
type Query {
  citizens: [Citizen!]!
  citizen(id: ID!): Citizen
}
""")

# id 0 = 관제실 제한 계정(공개 목록 미포함), note 에 flag
_CITIZENS = {
    "0": {"id": "0", "name": "control-room", "district": "SOC", "note": static_flag()},
    "1": {"id": "1", "name": "홍길동", "district": "강남", "note": None},
    "2": {"id": "2", "name": "김철수", "district": "송파", "note": None},
    "3": {"id": "3", "name": "이영희", "district": "마포", "note": None},
}


def _resolve_citizens(root, info):
    return [c for cid, c in _CITIZENS.items() if cid != "0"]  # 공개 목록엔 관제실 계정 제외


def _resolve_citizen(root, info, id):
    c = _CITIZENS.get(str(id))
    if c is None:
        return None
    if PATCHED and c["id"] == "0":
        # 방어: 제한 계정은 인가 없이 조회 불가
        return None
    return c


SCHEMA.query_type.fields["citizens"].resolve = _resolve_citizens
SCHEMA.query_type.fields["citizen"].resolve = _resolve_citizen


@app.get("/health")
def health():
    return {"status": "ok", "patched": PATCHED, "service": "smartcity-graphql"}


@app.get("/api/version")
def version():
    return {"protocol": "ad-http-v1", "service": "smartcity-graphql"}


@app.post("/graphql")
async def graphql_endpoint(request: Request):
    body = await request.json()
    query = body.get("query", "")
    variables = body.get("variables") or None
    validation_rules = None
    if PATCHED:
        # 방어: introspection 비활성화
        try:
            errors = validate(SCHEMA, parse(query), [NoSchemaIntrospectionCustomRule])
            if errors:
                return {"errors": [{"message": str(e.message)} for e in errors]}
        except Exception as e:
            return {"errors": [{"message": str(e)}]}
    result = graphql_sync(SCHEMA, query, variable_values=variables)
    out = {}
    if result.errors:
        out["errors"] = [{"message": e.message} for e in result.errors]
    if result.data is not None:
        out["data"] = result.data
    return out


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8119)
