"""shared.lifespan.on_startup 테스트 — on_event 대체 데코레이터.

- 여러 곳(서비스 본체 + shared attach_* 헬퍼 모사)에서 누적 등록 시 등록 순서대로 실행.
- FastAPI 가 이미 갖고 있던 lifespan(사용자 지정)과 합성(hook 먼저 → 기존 lifespan enter/exit).
- 데코레이터가 원함수를 그대로 반환.
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.testclient import TestClient

from shared.lifespan import on_startup


def test_multiple_hooks_run_in_registration_order():
    app = FastAPI()
    order = []

    # 서비스 본체가 등록
    @on_startup(app)
    async def _svc():
        order.append("svc")

    # 나중에 shared 헬퍼(attach_*)가 같은 app 에 추가 등록
    @on_startup(app)
    async def _twinA():
        order.append("twinA")

    @on_startup(app)
    async def _twinB():
        order.append("twinB")

    with TestClient(app):
        pass
    assert order == ["svc", "twinA", "twinB"]


def test_composes_with_existing_lifespan():
    events = []

    @asynccontextmanager
    async def base(app):
        events.append("base_enter")
        yield
        events.append("base_exit")

    app = FastAPI(lifespan=base)

    @on_startup(app)
    async def _hook():
        events.append("hook")

    with TestClient(app):
        pass
    # hook 이 먼저, 그다음 기존 lifespan enter, 컨텍스트 종료 시 exit
    assert events[:2] == ["hook", "base_enter"]
    assert events[-1] == "base_exit"


def test_decorator_returns_original_function():
    app = FastAPI()

    @on_startup(app)
    async def _hook():
        return 42

    assert _hook.__name__ == "_hook"
