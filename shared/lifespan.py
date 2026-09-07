"""
Lifespan startup 등록 헬퍼 (on_event 대체)
==========================================
FastAPI 0.141 에서 `@app.on_event("startup")` 은 deprecated 되었다(향후 제거 예정).
공식 대체는 `FastAPI(lifespan=...)` 이지만, 이 코드베이스는 startup 로직이 한 곳이 아니라
**서비스 본체 + 여러 shared 헬퍼(attach_modbus/opcua/hart/... , ics_twin 의 EDR 배선)** 에서
'이미 생성된 app' 에 분산 등록된다. lifespan 은 생성 시점에 하나만 넘길 수 있어 이 구조와
직접 맞지 않는다.

이 헬퍼는 그 간극을 메운다: `@on_startup(app)` 데코레이터가 startup 코루틴을 app 에 누적하고,
최초 등록 시 lifespan 컨텍스트를 지연 설치한다. 여러 곳에서 등록해도 **등록 순서대로** 실행되며,
FastAPI 가 이미 갖고 있던 lifespan(기본/사용자 지정)과도 **합성**된다(hook 먼저 → 기존 lifespan).

사용:
    from shared.lifespan import on_startup

    @on_startup(app)
    async def _startup():
        ...
"""
from contextlib import asynccontextmanager


def _hooks(app):
    """app 에 startup/shutdown hook 목록을 부착하고(최초 1회), 그때 lifespan 을 지연 설치.
    반환: (startup_hooks, shutdown_hooks) 튜플."""
    startup = getattr(app.state, "_startup_hooks", None)
    if startup is not None:
        return startup, app.state._shutdown_hooks

    startup = []
    shutdown = []
    app.state._startup_hooks = startup
    app.state._shutdown_hooks = shutdown
    prev = app.router.lifespan_context   # 기존(기본 또는 사용자) lifespan 보존

    @asynccontextmanager
    async def _lifespan(a):
        for hook in list(startup):
            await hook()
        async with prev(a):
            yield
        # 종료 시퀀스: 등록 역순으로 실행(배선의 역순 해제). 하나가 실패해도 나머지는 진행.
        for hook in reversed(list(shutdown)):
            try:
                await hook()
            except Exception:
                pass

    app.router.lifespan_context = _lifespan
    return startup, shutdown


def on_startup(app):
    """`@app.on_event("startup")` 의 lifespan 기반 대체 데코레이터.

    데코된 async 함수(인자 없음)를 app 의 startup 시퀀스에 등록한다. 데코레이터 자체는
    함수를 그대로 돌려주므로 필요하면 직접 호출도 가능하다."""
    def deco(func):
        _hooks(app)[0].append(func)
        return func
    return deco


def on_shutdown(app):
    """`@app.on_event("shutdown")` 의 lifespan 기반 대체 데코레이터.

    데코된 async 함수(인자 없음)를 app 종료 시퀀스에 등록한다(등록 역순 실행). 백그라운드
    태스크 취소·커넥션 정리 등 정상 종료(graceful shutdown)에 쓴다 — 취소하지 않으면
    무한 루프 태스크가 lifespan 종료를 지연시켜 컨테이너 stop 이 SIGKILL 까지 매달린다."""
    def deco(func):
        _hooks(app)[1].append(func)
        return func
    return deco
