FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/ shared/
COPY services/event_collector/ services/event_collector/
WORKDIR /app/services/event_collector
# 다일 내구성(S-11) 하드닝: glibc 는 스레드당 malloc arena 를 최대 8×nCPU 까지 만들어
# 멀티스레드(uvicorn+배치라이터+httpx) 상황에서 RSS 가 단편화로 부풀 수 있다. arena 를 2 로
# 제한하면 정상상태 RSS 기울기가 평탄해진다(A/B 소크 실측: baseline +4.0 MiB/h → arena2 ~0 MiB/h,
# 절대 RSS 도 ~1MiB 낮음·회귀 없음). libc 초기화 시 읽히므로 프로세스 시작 전 ENV 로 고정한다.
ENV MALLOC_ARENA_MAX=2
EXPOSE 8010
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8010"]
