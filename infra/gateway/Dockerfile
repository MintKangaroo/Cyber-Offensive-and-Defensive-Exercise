# 단일 진입점 gateway (P0-1): 5개 대시보드 프로덕션 빌드 → nginx 정적 서빙 + /api 프록시 + TLS.
FROM node:20-alpine AS build
WORKDIR /b
# 각 대시보드를 자기 base 경로 + same-origin /api URL로 빌드
COPY dashboards/livefire/ livefire/
RUN cd livefire && npm ci && VITE_BASE=/ops/ \
    VITE_EVENT_COLLECTOR_URL=/api/events VITE_SCORING_ENGINE_URL=/api/scoring \
    VITE_CONFIG_SERVICE_URL=/api/config VITE_INSTRUCTOR_API_URL=/api/instructor \
    VITE_RANGE_CONTROL_URL=/api/range npm run build
COPY dashboards/redportal/ redportal/
RUN cd redportal && npm ci && VITE_BASE=/red/ VITE_PORTAL_URL=/api/portal npm run build
COPY dashboards/blueportal/ blueportal/
RUN cd blueportal && npm ci && VITE_BASE=/blue/ VITE_PORTAL_URL=/api/portal \
    VITE_CONFIG_SERVICE_URL=/api/config VITE_EVENT_COLLECTOR_URL=/api/events npm run build
COPY dashboards/siem/ siem/
RUN cd siem && npm ci && VITE_BASE=/blue/siem/ VITE_SIEM_API_URL=/api/siem npm run build
COPY services/edr/console/ edrconsole/
RUN cd edrconsole && npm ci && VITE_BASE=/blue/edr/ \
    VITE_EDR_BACKEND_URL=/api/edr VITE_CONFIG_SERVICE_URL=/api/config npm run build

FROM nginx:alpine
RUN apk add --no-cache openssl
COPY --from=build /b/livefire/dist/    /usr/share/nginx/html/ops/
COPY --from=build /b/redportal/dist/   /usr/share/nginx/html/red/
COPY --from=build /b/blueportal/dist/  /usr/share/nginx/html/blue/
COPY --from=build /b/siem/dist/        /usr/share/nginx/html/blue/siem/
COPY --from=build /b/edrconsole/dist/  /usr/share/nginx/html/blue/edr/
COPY infra/gateway/landing.html /usr/share/nginx/html/landing.html
COPY infra/gateway/login.html /usr/share/nginx/html/login.html
COPY infra/gateway/nginx.conf   /etc/nginx/conf.d/default.conf
COPY infra/gateway/proxy_ws.conf /etc/nginx/proxy_ws.conf
COPY infra/gateway/entrypoint.sh /entrypoint.sh
EXPOSE 80 443
ENTRYPOINT ["/entrypoint.sh"]
