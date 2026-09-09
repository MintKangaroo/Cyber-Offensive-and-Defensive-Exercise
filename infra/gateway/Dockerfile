# Existing local workspaces remain independent builds with one shared source package.
FROM node:20-alpine AS build
WORKDIR /b
COPY dashboards/shared/ dashboards/shared/
COPY dashboards/control-tower/ dashboards/control-tower/
RUN cd dashboards/control-tower && npm ci && VITE_BASE=/control/ npm run build
COPY dashboards/livefire/ dashboards/livefire/
RUN cd dashboards/livefire && npm ci && VITE_BASE=/ops/ \
    VITE_EVENT_COLLECTOR_URL=/api/events VITE_SCORING_ENGINE_URL=/api/scoring \
    VITE_CONFIG_SERVICE_URL=/api/config VITE_INSTRUCTOR_API_URL=/api/instructor \
    VITE_RANGE_CONTROL_URL=/api/range VITE_ATTACK_DEFENSE_API_URL=/api/ad VITE_AUTH_API_URL= npm run build
COPY dashboards/redportal/ dashboards/redportal/
RUN cd dashboards/redportal && npm ci && VITE_BASE=/red/ VITE_PORTAL_URL=/api/portal \
    VITE_ATTACK_DEFENSE_API_URL=/api/ad VITE_AUTH_API_URL= npm run build
COPY dashboards/blueportal/ dashboards/blueportal/
RUN cd dashboards/blueportal && npm ci && VITE_BASE=/blue/ VITE_PORTAL_URL=/api/portal \
    VITE_CONFIG_SERVICE_URL=/api/config VITE_EVENT_COLLECTOR_URL=/api/events npm run build
COPY dashboards/siem/ dashboards/siem/
RUN cd dashboards/siem && npm ci && VITE_BASE=/blue/siem/ VITE_SIEM_API_URL=/api/siem npm run build
COPY services/edr/console/ services/edr/console/
RUN cd services/edr/console && npm ci && VITE_BASE=/blue/edr/ \
    VITE_EDR_BACKEND_URL=/api/edr VITE_CONFIG_SERVICE_URL=/api/config npm run build

FROM nginx:alpine
RUN apk add --no-cache openssl
COPY --from=build /b/dashboards/control-tower/dist/ /usr/share/nginx/html/control/
COPY --from=build /b/dashboards/livefire/dist/ /usr/share/nginx/html/ops/
COPY --from=build /b/dashboards/redportal/dist/ /usr/share/nginx/html/red/
COPY --from=build /b/dashboards/blueportal/dist/ /usr/share/nginx/html/blue/
COPY --from=build /b/dashboards/siem/dist/ /usr/share/nginx/html/blue/siem/
COPY --from=build /b/services/edr/console/dist/ /usr/share/nginx/html/blue/edr/
COPY dashboards/start-here/index.html /usr/share/nginx/html/start/index.html
COPY dashboards/competition/index.html /usr/share/nginx/html/competition/index.html
COPY infra/gateway/landing.html /usr/share/nginx/html/landing.html
COPY infra/gateway/login.html /usr/share/nginx/html/login.html
COPY infra/gateway/nginx.conf /etc/nginx/conf.d/default.conf
COPY infra/gateway/proxy_ws.conf /etc/nginx/proxy_ws.conf
COPY infra/gateway/entrypoint.sh /entrypoint.sh
EXPOSE 80 443
ENTRYPOINT ["/entrypoint.sh"]
