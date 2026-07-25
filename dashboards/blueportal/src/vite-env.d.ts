/// <reference types="vite/client" />

// Live Fire 대시보드가 사용하는 커스텀 Vite 환경변수 타입 선언.
// (미설정 시 client.ts의 localhost 기본값으로 폴백)
interface ImportMetaEnv {
  readonly VITE_EVENT_COLLECTOR_URL?: string;
  readonly VITE_SCORING_ENGINE_URL?: string;
  readonly VITE_CONFIG_SERVICE_URL?: string;
  readonly VITE_INSTRUCTOR_API_URL?: string;
}
interface ImportMeta {
  readonly env: ImportMetaEnv;
}
