/// <reference types="vite/client" />

// SIEM 대시보드가 사용하는 커스텀 Vite 환경변수 타입 선언.
interface ImportMetaEnv {
  readonly VITE_SIEM_API_URL?: string;
}
interface ImportMeta {
  readonly env: ImportMetaEnv;
}
