/// <reference types="vite/client" />

// 콘솔이 사용하는 커스텀 Vite 환경변수의 타입 선언.
// (미설정 시 client.ts에서 localhost 기본값으로 폴백)
interface ImportMetaEnv {
  readonly VITE_EDR_BACKEND_URL?: string;
  readonly VITE_CONFIG_SERVICE_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
