/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_COLLECTOR_URL?: string;
  readonly VITE_POWER_TWIN_URL?: string;
  readonly VITE_BASE?: string;
}
interface ImportMeta {
  readonly env: ImportMetaEnv;
}
