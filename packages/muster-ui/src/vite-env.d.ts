/// <reference types="vite/client" />

interface ImportMetaEnv {
  /**
   * `"true"` builds the developer bundle with the local PostgreSQL Action Gate
   * mutation control; anything else (including absence) builds the replay-only
   * judge bundle. `npm run dev` keeps the control without the flag.
   */
  readonly VITE_MUSTER_LOCAL_GATE?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
