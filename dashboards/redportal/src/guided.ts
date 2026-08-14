// Pure, framework-free logic for the Red Portal beginner "Guided Mode".
//
// The guided flow removes the mechanical friction from the live attack (copying
// tokens by hand, remembering API paths) while keeping the actual attack
// technique visible. Everything here is deterministic and unit-tested; the React
// component in App.tsx only orchestrates HTTP calls and renders these results.

export interface TargetResponse {
  status: number;
  body: string;
}

export type MissionKind = "notes" | "vault";

export interface GuidedStep {
  id: string;
  /** What the trainee is doing right now. */
  title: string;
  /** Why this step matters (the attack concept). */
  why: string;
  /** Label for the action button. */
  action: string;
}

export interface GuidedMission {
  kind: MissionKind;
  code: string;
  name: string;
  objective: string;
  steps: GuidedStep[];
}

/** FLAG token as emitted by the game engine (see uiLogic FLAG_FORMAT). */
export const FLAG_RE = /FLAG\{[A-Za-z0-9_-]{10,}\}/;

/** Pull the JWT / access token out of a login response body. */
export function extractToken(body: string): string | null {
  try {
    const value = JSON.parse(body);
    const token = value?.access_token;
    return typeof token === "string" && token.length > 0 ? token : null;
  } catch {
    return null;
  }
}

/** Find the first FLAG{...} token anywhere in a response body. */
export function findFlag(text: string): string | null {
  const match = FLAG_RE.exec(text ?? "");
  return match ? match[0] : null;
}

/** Directory entries returned by the vulnerable File Vault listing. */
export function parseEntries(body: string): string[] {
  try {
    const value = JSON.parse(body);
    const entries = value?.entries;
    if (!Array.isArray(entries)) return [];
    return entries.filter((item): item is string => typeof item === "string");
  } catch {
    return [];
  }
}

/** The traversal path used to read a discovered system file. */
export function systemFilePath(name: string): string {
  return `../../system/${name}`;
}

/** Note ids the beginner "explore" step will sweep looking for a planted flag. */
export function noteSweepIds(max = 12): number[] {
  return Array.from({ length: max }, (_, index) => index + 1);
}

/** A stable-per-session attacker credential so re-runs do not collide. */
export function guidedCredentials(seed = Date.now()): { username: string; password: string } {
  const suffix = Math.abs(seed).toString(36).slice(-6);
  return { username: `redop_${suffix}`, password: `redops-pass-${suffix}-2026` };
}

export function missionForTarget(serviceSlug: string | undefined): GuidedMission {
  return serviceSlug === "file-vault" ? VAULT_MISSION : NOTES_MISSION;
}

export const NOTES_MISSION: GuidedMission = {
  kind: "notes",
  code: "Mission 1",
  name: "Vulnerable Notes 침투",
  objective: "상대 팀 Notes 서비스에서 다른 사용자의 노트에 숨겨진 FLAG를 훔칩니다.",
  steps: [
    {
      id: "register",
      title: "계정 준비",
      why: "서비스를 사용하려면 먼저 내 계정이 필요합니다. 공격자도 정상 사용자로 가입합니다.",
      action: "① 계정 생성 (Register)",
    },
    {
      id: "login",
      title: "로그인",
      why: "로그인하면 access token(출입증)이 발급됩니다. 가이드가 자동으로 이 토큰을 이후 요청에 넣어 줍니다.",
      action: "② 로그인 (Login)",
    },
    {
      id: "explore",
      title: "다른 노트 훔쳐보기 (IDOR)",
      why: "이 서비스는 노트 번호만 바꾸면 소유자 확인 없이 남의 노트를 읽습니다. /api/notes/1, 2, 3 … 을 순서대로 조회합니다.",
      action: "③ 노트 자동 탐색",
    },
    {
      id: "capture",
      title: "FLAG 획득",
      why: "다른 사용자의 노트 안에서 FLAG{...} 값을 찾아냈습니다.",
      action: "④ FLAG 확인",
    },
    {
      id: "submit",
      title: "FLAG 제출",
      why: "획득한 FLAG를 경기 엔진에 제출하면 공격 점수를 얻습니다.",
      action: "⑤ FLAG 제출 (Submit)",
    },
  ],
};

export const VAULT_MISSION: GuidedMission = {
  kind: "vault",
  code: "Mission 2",
  name: "File Vault 침투",
  objective: "상대 팀 File Vault의 경로 조작(Path Traversal) 취약점으로 숨겨진 시스템 파일의 FLAG를 읽습니다.",
  steps: [
    {
      id: "register",
      title: "계정 준비",
      why: "File Vault도 사용하려면 계정이 필요합니다.",
      action: "① 계정 생성 (Register)",
    },
    {
      id: "login",
      title: "로그인",
      why: "발급된 access token을 가이드가 자동으로 다음 요청에 첨부합니다.",
      action: "② 로그인 (Login)",
    },
    {
      id: "discover",
      title: "숨겨진 디렉터리 탐색",
      why: "path=../../system 처럼 상위 경로로 빠져나가면 내 폴더 밖의 시스템 디렉터리 목록이 노출됩니다.",
      action: "③ 숨겨진 파일 탐색 (Discover)",
    },
    {
      id: "read",
      title: "파일 읽기",
      why: "탐색된 파일들을 하나씩 열어 FLAG가 들어 있는 파일을 찾습니다.",
      action: "④ 파일 자동 읽기 (Read)",
    },
    {
      id: "capture",
      title: "FLAG 획득",
      why: "시스템 파일 안에서 FLAG{...} 값을 찾아냈습니다.",
      action: "⑤ FLAG 확인",
    },
    {
      id: "submit",
      title: "FLAG 제출",
      why: "획득한 FLAG를 경기 엔진에 제출하면 공격 점수를 얻습니다.",
      action: "⑥ FLAG 제출 (Submit)",
    },
  ],
};
