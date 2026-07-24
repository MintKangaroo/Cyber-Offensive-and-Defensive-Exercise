import { create } from "zustand";
import type { RangeEvent, AssetState, Role, Asset } from "../api/types";
import { ASSETS } from "../api/types";

const EVENT_BUFFER_LIMIT = 500;
const RECOVERED_FLASH_MS = 3000;

interface RangeStore {
  events: RangeEvent[];                       // 최신순 링버퍼
  assetStates: Record<string, AssetState>;
  role: Role;
  paused: boolean;
  scenarioId: string;
  instructorToken: string;

  pushEvent: (e: RangeEvent) => void;
  setInitialEvents: (events: RangeEvent[]) => void;
  setRole: (r: Role) => void;
  togglePause: () => void;
  setScenarioId: (id: string) => void;
  setInstructorToken: (t: string) => void;
}

function deriveAssetState(latest: RangeEvent | undefined): AssetState {
  if (!latest) return "secure";
  if (latest.event_type === "asset_recovered") return "recovered";
  if (latest.event_type === "asset_compromised") return "compromised";
  if (["red_attack_started", "flag_exfiltrated"].includes(latest.event_type)) return "under_attack";
  return "secure";
}

function initialAssetStates(): Record<string, AssetState> {
  const result: Record<string, AssetState> = {};
  for (const a of ASSETS) result[a] = "secure";
  return result;
}

export const useRangeStore = create<RangeStore>((set, get) => ({
  events: [],
  assetStates: initialAssetStates(),
  role: "observer",
  paused: false,
  scenarioId: "default",
  instructorToken: "",

  pushEvent: (e) => {
    if (get().paused) {
      // 일시정지 중엔 버퍼만 쌓고 화면 갱신용 상태는 건드리지 않음(스크롤 위치 유지 목적)
      set((s) => ({ events: [e, ...s.events].slice(0, EVENT_BUFFER_LIMIT) }));
      return;
    }
    set((s) => ({ events: [e, ...s.events].slice(0, EVENT_BUFFER_LIMIT) }));

    const nextState = deriveAssetState(e);
    if (e.target_asset) {
      set((s) => ({ assetStates: { ...s.assetStates, [e.target_asset]: nextState } }));
      if (nextState === "recovered") {
        setTimeout(() => {
          set((s) => ({
            assetStates: {
              ...s.assetStates,
              [e.target_asset]: s.assetStates[e.target_asset] === "recovered" ? "secure" : s.assetStates[e.target_asset],
            },
          }));
        }, RECOVERED_FLASH_MS);
      }
    }
  },

  setInitialEvents: (events) => {
    // 리플레이/최초 로드 시 자산 상태를 순서대로 재구성
    const states = initialAssetStates();
    const ordered = [...events].reverse(); // 오래된 것부터 적용
    for (const e of ordered) {
      if (e.target_asset && e.target_asset in states) {
        states[e.target_asset as Asset] = deriveAssetState(e);
      }
    }
    set({ events: [...events], assetStates: states });
  },

  setRole: (r) => set({ role: r }),
  togglePause: () => set((s) => ({ paused: !s.paused })),
  setScenarioId: (id) => set({ scenarioId: id }),
  setInstructorToken: (t) => set({ instructorToken: t }),
}));
