import { useMemo, useState } from "react";
import LegacyExerciseApp from "./LegacyExerciseApp";
import { AttackDefenseApp } from "./attackDefense/AttackDefenseApp";
import { BroadcastOverlay } from "./attackDefense/BroadcastOverlay";
import type { MatchMode } from "./attackDefense/types";

function initialMode(): MatchMode {
  const params = new URLSearchParams(window.location.search);
  const requested = params.get("mode");
  if (requested === "attack_defense" || requested === "hybrid_live_fire" || requested === "exercise") {
    return requested;
  }
  if (window.location.pathname.startsWith("/observer/")) return "attack_defense";
  return (localStorage.getItem("cr_match_mode") as MatchMode) || "exercise";
}

export default function App() {
  const [mode, setMode] = useState<MatchMode>(initialMode);
  const modeControl = useMemo(() => (
    <label className="mode-switcher">
      <span>Match mode</span>
      <select
        aria-label="Match mode"
        value={mode}
        onChange={(event) => {
          const next = event.target.value as MatchMode;
          localStorage.setItem("cr_match_mode", next);
          setMode(next);
        }}
      >
        <option value="exercise">Exercise / CCE</option>
        <option value="attack_defense">Attack / Defense</option>
        <option value="hybrid_live_fire">Hybrid Live Fire</option>
      </select>
    </label>
  ), [mode]);

  if (window.location.pathname.startsWith("/broadcast/")) {
    return <BroadcastOverlay />;
  }

  if (mode === "exercise") {
    return (
      <div className="mode-frame">
        <div className="mode-frame__control">{modeControl}</div>
        <LegacyExerciseApp />
      </div>
    );
  }
  return <AttackDefenseApp modeControl={modeControl} />;
}
