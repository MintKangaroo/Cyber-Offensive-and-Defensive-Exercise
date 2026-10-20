import type { SchematicKind } from "../types";

// 시설별 물리 스키매틱 — 발전소는 발전소답게, 병원은 병원답게.

function PowerOneLine() {
  return (
    <svg width="100%" height="92" viewBox="0 0 420 92" preserveAspectRatio="xMidYMid meet" role="img" aria-label="발전 계통 단선도">
      <circle cx="38" cy="46" r="15" fill="none" stroke="#ff5b60" strokeWidth="1.8" />
      <path d="M30 46 q4 -6 8 0 t8 0" fill="none" stroke="#ff8f92" strokeWidth="1.4" />
      <text x="38" y="80" fill="#8aa3c2" fontFamily="monospace" fontSize="8" textAnchor="middle">GEN</text>
      <line x1="53" y1="46" x2="92" y2="46" stroke="#ff5b60" strokeWidth="1.8" />
      <rect x="92" y="37" width="18" height="18" fill="none" stroke="#ff5b60" strokeWidth="1.8" />
      <text x="101" y="50" fill="#ff8f92" fontFamily="monospace" fontSize="9" textAnchor="middle">52</text>
      <text x="101" y="80" fill="#ff8f92" fontFamily="monospace" fontSize="7.5" textAnchor="middle">TRIP</text>
      <line x1="110" y1="46" x2="150" y2="46" stroke="#3a2a2e" strokeWidth="1.8" strokeDasharray="3 3" />
      <line x1="150" y1="24" x2="150" y2="68" stroke="#5f7b9e" strokeWidth="3.5" />
      <line x1="150" y1="46" x2="188" y2="46" stroke="#5f7b9e" strokeWidth="1.6" />
      <circle cx="202" cy="46" r="10" fill="none" stroke="#7d97b5" strokeWidth="1.6" />
      <circle cx="214" cy="46" r="10" fill="none" stroke="#7d97b5" strokeWidth="1.6" />
      <text x="208" y="80" fill="#8aa3c2" fontFamily="monospace" fontSize="7.5" textAnchor="middle">XFMR</text>
      <line x1="226" y1="46" x2="330" y2="46" stroke="#5f7b9e" strokeWidth="1.6" strokeDasharray="6 4" />
      <rect x="330" y="33" width="80" height="26" fill="none" stroke="#5a3a3e" strokeWidth="1.4" />
      <text x="370" y="45" fill="#ff8f92" fontFamily="monospace" fontSize="8" textAnchor="middle">154kV GRID</text>
      <text x="370" y="55" fill="#d09ca0" fontFamily="monospace" fontSize="7" textAnchor="middle">DE-ENERGIZED</text>
    </svg>
  );
}

function HospitalVitals() {
  return (
    <svg width="100%" height="92" viewBox="0 0 420 92" preserveAspectRatio="xMidYMid meet" role="img" aria-label="환자 모니터 바이탈">
      {/* ECG waveform */}
      <polyline
        points="4,52 40,52 48,52 54,30 60,70 66,46 78,52 150,52 158,52 164,30 170,70 176,46 188,52 260,52 268,52 274,30 280,70 286,46 298,52 416,52"
        fill="none" stroke="#ff5b60" strokeWidth="1.6"
      />
      <text x="6" y="16" fill="#ff8f92" fontFamily="monospace" fontSize="9">HR 148 ▲</text>
      <text x="150" y="16" fill="#f2b84b" fontFamily="monospace" fontSize="9">SpO₂ 86% ▼</text>
      {/* infusion pump block */}
      <rect x="300" y="60" width="112" height="28" fill="none" stroke="#5a3a3e" strokeWidth="1.4" />
      <text x="356" y="74" fill="#ff8f92" fontFamily="monospace" fontSize="8" textAnchor="middle">PUMP-07</text>
      <text x="356" y="84" fill="#d09ca0" fontFamily="monospace" fontSize="7.5" textAnchor="middle">900 mL/h · OVERDOSE</text>
      <text x="6" y="86" fill="#8aa3c2" fontFamily="monospace" fontSize="7.5">PATIENT P001 · WARD-3</text>
    </svg>
  );
}

function WaterProcess() {
  return (
    <svg width="100%" height="92" viewBox="0 0 420 92" preserveAspectRatio="xMidYMid meet" role="img" aria-label="상수도 공정도">
      {/* intake pump */}
      <circle cx="40" cy="48" r="14" fill="none" stroke="#f2b84b" strokeWidth="1.6" />
      <path d="M34 48 l12 -7 v14 z" fill="#f2b84b" />
      <text x="40" y="80" fill="#8aa3c2" fontFamily="monospace" fontSize="7.5" textAnchor="middle">INTAKE-1</text>
      <line x1="54" y1="48" x2="110" y2="48" stroke="#5f7b9e" strokeWidth="2" />
      {/* chlorine dosing */}
      <rect x="110" y="34" width="26" height="28" fill="none" stroke="#ff5b60" strokeWidth="1.6" />
      <text x="123" y="52" fill="#ff8f92" fontFamily="monospace" fontSize="8" textAnchor="middle">Cl</text>
      <text x="123" y="80" fill="#ff8f92" fontFamily="monospace" fontSize="7.5" textAnchor="middle">9.4▲</text>
      <line x1="136" y1="48" x2="300" y2="48" stroke="#5f7b9e" strokeWidth="2" />
      {/* reservoir overflow */}
      <path d="M300 30 h108 v40 h-108 z" fill="none" stroke="#ff5b60" strokeWidth="1.6" />
      <rect x="300" y="30" width="108" height="8" fill="#ff5b6033" />
      <text x="354" y="56" fill="#ff8f92" fontFamily="monospace" fontSize="8" textAnchor="middle">RESERVOIR 104%</text>
      <text x="354" y="84" fill="#d09ca0" fontFamily="monospace" fontSize="7.5" textAnchor="middle">OVERFLOW</text>
    </svg>
  );
}

function GenericSchematic() {
  return (
    <svg width="100%" height="92" viewBox="0 0 420 92" preserveAspectRatio="xMidYMid meet" role="img" aria-label="제어 계통도">
      <rect x="12" y="34" width="70" height="26" fill="none" stroke="#5f7b9e" strokeWidth="1.4" />
      <text x="47" y="51" fill="#8aa3c2" fontFamily="monospace" fontSize="8" textAnchor="middle">CONTROL</text>
      <line x1="82" y1="47" x2="170" y2="47" stroke="#5f7b9e" strokeWidth="1.6" />
      <circle cx="190" cy="47" r="13" fill="none" stroke="#f2b84b" strokeWidth="1.6" />
      <text x="190" y="51" fill="#f2d089" fontFamily="monospace" fontSize="9" textAnchor="middle">◆</text>
      <line x1="203" y1="47" x2="300" y2="47" stroke="#3a2a2e" strokeWidth="1.6" strokeDasharray="5 4" />
      <rect x="300" y="33" width="108" height="28" fill="none" stroke="#5a3a3e" strokeWidth="1.5" />
      <text x="354" y="45" fill="#ff8f92" fontFamily="monospace" fontSize="8" textAnchor="middle">CROWN JEWEL</text>
      <text x="354" y="55" fill="#d09ca0" fontFamily="monospace" fontSize="7.5" textAnchor="middle">TARGET</text>
    </svg>
  );
}

export function Schematic({ kind }: { kind: SchematicKind }) {
  switch (kind) {
    case "power-oneline": return <PowerOneLine />;
    case "hospital-vitals": return <HospitalVitals />;
    case "water-process": return <WaterProcess />;
    default: return <GenericSchematic />;
  }
}

export const SCHEMATIC_TITLE: Record<SchematicKind, string> = {
  "power-oneline": "발전 계통 단선도 · ONE-LINE",
  "hospital-vitals": "환자 안전 계통 · PATIENT VITALS",
  "water-process": "정수/배수 공정도 · PROCESS",
  "generic": "제어 계통도 · SCHEMATIC",
};
