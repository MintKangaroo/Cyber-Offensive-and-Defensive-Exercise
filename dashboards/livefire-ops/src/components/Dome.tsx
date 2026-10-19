// 방사형 돔 아레나 배경 (CCE Live Fire 현황 계보).
export function Dome() {
  return (
    <svg className="dome" viewBox="0 0 1000 560" preserveAspectRatio="xMidYMax slice" aria-hidden="true">
      <defs>
        <radialGradient id="fanW" cx="50%" cy="100%" r="90%">
          <stop offset="0" stopColor="#ffffff" stopOpacity=".10" />
          <stop offset="70%" stopColor="#ffffff" stopOpacity=".02" />
          <stop offset="100%" stopColor="#ffffff" stopOpacity="0" />
        </radialGradient>
        <radialGradient id="fanB" cx="50%" cy="100%" r="90%">
          <stop offset="0" stopColor="#3f7fd6" stopOpacity=".16" />
          <stop offset="100%" stopColor="#3f7fd6" stopOpacity="0" />
        </radialGradient>
        <radialGradient id="fanP" cx="50%" cy="100%" r="90%">
          <stop offset="0" stopColor="#9a7ae6" stopOpacity=".14" />
          <stop offset="100%" stopColor="#9a7ae6" stopOpacity="0" />
        </radialGradient>
      </defs>
      {/* 부채꼴 섹터 (apex 500,640) */}
      <polygon points="500,640 120,40 360,-20" fill="url(#fanW)" />
      <polygon points="500,640 430,-30 690,-20" fill="url(#fanB)" />
      <polygon points="500,640 720,-20 950,70" fill="url(#fanP)" />
      {/* 방사 그리드 */}
      <g stroke="#16304e" strokeWidth="1" opacity=".55">
        <line x1="500" y1="640" x2="90" y2="60" />
        <line x1="500" y1="640" x2="260" y2="10" />
        <line x1="500" y1="640" x2="500" y2="-30" />
        <line x1="500" y1="640" x2="740" y2="10" />
        <line x1="500" y1="640" x2="910" y2="60" />
      </g>
      {/* 동심 아크 */}
      <g fill="none" stroke="#1d3a5c" strokeWidth="1" opacity=".7">
        <path d="M70 300 A560 560 0 0 1 930 300" />
        <path d="M150 400 A430 430 0 0 1 850 400" />
        <path d="M230 470 A300 300 0 0 1 770 470" />
      </g>
      {/* 돔 림 대시 틱 */}
      <path d="M40 270 A620 620 0 0 1 960 270" fill="none" stroke="#54b8ec" strokeWidth="3" strokeDasharray="2 9" opacity=".7" />
      <path d="M30 255 A650 650 0 0 1 970 255" fill="none" stroke="#294c74" strokeWidth="1" strokeDasharray="1 7" opacity=".6" />
      {/* 스윕 */}
      <path d="M500 640 L250 70" stroke="#54b8ec" strokeWidth="2" opacity=".5" />
      <path d="M230 470 A300 300 0 0 1 500 350" fill="none" stroke="#7fd0f5" strokeWidth="2" opacity=".6" />
    </svg>
  );
}
