import { useState } from "react";
import type { ProcessNode, Alert } from "../api/types";

/**
 * 터미널의 `tree`/`pstree` 출력을 그대로 가져온 트리 뷰.
 * 프로세스 계층이 곧 공격 체인(uvicorn -> sh -> nc)이므로,
 * 데이터 구조 자체를 시각적 시그니처로 삼는다 — 별도 장식 없이 커넥터 문자만으로 표현.
 */

interface Props {
  tree: ProcessNode[];
  flaggedPids: Set<number>;
  alertsByPid: Map<number, Alert[]>;
  onSelectPid: (pid: number) => void;
  selectedPid: number | null;
}

function connectorPrefix(depth: number, isLast: boolean[]): string {
  let prefix = "";
  for (let i = 0; i < depth; i++) {
    prefix += isLast[i] ? "    " : "│   ";
  }
  return prefix;
}

function ProcessRow({
  node,
  depth,
  isLastStack,
  flaggedPids,
  alertsByPid,
  onSelectPid,
  selectedPid,
}: {
  node: ProcessNode;
  depth: number;
  isLastStack: boolean[];
  flaggedPids: Set<number>;
  alertsByPid: Map<number, Alert[]>;
  onSelectPid: (pid: number) => void;
  selectedPid: number | null;
}) {
  const [collapsed, setCollapsed] = useState(false);
  const isFlagged = flaggedPids.has(node.pid);
  const alerts = alertsByPid.get(node.pid) ?? [];
  const hasCritical = alerts.some((a) => a.severity === "critical");
  const isSelected = selectedPid === node.pid;
  const isLast = isLastStack[isLastStack.length - 1] ?? true;
  const branch = depth === 0 ? "" : isLast ? "└─ " : "├─ ";

  return (
    <div>
      <div
        onClick={() => onSelectPid(node.pid)}
        className={`group flex items-baseline gap-2 py-0.5 px-2 cursor-pointer rounded-sm
          ${isSelected ? "bg-[#1B2530]" : "hover:bg-[#141B22]"}`}
      >
        <span className="text-[#3A4552] select-none whitespace-pre">
          {connectorPrefix(depth, isLastStack)}
          {branch}
        </span>
        {node.children.length > 0 && (
          <button
            onClick={(e) => {
              e.stopPropagation();
              setCollapsed((c) => !c);
            }}
            className="text-[#5B6570] hover:text-[#9FB0C0] text-xs w-3"
          >
            {collapsed ? "+" : "−"}
          </button>
        )}
        <span
          className={`font-mono text-[13px] ${
            hasCritical ? "text-[#FF3B3B] font-semibold" : isFlagged ? "text-[#FF8A3D]" : "text-[#D9E1E8]"
          }`}
        >
          {node.name}
        </span>
        <span className="font-mono text-[11px] text-[#5B6570]">pid:{node.pid}</span>
        {isFlagged && (
          <span className="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-[#3A1414] text-[#FF8A3D] border border-[#5A2323]">
            flagged
          </span>
        )}
        <span className="font-mono text-[11px] text-[#5B6570] truncate max-w-[420px] opacity-0 group-hover:opacity-100 transition-opacity">
          {node.cmdline}
        </span>
      </div>
      {!collapsed &&
        node.children.map((child, i) => (
          <ProcessRow
            key={child.pid}
            node={child}
            depth={depth + 1}
            isLastStack={[...isLastStack, i === node.children.length - 1]}
            flaggedPids={flaggedPids}
            alertsByPid={alertsByPid}
            onSelectPid={onSelectPid}
            selectedPid={selectedPid}
          />
        ))}
    </div>
  );
}

export function ProcessTree({ tree, flaggedPids, alertsByPid, onSelectPid, selectedPid }: Props) {
  if (tree.length === 0) {
    return (
      <div className="font-mono text-sm text-[#5B6570] p-4">
        프로세스 정보 없음 — 에이전트가 아직 스냅샷을 보내지 않았거나 psutil이 이 환경에서
        비활성화되어 있습니다.
      </div>
    );
  }
  return (
    <div className="font-mono py-2">
      {tree.map((root, i) => (
        <ProcessRow
          key={root.pid}
          node={root}
          depth={0}
          isLastStack={[i === tree.length - 1]}
          flaggedPids={flaggedPids}
          alertsByPid={alertsByPid}
          onSelectPid={onSelectPid}
          selectedPid={selectedPid}
        />
      ))}
    </div>
  );
}
