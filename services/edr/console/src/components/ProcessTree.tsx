import { useState } from "react";
import { EmptyState } from "@cyber-range/command-system";
import type { ProcessNode, Alert } from "../api/types";

/**
 * pstree-style process explorer. The process hierarchy IS the attack chain
 * (uvicorn → sh → nc), so the tree structure is the visual signature — only the
 * connector characters, kept verbatim, plus token-based highlighting for flagged
 * and critical processes. Colors now come from the shared design system.
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
  const nameClass = hasCritical
    ? "edr-proc-name edr-critical"
    : isFlagged
      ? "edr-proc-name edr-flagged"
      : "edr-proc-name";

  return (
    <div>
      <div
        className="edr-proc"
        aria-current={isSelected ? "true" : undefined}
        onClick={() => onSelectPid(node.pid)}
      >
        <span className="edr-connector">
          {connectorPrefix(depth, isLastStack)}
          {branch}
        </span>
        {node.children.length > 0 && (
          <button
            type="button"
            className="edr-toggle"
            aria-label={collapsed ? "확장" : "접기"}
            onClick={(e) => {
              e.stopPropagation();
              setCollapsed((c) => !c);
            }}
          >
            {collapsed ? "+" : "−"}
          </button>
        )}
        <span className={nameClass}>{node.name}</span>
        <span className="edr-proc-pid">pid:{node.pid}</span>
        {isFlagged && (
          <span className="cr-badge cr-tone-warning" style={{ fontSize: 10 }}>
            flagged
          </span>
        )}
        <span className="edr-proc-cmd">{node.cmdline}</span>
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

export function ProcessTree({
  tree,
  flaggedPids,
  alertsByPid,
  onSelectPid,
  selectedPid,
}: Props) {
  if (tree.length === 0) {
    return (
      <EmptyState
        title="프로세스 정보 없음"
        detail="에이전트가 아직 스냅샷을 보내지 않았거나 psutil이 이 환경에서 비활성화되어 있습니다."
      />
    );
  }
  return (
    <div className="edr-tree">
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
