import { useEffect, useState } from "react";
import {
  Button,
  DataTable,
  object,
  EmptyState,
  ErrorState,
  Icon,
  Panel,
  Skeleton,
  StatusBadge,
  objects,
  str,
  num,
  type JsonObject,
} from "@cyber-range/command-system";
import { api, post, display, duration, workspaceUrl } from "../api";
import { useCommand } from "../context";
const STEPS = [
  "Briefing",
  "Objective",
  "Investigation task",
  "Evidence",
  "Defense",
  "Validation",
  "Result",
  "Explanation",
];
export default function Training() {
  const { session, navigate } = useCommand();
  const [step, setStep] = useState(0);
  const [profile, setProfile] = useState<JsonObject | null>(null);
  const [error, setError] = useState("");
  const [starting, setStarting] = useState("");
  const personal = object(profile?.individual);
  const individual = personal.status === "ready" ? object(personal.data) : null;
  const visible = individual || profile;
  const isPersonal = individual?.scope === "individual";
  async function begin(id: string) {
    setStarting(id);
    setError("");
    try {
      await post(`/training/challenges/${encodeURIComponent(id)}/start`, {});
      navigate("challenges", id);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Practice start failed");
    } finally {
      setStarting("");
    }
  }
  useEffect(() => {
    if (!session.team_id) return;
    setProfile(null);
    setError("");
    let cancelled = false;
    api("/training")
      .then((r) => {
        if (!cancelled) setProfile(r);
      })
      .catch((e) => {
        if (!cancelled) setError(e.message);
      });
    return () => {
      cancelled = true;
    };
  }, [session.actor, session.team_id, session.match_id, session.role]);
  return (
    <div className="training-workspace">
      <Panel title="Guided mission">
        <div className="mission-steps">
          {STEPS.map((name, index) => (
            <button
              key={name}
              className={index === step ? "current" : ""}
              onClick={() => setStep(index)}
              aria-current={index === step ? "step" : undefined}
            >
              <span>{index + 1}</span>
              {name}
            </button>
          ))}
        </div>
        <div className="mission-content">
          <span className="eyebrow">
            MISSION {String(step + 1).padStart(2, "0")} / 08
          </span>
          <h2>{STEPS[step]}</h2>
          {step === 0 ? (
            <>
              <p>
                You are operating in an authorized cyber range. Read your
                assigned mission, collect evidence, defend the affected service,
                and review the results.
              </p>
              <StatusBadge tone="operational">
                Targets are restricted to your assigned training environment
              </StatusBadge>
            </>
          ) : step === 1 ? (
            <>
              <p>
                Select an assigned challenge and read its objective and success
                criteria. The challenge workbench retains the exact grading
                contract.
              </p>
              <Button onClick={() => navigate("challenges")}>
                Browse challenges
                <Icon name="arrow" />
              </Button>
            </>
          ) : step === 2 ? (
            <>
              <p>
                Follow the existing guided investigation. The workbench handles
                sign-in, approved targets and evidence submission.
              </p>
              <a
                className="cr-button cr-button-operational"
                href={workspaceUrl(
                  session.role === "blue" ? "blue" : "beginner",
                )}
              >
                Open guided training
                <Icon name="arrow" />
              </a>
            </>
          ) : step === 3 ? (
            <>
              <p>
                Record the evidence you observed: timestamps, asset identity,
                relevant event IDs and your reasoning. Never assume a successful
                compromise or detection without validation.
              </p>
              <Button onClick={() => navigate("events")}>
                Inspect exercise evidence
              </Button>
            </>
          ) : step === 4 ? (
            <>
              <p>
                Apply the defensive task and verify that normal service behavior
                still works. Use the existing defense guide to complete
                authorized patch validation.
              </p>
              <a
                className="cr-button cr-button-operational"
                href={workspaceUrl("livefire") + "?mode=attack_defense"}
              >
                Open defense guide
                <Icon name="arrow" />
              </a>
            </>
          ) : step === 5 ? (
            <>
              <p>
                Validation is performed by the challenge grader or competition
                checker. Moving through this guide does not mark a task complete
                or award points.
              </p>
              <Button onClick={() => navigate("competition")}>
                Check source results
              </Button>
            </>
          ) : step === 6 ? (
            <>
              <p>
                Review the source scoreboard and your completed challenges.
                Attack, Defense and Availability remain separate categories.
              </p>
              <Button onClick={() => navigate("competition")}>
                Open competition results
              </Button>
            </>
          ) : (
            <>
              <p>
                Explain what you observed, which evidence supports your
                conclusion, and how your defense changed the outcome. Ask your
                instructor for a review or use conceptual copilot hints when
                policy allows.
              </p>
              <a className="cr-button" href={workspaceUrl("beginner")}>
                Return to training hub
              </a>
            </>
          )}
          <div className="mission-navigation">
            <Button disabled={step === 0} onClick={() => setStep((s) => s - 1)}>
              Previous
            </Button>
            <Button
              tone="operational"
              disabled={step === 7}
              onClick={() => setStep((s) => s + 1)}
            >
              Continue
              <Icon name="arrow" />
            </Button>
          </div>
        </div>
      </Panel>
      <Panel
        title="Training progress & next exercises"
        actions={<StatusBadge>Transparent assessment</StatusBadge>}
      >
        {error ? (
          <ErrorState message={error} />
        ) : !session.team_id ? (
          <EmptyState
            title="Trainee membership required"
            detail="Sign in with an assigned Red or Blue membership to view recorded training evidence."
          />
        ) : !profile ? (
          <Skeleton label="Loading recorded progress" />
        ) : (
          <div className="panel-padding">
            <StatusBadge tone={isPersonal ? "operational" : "warning"}>
              {isPersonal
                ? "Personal exercise evidence"
                : "Team completion evidence"}
            </StatusBadge>
            {personal.status != null && personal.status !== "ready" && (
              <p role="status" className="muted">
                Individual evidence is unavailable ({str(personal.status)}). The
                values below describe team completion.
              </p>
            )}
            {isPersonal && individual?.collection_enabled === false && (
              <p role="status" className="text-warning">
                Verified submission attribution is disabled in this
                compatibility deployment. Personal attempt counts include only
                previously verified records.
              </p>
            )}
            <p className="muted">{str(visible?.method)}</p>
            <div className="skill-grid">
              {objects(visible?.domains).map((d) => (
                <div className="skill-card" key={str(d.domain)}>
                  <strong>{str(d.domain)}</strong>
                  <span>
                    {num(d.proficiency) === null
                      ? "Unmeasured"
                      : `${d.proficiency}% completion coverage`}
                  </span>
                  <progress
                    max={100}
                    value={num(d.proficiency) ?? 0}
                    aria-label={`${str(d.domain)} recorded completion coverage`}
                  />
                  <small>
                    {display(d.completed)} / {display(d.available)} challenges ·
                    {isPersonal ? "personal evidence" : "team evidence"}
                  </small>
                </div>
              ))}
            </div>
            <h3>Suggested next exercises</h3>
            {objects(visible?.recommendations).map((r) => (
              <button
                key={str(r.id)}
                className="notice-row"
                disabled={Boolean(starting)}
                onClick={() =>
                  isPersonal
                    ? void begin(str(r.id))
                    : navigate("challenges", str(r.id))
                }
              >
                <span>
                  <strong>{str(r.title)}</strong>
                  <small>{str(r.reason)}</small>
                  {isPersonal && (
                    <small>
                      {starting === r.id
                        ? "Recording practice start…"
                        : "Start practice and open challenge"}
                    </small>
                  )}
                </span>
                <StatusBadge>{str(r.difficulty)}</StatusBadge>
              </button>
            ))}
            {isPersonal && (
              <>
                <h3>Personal exercise history</h3>
                <DataTable
                  caption="Personal training evidence"
                  rows={objects(individual?.activity).map((r) => ({
                    challenge: str(r.title),
                    status: (
                      <StatusBadge tone={r.completed ? "healthy" : "neutral"}>
                        {r.completed ? "Grader passed" : "In progress"}
                      </StatusBadge>
                    ),
                    attempts: display(r.attempts),
                    elapsed: duration(r.elapsed_sec),
                  }))}
                  columns={[
                    { key: "challenge", label: "Challenge" },
                    { key: "status", label: "Result" },
                    { key: "attempts", label: "Evaluated attempts" },
                    { key: "elapsed", label: "Start → first pass" },
                  ]}
                />
              </>
            )}
            <p className="muted">
              Unavailable measurements:{" "}
              {Array.isArray(visible?.unavailable_inputs)
                ? visible.unavailable_inputs.map(String).join(", ")
                : "individual measurements"}
              . No proficiency estimate modifies competition scoring.
            </p>
          </div>
        )}
      </Panel>
    </div>
  );
}
