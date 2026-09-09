import { useEffect, useMemo, useState } from "react";
import {
  Button,
  Dialog,
  EmptyState,
  ErrorState,
  Icon,
  Panel,
  StatusBadge,
  object,
  objects,
  str,
  num,
  type JsonObject,
} from "@cyber-range/command-system";
import { api, post, display, duration } from "../api";
import { useCommand } from "../context";
import {
  parseSource,
  editSource,
  appendStage,
  moveStage,
  NEW_SCENARIO,
  type KeyPath,
} from "../scenarioModel";
export default function Studio() {
  const { entity, data, notify } = useCommand();
  const [source, setSource] = useState(NEW_SCENARIO);
  const [mode, setMode] = useState<"visual" | "yaml">("visual");
  const [docIndex, setDocIndex] = useState(0);
  const [error, setError] = useState("");
  const [validation, setValidation] = useState<JsonObject | null>(null);
  const [busy, setBusy] = useState(false);
  const [sha, setSha] = useState("");
  const [dirty, setDirty] = useState(false);
  const [publish, setPublish] = useState(false);
  const [reason, setReason] = useState("");
  const [clock, setClock] = useState(0);
  const [drafts, setDrafts] = useState<JsonObject[]>([]);
  const parsed = useMemo(() => {
    try {
      return { docs: parseSource(source), error: "" };
    } catch (e) {
      return {
        docs: [],
        error: e instanceof Error ? e.message : "Invalid YAML",
      };
    }
  }, [source]);
  const current = parsed.docs[docIndex];
  const raw = current?.raw || {};
  const root = current?.root || "scenario";
  const sid = str(raw.id);
  useEffect(() => {
    void api("/drafts")
      .then((r) => setDrafts(objects(r.drafts)))
      .catch(() => setError("Saved drafts could not be loaded."));
  }, []);
  useEffect(() => {
    if (!entity) return;
    let cancelled = false;
    setBusy(true);
    api(`/scenarios/${encodeURIComponent(entity)}/source`)
      .then((r) => {
        if (!cancelled) {
          setSource(str(r.yaml));
          setSha(str(r.sha256));
          setDirty(false);
          setDocIndex(0);
          setValidation(null);
        }
      })
      .catch((e) => {
        if (!cancelled) setError(e.message);
      })
      .finally(() => {
        if (!cancelled) setBusy(false);
      });
    return () => {
      cancelled = true;
    };
  }, [entity]);
  useEffect(() => {
    const warn = (e: BeforeUnloadEvent) => {
      if (dirty) {
        e.preventDefault();
        e.returnValue = "";
      }
    };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [dirty]);
  const change = (text: string) => {
    setSource(text);
    setValidation(null);
    setDirty(true);
    setError("");
  };
  const update = (path: KeyPath, value: unknown) => {
    try {
      change(editSource(source, docIndex, path, value));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Visual edit failed");
    }
  };
  async function validate() {
    setBusy(true);
    setError("");
    try {
      setValidation(await post("/scenarios/validate", { yaml: source }));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Validation failed");
    } finally {
      setBusy(false);
    }
  }
  async function save() {
    setBusy(true);
    try {
      await post(`/scenarios/${encodeURIComponent(sid || "untitled")}/draft`, {
        yaml: source,
        expected_sha256: sha,
      });
      setDirty(false);
      notify("Draft saved. The running scenario is unchanged.");
      setDrafts(objects((await api("/drafts")).drafts));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Draft save failed");
    } finally {
      setBusy(false);
    }
  }
  async function apply() {
    setBusy(true);
    try {
      const result = await post(
        `/scenarios/${encodeURIComponent(sid)}/publish`,
        { yaml: source, reason, confirm: true, expected_sha256: sha },
      );
      setSha(str(result.sha256));
      setDirty(false);
      setPublish(false);
      notify("Validated scenario published to the local engine");
      void data.refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Publish failed");
      setPublish(false);
    } finally {
      setBusy(false);
    }
  }
  const reports = objects(validation?.documents);
  const report = reports[docIndex];
  const timeline = objects(report?.timeline);
  const issues = objects(report?.issues);
  return (
    <div className="studio">
      <div className="studio-toolbar">
        <div className="segmented" aria-label="Editor mode">
          <button
            aria-pressed={mode === "visual"}
            onClick={() => setMode("visual")}
          >
            Visual editor
          </button>
          <button
            aria-pressed={mode === "yaml"}
            onClick={() => setMode("yaml")}
          >
            YAML source
          </button>
        </div>
        <StatusBadge tone={dirty ? "warning" : "neutral"}>
          {dirty ? "Unsaved edits" : "Draft workspace"}
        </StatusBadge>
        <span className="spacer" />
        <Button disabled={busy} onClick={() => void save()}>
          Save draft
        </Button>
        <Button disabled={busy} onClick={() => void validate()}>
          <Icon name="shield" />
          Validate & dry run
        </Button>
        <Button
          tone="operational"
          disabled={busy || validation?.ok !== true || !sid}
          onClick={() => {
            setReason("");
            setPublish(true);
          }}
        >
          Publish scenario
        </Button>
      </div>
      {error && <ErrorState message={error} />}
      <div className="info-banner">
        Visual edits preserve stage IDs, dependencies and unknown YAML fields.
        Drafts do not alter running exercises. Publishing requires validation
        and an audit reason.
      </div>
      <div className="studio-grid">
        <section className="studio-editor">
          <Panel
            title="Exercise source"
            actions={
              <select
                aria-label="Scenario document"
                value={docIndex}
                onChange={(e) => setDocIndex(Number(e.target.value))}
              >
                {parsed.docs.map((d, i) => (
                  <option value={i} key={i}>
                    {str(d.raw.id) || `Document ${i + 1}`}
                  </option>
                ))}
              </select>
            }
          >
            {mode === "yaml" ? (
              <label className="yaml-label">
                <span className="cr-sr-only">Scenario YAML source</span>
                <textarea
                  className="yaml-editor"
                  spellCheck={false}
                  value={source}
                  onChange={(e) => change(e.target.value)}
                  aria-describedby="yaml-fidelity"
                />
                <small id="yaml-fidelity" className="muted">
                  Switching modes keeps the original source text. Syntax errors
                  remain visible until corrected.
                </small>
              </label>
            ) : parsed.error ? (
              <EmptyState
                title="Visual mode needs valid YAML"
                detail={parsed.error}
                action={
                  <Button onClick={() => setMode("yaml")}>
                    Open YAML source
                  </Button>
                }
              />
            ) : (
              <>
                <div className="scenario-fields">
                  <label>
                    Scenario ID
                    <input
                      value={sid}
                      onChange={(e) => update([root, "id"], e.target.value)}
                    />
                  </label>
                  <label>
                    Exercise name
                    <input
                      value={str(raw.name)}
                      onChange={(e) => update([root, "name"], e.target.value)}
                    />
                  </label>
                  <label>
                    Target sector
                    <select
                      value={str(raw.target_asset)}
                      onChange={(e) =>
                        update([root, "target_asset"], e.target.value)
                      }
                    >
                      {data.snapshot?.assets.map((a) => (
                        <option key={a.id} value={a.id}>
                          {a.name}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label>
                    Time limit (seconds)
                    <input
                      type="number"
                      min={0}
                      value={num(raw.time_limit_sec) ?? 0}
                      onChange={(e) =>
                        update([root, "time_limit_sec"], Number(e.target.value))
                      }
                    />
                  </label>
                  <label className="field-wide">
                    Briefing
                    <textarea
                      value={str(raw.description)}
                      onChange={(e) =>
                        update([root, "description"], e.target.value)
                      }
                      rows={3}
                    />
                  </label>
                </div>
                <div className="stage-list">
                  {current?.stages.map((s, index) => (
                    <article
                      className="stage-card"
                      key={s.path.join(".")}
                      draggable
                      onDragStart={(e) =>
                        e.dataTransfer.setData("text/plain", String(index))
                      }
                      onDragOver={(e) => e.preventDefault()}
                      onDrop={(e) => {
                        e.preventDefault();
                        const from = Number(
                          e.dataTransfer.getData("text/plain"),
                        );
                        const other = current.stages[from];
                        if (other && other.phase === s.phase) {
                          try {
                            change(
                              moveStage(
                                source,
                                docIndex,
                                s.path.slice(0, -1),
                                Number(other.path.at(-1)),
                                Number(s.path.at(-1)),
                              ),
                            );
                          } catch (err) {
                            setError(String(err));
                          }
                        } else
                          setError(
                            "Cross-phase moves require explicit YAML edits so dependencies are preserved.",
                          );
                      }}
                    >
                      <header>
                        <span className="stage-number">
                          {display(s.raw.stage)}
                        </span>
                        <div>
                          <small>{s.phase}</small>
                          <strong>{str(s.raw.name)}</strong>
                        </div>
                        <span className="spacer" />
                        <Button
                          aria-label={`Move stage ${display(s.raw.stage)} up`}
                          disabled={Number(s.path.at(-1)) === 0}
                          onClick={() => {
                            try {
                              change(
                                moveStage(
                                  source,
                                  docIndex,
                                  s.path.slice(0, -1),
                                  Number(s.path.at(-1)),
                                  Number(s.path.at(-1)) - 1,
                                ),
                              );
                            } catch (e) {
                              setError(String(e));
                            }
                          }}
                        >
                          ↑
                        </Button>
                      </header>
                      <div className="stage-fields">
                        <label>
                          Stage name
                          <input
                            value={str(s.raw.name)}
                            onChange={(e) =>
                              update([...s.path, "name"], e.target.value)
                            }
                          />
                        </label>
                        <label>
                          Objective event
                          <select
                            value={str(s.raw.objective_event)}
                            onChange={(e) =>
                              update(
                                [...s.path, "objective_event"],
                                e.target.value,
                              )
                            }
                          >
                            {[
                              "red_attack_started",
                              "red_objective_success",
                              "flag_exfiltrated",
                              "asset_compromised",
                              "blue_detection_success",
                              "blue_block_success",
                              "blue_patch_verified",
                              "asset_recovered",
                              "stage_completed",
                            ].map((t) => (
                              <option key={t}>{t}</option>
                            ))}
                          </select>
                        </label>
                        <label>
                          Points
                          <input
                            type="number"
                            value={num(s.raw.points) ?? 0}
                            onChange={(e) =>
                              update(
                                [...s.path, "points"],
                                Number(e.target.value),
                              )
                            }
                          />
                        </label>
                        <label>
                          Requires stage
                          <input
                            type="number"
                            value={num(s.raw.requires_stage) ?? ""}
                            onChange={(e) =>
                              update(
                                [...s.path, "requires_stage"],
                                e.target.value === ""
                                  ? null
                                  : Number(e.target.value),
                              )
                            }
                          />
                        </label>
                        <label>
                          Expected duration (seconds)
                          <input
                            type="number"
                            min={0}
                            value={num(s.raw.expected_sec) ?? ""}
                            onChange={(e) => {
                              if (e.target.value !== "")
                                update(
                                  [...s.path, "expected_sec"],
                                  Number(e.target.value),
                                );
                            }}
                            placeholder="Derived by dry run"
                          />
                        </label>
                        <label>
                          Training vulnerability ID
                          <input
                            value={str(object(s.raw.match).vuln_id)}
                            onChange={(e) =>
                              update(
                                [...s.path, "match", "vuln_id"],
                                e.target.value,
                              )
                            }
                          />
                        </label>
                      </div>
                    </article>
                  ))}
                </div>
                {root === "scenario" && (
                  <div className="panel-padding">
                    <Button
                      onClick={() => {
                        try {
                          change(
                            appendStage(source, docIndex, [root, "stages"]),
                          );
                        } catch (e) {
                          setError(String(e));
                        }
                      }}
                    >
                      + Add stage
                    </Button>
                  </div>
                )}
                <div className="panel-padding">
                  <h3>Blue response objectives</h3>
                  {objects(raw.blue_objectives).map((o, index) => (
                    <div className="stage-fields" key={index}>
                      <label>
                        Objective
                        <input
                          value={str(o.name)}
                          onChange={(e) =>
                            update(
                              [root, "blue_objectives", index, "name"],
                              e.target.value,
                            )
                          }
                        />
                      </label>
                      <label>
                        Score
                        <input
                          type="number"
                          value={num(o.points) ?? 0}
                          onChange={(e) =>
                            update(
                              [root, "blue_objectives", index, "points"],
                              Number(e.target.value),
                            )
                          }
                        />
                      </label>
                    </div>
                  ))}
                  <p className="muted">
                    Crossover phase conditions, evidence rules, rubrics and
                    advanced fields remain available in YAML source. Inject
                    campaigns use the existing Injects workspace.
                  </p>
                </div>
              </>
            )}
          </Panel>
        </section>
        <aside className="studio-preview">
          <Panel
            title="Validation & timeline projection"
            actions={
              validation && (
                <StatusBadge tone={validation.ok ? "healthy" : "critical"}>
                  {validation.ok ? "Validated" : "Needs correction"}
                </StatusBadge>
              )
            }
          >
            {validation ? (
              <div className="panel-padding">
                <div className="mini-metrics">
                  <div>
                    <b>{display(report?.stage_count)}</b>
                    <span>Stages</span>
                  </div>
                  <div>
                    <b>{display(report?.total_points)}</b>
                    <span>Stage points</span>
                  </div>
                  <div>
                    <b>{duration(report?.time_limit_sec)}</b>
                    <span>Time limit</span>
                  </div>
                </div>
                {issues.map((i, index) => (
                  <div
                    className={`validation-issue ${i.level === "error" ? "text-critical" : "text-warning"}`}
                    key={index}
                  >
                    <strong>{str(i.code)}</strong>
                    <p>{str(i.message)}</p>
                    <small>{str(i.where)}</small>
                  </div>
                ))}
                {!issues.length && (
                  <p className="text-healthy">
                    ✓ Schema and semantic checks passed
                  </p>
                )}
                <label>
                  Phase-clock preview: {duration(clock)}
                  <input
                    type="range"
                    min={0}
                    max={num(report?.time_limit_sec) || 1}
                    value={clock}
                    onChange={(e) => setClock(Number(e.target.value))}
                  />
                </label>
                <ol className="projection-list">
                  {timeline.map((t, index) => (
                    <li
                      className={
                        clock >= (num(t.start_sec) ?? 0) &&
                        clock < (num(t.end_sec) ?? 0)
                          ? "current"
                          : ""
                      }
                      key={index}
                    >
                      <span>{display(t.stage)}</span>
                      <div>
                        <strong>{str(t.name)}</strong>
                        <small>
                          {duration(t.start_sec)} → {duration(t.end_sec)}
                        </small>
                      </div>
                    </li>
                  ))}
                </ol>
                <p className="muted">
                  Projected pacing is a preview, not observed exercise state.
                </p>
              </div>
            ) : (
              <EmptyState
                title="Validate before execution"
                detail="Run the actual engine schema and semantic checks, then preview the stage clock. No attacks are executed by a dry run."
              />
            )}
          </Panel>
          <Panel title="Saved drafts">
            {drafts.length ? (
              drafts.map((d) => (
                <button
                  className="notice-row"
                  key={str(d.id)}
                  onClick={() => {
                    if (dirty) {
                      setError(
                        "Save the current draft before opening another draft.",
                      );
                      return;
                    }
                    setSource(str(d.yaml));
                    setSha(str(d.expected_sha256));
                    setDocIndex(0);
                    setValidation(null);
                  }}
                >
                  <Icon name="report" />
                  <span>{str(d.id)}</span>
                  <Icon name="arrow" size={14} />
                </button>
              ))
            ) : (
              <EmptyState
                title="No saved drafts"
                detail="Save locally persisted instructor drafts without changing running scenarios."
              />
            )}
          </Panel>
        </aside>
      </div>
      {publish && (
        <Dialog
          title="Publish validated scenario"
          onClose={() => {
            if (!busy) setPublish(false);
          }}
        >
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void apply();
            }}
          >
            <p>
              Publish {sid} to the local scenario engine. Active scenarios
              cannot be replaced. Existing source revisions are checked for
              concurrent edits.
            </p>
            <label>
              Audit reason
              <textarea
                autoFocus
                required
                minLength={3}
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                rows={3}
              />
            </label>
            <div className="dialog-actions">
              <Button disabled={busy} onClick={() => setPublish(false)}>
                Cancel
              </Button>
              <Button
                type="submit"
                tone="operational"
                disabled={busy || reason.trim().length < 3}
              >
                {busy ? "Publishing…" : "Confirm publish"}
              </Button>
            </div>
          </form>
        </Dialog>
      )}
    </div>
  );
}
