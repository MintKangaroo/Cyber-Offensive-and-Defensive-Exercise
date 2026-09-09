import { useEffect, useState } from "react";
import {
  Button,
  EmptyState,
  ErrorState,
  StatusBadge,
  str,
  type JsonObject,
} from "@cyber-range/command-system";
import { api, post } from "../api";
import { useCommand } from "../context";
export default function Copilot() {
  const { session, scenarioId, entity } = useCommand();
  const [policy, setPolicy] = useState<JsonObject | null>(null);
  const [question, setQuestion] = useState("");
  const [answer, setAnswer] = useState<JsonObject | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [mode, setMode] = useState(
    session.role === "instructor"
      ? "instructor"
      : session.role === "blue"
        ? "soc"
        : "trainee",
  );
  const [reason, setReason] = useState("");
  const load = () =>
    api("/copilot/policy")
      .then(setPolicy)
      .catch((e) => setError(e.message));
  useEffect(() => {
    void load();
  }, []);
  const enabled =
    policy?.enabled === true && policy.provider_configured === true;
  return (
    <div className="copilot">
      <StatusBadge tone="intelligence">
        AI-GENERATED SUGGESTIONS · HUMAN REVIEW REQUIRED
      </StatusBadge>
      <p className="muted">
        The assistant can explain supplied evidence and suggest defensive
        investigation steps. It cannot execute controls or modify scores.
      </p>
      {error && <ErrorState message={error} />}
      <label>
        Assistance mode
        <select value={mode} onChange={(e) => setMode(e.target.value)}>
          {session.role === "instructor" && (
            <option value="instructor">Instructor copilot</option>
          )}
          {["instructor", "blue"].includes(session.role) && (
            <option value="soc">SOC copilot</option>
          )}
          <option value="trainee">Trainee conceptual hints</option>
        </select>
      </label>
      {!enabled && (
        <EmptyState
          title="Copilot is optional and currently unavailable"
          detail={
            policy?.provider_configured
              ? "Instructor policy has disabled AI assistance for this platform."
              : "No local AI provider is configured. All operational workspaces work independently of AI."
          }
        />
      )}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          setBusy(true);
          setError("");
          post("/copilot", {
            mode,
            question,
            scenario_id: scenarioId,
            incident_id: entity.startsWith("INC-") ? entity : "",
          })
            .then(setAnswer)
            .catch((e) => setError(e.message))
            .finally(() => setBusy(false));
        }}
      >
        <label>
          Request assistance
          <textarea
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            rows={4}
            placeholder="Summarize observed evidence and suggest the next defensive investigation steps."
            maxLength={2000}
            required
            disabled={!enabled}
          />
        </label>
        <Button type="submit" disabled={!enabled || busy || !question.trim()}>
          {busy ? "Preparing explanation…" : "Generate grounded suggestion"}
        </Button>
      </form>
      {answer && (
        <section className="copilot-answer">
          <StatusBadge tone="intelligence">
            AI-generated · {str(answer.model)}
          </StatusBadge>
          <p>{str(answer.text)}</p>
          <h3>Supplied evidence IDs</h3>
          <ul>
            {(Array.isArray(answer.evidence_ids)
              ? answer.evidence_ids
              : []
            ).map((id) => (
              <li className="mono" key={String(id)}>
                {String(id)}
              </li>
            ))}
          </ul>
          <small>
            These are the supplied evidence references, not independent
            verification of the model’s conclusions.
          </small>
        </section>
      )}
      {session.role === "instructor" && (
        <details>
          <summary>Instructor AI policy</summary>
          <p className="muted">
            A local Ollama-compatible provider is configured by the platform
            operator. Complete challenge solutions are excluded from model
            context.
          </p>
          <label>
            Policy change reason
            <input value={reason} onChange={(e) => setReason(e.target.value)} />
          </label>
          <Button
            disabled={reason.trim().length < 3 || busy}
            onClick={() => {
              setBusy(true);
              post("/copilot/policy", {
                enabled: !policy?.enabled,
                trainee_mode: "concepts",
                reason,
              })
                .then(load)
                .catch((e) => setError(e.message))
                .finally(() => setBusy(false));
            }}
          >
            {policy?.enabled ? "Disable assistance" : "Enable assistance"}
          </Button>
        </details>
      )}
    </div>
  );
}
