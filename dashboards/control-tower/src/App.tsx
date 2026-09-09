import {
  lazy,
  Suspense,
  useEffect,
  useMemo,
  useState,
  type FormEvent,
} from "react";
import {
  ApiError,
  Button,
  Dialog,
  Drawer,
  EmptyState,
  ErrorState,
  Icon,
  Skeleton,
  StatusBadge,
  object,
  objects,
  str,
  techniques,
  type JsonObject,
} from "@cyber-range/command-system";
import {
  authApi,
  api,
  getSession,
  setAccessToken,
  display,
  time,
  duration,
  type Session,
} from "./api";
import { CommandContext } from "./context";
import { useCommandData } from "./useCommandData";
import { visibleNav } from "./navigation";
import {
  Overview,
  DigitalTwin,
  EventStream,
  AssetList,
} from "./pages/Operations";
const Incidents = lazy(() => import("./pages/Incidents"));
const Studio = lazy(() => import("./pages/Studio"));
const Replay = lazy(() => import("./pages/Replay"));
const Resources = lazy(() => import("./pages/Resources"));
const Competition = lazy(() => import("./pages/Competition"));
const Copilot = lazy(() => import("./pages/Copilot"));
const Training = lazy(() => import("./pages/Training"));
function getRoute() {
  const [route, entity] = location.hash.slice(1).split("/");
  let decoded = "";
  try {
    decoded = decodeURIComponent(entity || "");
  } catch {
    /* Invalid bookmark has no entity. */
  }
  return { route: route || "overview", entity: decoded };
}
export default function App() {
  const [session, setSession] = useState<Session | null>(null);
  const [staticAccess, setStaticAccess] = useState(false);
  const [film, setFilm] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  useEffect(() => {
    let cancelled = false;
    getSession()
      .then((s) => {
        if (!cancelled) setSession(s);
      })
      .catch((e) => {
        if (!cancelled && !(e instanceof ApiError && e.status === 401))
          setError(e.message);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);
  useEffect(() => {
    if (!session || staticAccess) return;
    const timer = setInterval(
      () => {
        authApi("/auth/refresh", { method: "POST" })
          .then((r) => {
            setAccessToken(str(r.access_token));
          })
          .catch(() => {
            setAccessToken("");
            setSession(null);
            setError("Session expired. Sign in to continue.");
          });
      },
      12 * 60 * 1000,
    );
    return () => clearInterval(timer);
  }, [session, staticAccess]);
  async function login(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    setError("");
    const form = new FormData(event.currentTarget);
    try {
      setStaticAccess(
        Boolean(form.get("token")) &&
          String(form.get("token")).split(".").length !== 3,
      );
      if (form.get("token")) setAccessToken(String(form.get("token")));
      else {
        const r = await authApi("/auth/login", {
          method: "POST",
          body: JSON.stringify({
            username: form.get("username"),
            password: form.get("password"),
          }),
        });
        setAccessToken(str(r.access_token));
      }
      setSession(await getSession());
    } catch (e) {
      setAccessToken("");
      setError(e instanceof Error ? e.message : "Sign-in failed");
    } finally {
      setLoading(false);
    }
  }
  if (!session)
    return (
      <div className="login-page">
        <div
          className="login-visual"
          aria-hidden="true"
          style={{
            backgroundImage: `linear-gradient(90deg,var(--cr-bg) 3%, color-mix(in srgb,var(--cr-bg) 96%,transparent) 30%, color-mix(in srgb,var(--cr-bg) 40%,transparent) 65%), url(${import.meta.env.BASE_URL}brand/command-hero.webp)`,
          }}
        />
        <div className="login-brand">
          <Icon name="command" size={32} />
          <span>
            CYBER RANGE
            <br />
            <b>COMMAND</b>
          </span>
        </div>
        <main className="login-card">
          <span className="eyebrow">CYBER RANGE COMMAND SYSTEM</span>
          <h1>
            One range.
            <br />
            Complete awareness.
          </h1>
          <p>
            Digital twin cyber operations, exercise control, and evidence-led
            training.
          </p>
          <form onSubmit={login}>
            <label>
              Username
              <input
                name="username"
                autoComplete="username"
                placeholder="Your exercise account"
              />
            </label>
            <label>
              Password
              <input
                name="password"
                type="password"
                autoComplete="current-password"
              />
            </label>
            <details>
              <summary>Advanced access</summary>
              <label>
                Authorized role token
                <input name="token" type="password" autoComplete="off" />
              </label>
            </details>
            {error && (
              <p className="form-error" role="alert">
                {error}
              </p>
            )}
            <Button type="submit" tone="operational" disabled={loading}>
              {loading ? "Verifying access…" : "Enter command platform"}
              <Icon name="arrow" />
            </Button>
          </form>
          <Button className="brand-film-trigger" onClick={() => setFilm(true)}>
            Preview range identity
            <Icon name="replay" size={14} />
          </Button>
          {film && (
            <Dialog
              title="Cyber Range Command · visual identity"
              onClose={() => setFilm(false)}
            >
              <video
                controls
                autoPlay
                muted
                playsInline
                preload="none"
                className="brand-film"
                src={`${import.meta.env.BASE_URL}brand/login-sequence.mp4`}
                aria-label="Decorative infrastructure identity sequence"
              />
              <p className="muted">
                Brand illustration generated with Higgsfield. This sequence
                contains no live exercise data.
              </p>
            </Dialog>
          )}
          <div className="scope-note">
            <Icon name="shield" />
            <span>
              Authorized training environment
              <br />
              Access follows your assigned exercise role.
            </span>
          </div>
        </main>
        <footer className="login-footer">
          DIGITAL TWIN CYBER OPERATIONS CENTER{" "}
          <span>CYBER RANGE / SECURE ACCESS</span>
        </footer>
      </div>
    );
  return (
    <CommandApp
      key={`${session.actor}:${session.role}:${session.team_id}:${session.match_id}`}
      session={session}
      logout={() => {
        void authApi("/auth/logout", { method: "POST" });
        setAccessToken("");
        setSession(null);
      }}
    />
  );
}
function CommandApp({
  session,
  logout,
}: {
  session: Session;
  logout: () => void;
}) {
  const [routeState, setRouteState] = useState(getRoute);
  const [scenarioId, setScenarioId] = useState(session.match_id || "default");
  const [remoteResults, setRemoteResults] = useState<JsonObject[]>([]);
  const [searchStatus, setSearchStatus] = useState("");
  const [palette, setPalette] = useState(false);
  const [query, setQuery] = useState("");
  const [mobileNav, setMobileNav] = useState(false);
  const [inspector, setInspector] = useState<{
    type: "event" | "asset";
    id: string;
  } | null>(null);
  const [assetDetail, setAssetDetail] = useState<JsonObject | null>(null);
  const [wallClock, setWallClock] = useState(Date.now() / 1000);
  const [notifications, setNotifications] = useState(false);
  const [copilot, setCopilot] = useState(false);
  const [warroom, setWarroom] = useState(false);
  const [toast, setToast] = useState("");
  const [contrast, setContrast] = useState(
    () => localStorage.getItem("cr-contrast") === "high",
  );
  const [dense, setDense] = useState(
    () => localStorage.getItem("cr-density") !== "comfortable",
  );
  const data = useCommandData(session, scenarioId);
  const items = visibleNav(session);
  const current = items.find((n) => n.id === routeState.route);
  const route = current?.id || "unauthorized";
  const navigate = (next: string, entity = "") => {
    location.hash = next + (entity ? "/" + encodeURIComponent(entity) : "");
    setMobileNav(false);
    setPalette(false);
  };
  useEffect(() => {
    const listener = () => setRouteState(getRoute());
    window.addEventListener("hashchange", listener);
    return () => window.removeEventListener("hashchange", listener);
  }, []);
  useEffect(() => {
    document.documentElement.dataset.contrast = contrast ? "high" : "standard";
    localStorage.setItem("cr-contrast", contrast ? "high" : "standard");
  }, [contrast]);
  useEffect(() => {
    document.documentElement.dataset.density = dense
      ? "compact"
      : "comfortable";
    localStorage.setItem("cr-density", dense ? "compact" : "comfortable");
  }, [dense]);
  useEffect(() => {
    const key = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPalette((v) => !v);
      }
      if (e.key === "Escape") setMobileNav(false);
    };
    window.addEventListener("keydown", key);
    return () => window.removeEventListener("keydown", key);
  }, []);
  useEffect(() => {
    if (!toast) return;
    const timer = setTimeout(() => setToast(""), 5000);
    return () => clearTimeout(timer);
  }, [toast]);
  useEffect(() => {
    setAssetDetail(null);
    if (inspector?.type !== "asset") return;
    let cancelled = false;
    api("/assets/" + encodeURIComponent(inspector.id))
      .then((v) => {
        if (!cancelled) setAssetDetail(v);
      })
      .catch(() => {
        if (!cancelled) setAssetDetail({ error: "Asset context unavailable" });
      });
    return () => {
      cancelled = true;
    };
  }, [inspector]);
  const inspectEvent = (id: string) => setInspector({ type: "event", id });
  const inspectAsset = (id: string) => setInspector({ type: "asset", id });
  const selectedEvent = data.events.find((e) => e.event_id === inspector?.id);
  const selectedAsset = data.snapshot?.assets.find(
    (a) => a.id === inspector?.id,
  );
  const sourceStatus = Object.values(data.snapshot?.sources || {});
  const unavailable = sourceStatus.filter((s) => s.status !== "ready").length;
  const alerts = objects(data.snapshot?.sources.alerts?.data?.alerts);
  const incidents = objects(data.snapshot?.sources.incidents?.data?.incidents);
  const safety = object(data.snapshot?.sources.safety?.data?.safety);
  const scenario = object(data.snapshot?.sources.scenarios?.data);
  const availableScenarios = Array.isArray(scenario.available)
    ? scenario.available.filter((s): s is string => typeof s === "string")
    : [];
  useEffect(() => {
    setRemoteResults([]);
    setSearchStatus("");
    if (!palette || query.trim().length < 2) return;
    let cancelled = false;
    const timer = setTimeout(() => {
      setSearchStatus("Searching authorized catalog…");
      api(
        `/search?q=${encodeURIComponent(query.trim())}&scenario_id=${encodeURIComponent(scenarioId)}`,
      )
        .then((r) => {
          if (!cancelled) {
            setRemoteResults(objects(r.results));
            setSearchStatus(
              r.partial
                ? "Some search sources are unavailable."
                : "Catalog search complete.",
            );
          }
        })
        .catch(() => {
          if (!cancelled)
            setSearchStatus(
              "Catalog unavailable; loaded results remain searchable.",
            );
        });
    }, 300);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [palette, query, scenarioId]);
  const searchResults = useMemo(() => {
    const result = items.map((i) => ({
      type: "Workspace",
      id: i.id,
      title: i.label,
      go: () => navigate(i.id),
    }));
    for (const a of data.snapshot?.assets || [])
      result.push({
        type: "Asset",
        id: a.id,
        title: a.name,
        go: () => {
          setPalette(false);
          inspectAsset(a.id);
        },
      });
    for (const i of incidents)
      result.push({
        type: "Incident",
        id: str(i.id),
        title: str(i.title),
        go: () => navigate("incidents", str(i.id)),
      });
    for (const a of alerts)
      result.push({
        type: "Alert",
        id: str(a.id),
        title: str(a.title) || str(a.rule_id),
        go: () => navigate("siem", str(a.id)),
      });
    for (const e of data.events.slice(0, 300))
      result.push({
        type: "Event",
        id: e.event_id,
        title: `${e.event_type} · ${e.target_asset}`,
        go: () => {
          setPalette(false);
          inspectEvent(e.event_id);
        },
      });
    for (const s of objects(data.snapshot?.sources.services?.data?.services))
      result.push({
        type: "Service",
        id: str(s.name),
        title: str(s.name),
        go: () => navigate("services", str(s.name)),
      });
    for (const sid of availableScenarios)
      result.push({
        type: "Scenario",
        id: sid,
        title: sid,
        go: () => navigate("studio", sid),
      });
    const routes: Record<string, string> = {
      challenge: "challenges",
      team: "teams",
      incident: "incidents",
      scenario: "studio",
    };
    for (const row of remoteResults) {
      const kind = str(row.kind),
        id = str(row.id);
      const type = kind.charAt(0).toUpperCase() + kind.slice(1);
      if (result.some((r) => r.type === type && r.id === id)) continue;
      if (kind === "asset")
        result.push({
          type,
          id,
          title: str(row.title),
          go: () => {
            setPalette(false);
            inspectAsset(id);
          },
        });
      else if (routes[kind] && items.some((n) => n.id === routes[kind]))
        result.push({
          type,
          id,
          title: str(row.title),
          go: () => navigate(routes[kind], id),
        });
    }
    return result
      .filter((r) =>
        `${r.type} ${r.title} ${r.id}`
          .toLowerCase()
          .includes(query.toLowerCase()),
      )
      .slice(0, 40);
    // The memo is a convenience; all searchable records have already passed server projection.
  }, [query, routeState.route, data.snapshot, data.events, remoteResults]);
  const lifecycle = data.events.filter(
    (e) =>
      e.event_type === "scenario_started" || e.event_type === "scenario_ended",
  );
  const lastStart = lifecycle.find((e) => e.event_type === "scenario_started");
  const exerciseEnd =
    lifecycle[0]?.event_type === "scenario_ended" ? lifecycle[0] : null;
  const elapsed = lastStart
    ? Math.max(0, (exerciseEnd?.timestamp ?? wallClock) - lastStart.timestamp)
    : null;
  const observedPhase = data.events.find((e) => e.phase)?.phase;
  useEffect(() => {
    const timer = setInterval(() => setWallClock(Date.now() / 1000), 1000);
    return () => clearInterval(timer);
  }, []);
  const urgent = incidents.filter(
    (i) =>
      i.status !== "closed" &&
      (i.severity === "critical" || object(i.sla).resolution_breached === true),
  );
  const context = {
    session,
    data,
    scenarioId,
    navigate,
    inspectEvent,
    inspectAsset,
    entity: routeState.entity,
    notify: setToast,
  };
  function renderRoute() {
    if (["overview", "live"].includes(route))
      return <Overview warroom={warroom} />;
    if (route === "twin") return <DigitalTwin />;
    if (route === "assets") return <AssetList />;
    if (route === "events") return <EventStream />;
    if (["incidents", "soc"].includes(route)) return <Incidents />;
    if (route === "studio") return <Studio />;
    if (["replay", "aar", "analytics"].includes(route))
      return <Replay mode={route} />;
    if (route === "competition") return <Competition />;
    if (route === "training") return <Training />;
    if (route === "unauthorized")
      return (
        <EmptyState
          title="Workspace not authorized"
          detail="Your current role does not include this workspace."
          action={
            <Button onClick={() => navigate("overview")}>
              Return to overview
            </Button>
          }
        />
      );
    if (route === "settings")
      return (
        <div className="settings-grid">
          <section className="settings-card">
            <h2>Display preferences</h2>
            <label className="check-row">
              <input
                type="checkbox"
                checked={contrast}
                onChange={(e) => setContrast(e.target.checked)}
              />
              High contrast
            </label>
            <label className="check-row">
              <input
                type="checkbox"
                checked={!dense}
                onChange={(e) => setDense(!e.target.checked)}
              />
              Comfortable density
            </label>
            <p>
              Motion follows your system’s reduced-motion preference.
              Preferences are stored on this device.
            </p>
          </section>
          <section className="settings-card">
            <h2>Brand atmosphere preview</h2>
            <p>
              Optional Higgsfield animation. Play explicitly to preview;
              operational views use measured data and static evidence.
            </p>
            <video
              controls
              muted
              playsInline
              preload="none"
              className="brand-film"
              src={`${import.meta.env.BASE_URL}brand/live-atmosphere.mp4`}
              aria-label="Decorative digital range atmosphere preview"
            />
          </section>
          <section className="settings-card">
            <h2>Authenticated access</h2>
            <dl>
              <dt>Operator</dt>
              <dd>{session.actor}</dd>
              <dt>Role</dt>
              <dd>{session.role}</dd>
              <dt>Team</dt>
              <dd>{session.team_id || "No team membership"}</dd>
              <dt>Exercise</dt>
              <dd>{session.match_id || "Instructor / platform scope"}</dd>
            </dl>
            <p>All workspaces enforce permissions on the server.</p>
            <Button onClick={logout}>Sign out</Button>
          </section>
        </div>
      );
    return <Resources route={route} />;
  }
  return (
    <CommandContext.Provider value={context}>
      <div className={`command-app ${warroom ? "warroom" : ""}`}>
        <a
          href="#command-main"
          className="skip-link"
          onClick={(e) => {
            e.preventDefault();
            document.getElementById("command-main")?.focus();
          }}
        >
          Skip to workspace
        </a>
        <aside
          className={`sidebar ${mobileNav ? "sidebar-open" : ""}`}
          aria-label="Command navigation"
        >
          <a className="brand" href="#overview">
            <span className="brand-mark">
              <Icon name="command" size={25} />
            </span>
            <span>
              CYBER RANGE<b>COMMAND</b>
            </span>
            <span className="brand-version">01</span>
          </a>
          <div className="sidebar-context">
            <span className="eyebrow">OPERATIONAL WORKSPACE</span>
            <strong>
              <span className="status-square" />
              Cyber range operations
            </strong>
            <small>Authorized training environment</small>
          </div>
          <nav>
            {[...new Set(items.map((n) => n.group))].map((group) => (
              <div className="nav-group" key={group}>
                <h2>{group}</h2>
                {items
                  .filter((n) => n.group === group)
                  .map((item) => (
                    <a
                      key={item.id}
                      href={`#${item.id}`}
                      aria-current={route === item.id ? "page" : undefined}
                      onClick={() => setMobileNav(false)}
                    >
                      <Icon name={item.icon} />
                      <span>{item.label}</span>
                      {item.id === "incidents" && urgent.length > 0 && (
                        <b className="nav-count">{urgent.length}</b>
                      )}
                    </a>
                  ))}
              </div>
            ))}
          </nav>
          <div className="sidebar-footer">
            <span className="avatar">
              {session.actor.slice(0, 2).toUpperCase()}
            </span>
            <div>
              <b>{session.actor}</b>
              <small>
                {session.role} · {session.team_id || "Command access"}
              </small>
            </div>
            <Button aria-label="Sign out" onClick={logout}>
              <Icon name="arrow" size={15} />
            </Button>
          </div>
        </aside>
        {mobileNav && (
          <button
            className="nav-backdrop"
            aria-label="Close navigation"
            onClick={() => setMobileNav(false)}
          />
        )}
        <div className="command-body">
          <header className="command-header">
            <Button
              className="mobile-menu"
              aria-label="Open navigation"
              aria-expanded={mobileNav}
              onClick={() => setMobileNav((v) => !v)}
            >
              <Icon name="menu" />
            </Button>
            <div className="breadcrumbs">
              <span>Command platform</span>
              <Icon name="chevron" size={12} />
              <b>{current?.label || "Access restricted"}</b>
            </div>
            <div className="header-actions">
              <button
                className="palette-trigger"
                onClick={() => {
                  setQuery("");
                  setPalette(true);
                }}
              >
                <Icon name="search" />
                <span>Search range…</span>
                <kbd>⌘ K</kbd>
              </button>
              <Button
                aria-label="Open notification center"
                onClick={() => setNotifications(true)}
              >
                <Icon name="bell" />
                {urgent.length > 0 && (
                  <span className="notification-count">{urgent.length}</span>
                )}
              </Button>
              {session.capabilities.includes("copilot") && (
                <Button onClick={() => setCopilot(true)}>
                  <Icon name="command" />
                  <span className="hide-mobile">Copilot</span>
                </Button>
              )}
              <span className="environment-tag">LAB ONLY</span>
            </div>
          </header>
          <div className="global-status">
            <div>
              <span
                className={`connection-dot ${data.connection === "live" ? "live" : ""}`}
              />
              <b>
                {data.connection === "live"
                  ? "LIVE TELEMETRY"
                  : data.connection === "delayed"
                    ? `DELAYED ${session.observer_delay_sec}s`
                    : "TELEMETRY " + data.connection.toUpperCase()}
              </b>
            </div>
            <div>
              <span>Exercise</span>
              <b className="mono">{scenarioId}</b>
            </div>
            <div>
              <span>Sources</span>
              <b>
                {data.snapshot
                  ? `${sourceStatus.length - unavailable}/${sourceStatus.length} available`
                  : "Connecting"}
              </b>
            </div>
            {session.capabilities.includes("control") && (
              <div className="safety-global">
                <span>Emergency stop</span>
                <b
                  className={
                    safety.active_emergency_stop === true ? "text-critical" : ""
                  }
                >
                  {safety.active_emergency_stop === true
                    ? "ACTIVE"
                    : safety.active_emergency_stop === false
                      ? "Released"
                      : "Unavailable"}
                </b>
              </div>
            )}
            <div className="global-phase">
              <span>Observed phase</span>
              <b>{observedPhase || "Unavailable"}</b>
            </div>
            <div className="global-elapsed">
              <span>Elapsed</span>
              <b>{duration(elapsed)}</b>
            </div>
            <span className="global-spacer" />
            <span className="global-time">
              {data.snapshot
                ? "Snapshot " + time(data.snapshot.generated_at)
                : "Awaiting snapshot"}
            </span>
          </div>
          <main id="command-main" tabIndex={-1}>
            <div className="page-heading">
              <div>
                <span className="eyebrow">
                  {warroom
                    ? "MISSION DISPLAY"
                    : current?.group?.toUpperCase() || "COMMAND"}
                </span>
                <h1>
                  {warroom ? "War Room" : current?.label || "Access restricted"}
                </h1>
                <p>
                  {route === "overview"
                    ? "Your range, in focus. Operational state and the evidence behind it."
                    : route === "twin"
                      ? "Inspect the infrastructure. Follow observed activity across the authorized range."
                      : route === "events"
                        ? "A bounded, searchable record of live exercise activity."
                        : "Evidence-led operations within your assigned exercise scope."}
                </p>
              </div>
              <div className="page-actions">
                {session.role === "instructor" && (
                  <label className="scope-select">
                    <span>Exercise scope</span>
                    <select
                      value={scenarioId}
                      onChange={(e) => {
                        setScenarioId(e.target.value);
                        setInspector(null);
                      }}
                    >
                      <option value="default">Default exercise</option>
                      {[...new Set(availableScenarios)]
                        .filter((s) => s !== "default")
                        .map((s) => (
                          <option key={s}>{s}</option>
                        ))}
                    </select>
                  </label>
                )}
                <Button
                  onClick={() => {
                    setWarroom((v) => !v);
                    if (!warroom) navigate("overview");
                  }}
                >
                  <Icon name="expand" />
                  {warroom ? "Exit War Room" : "War Room"}
                </Button>
                {warroom && (
                  <Button
                    onClick={() => {
                      void document.documentElement
                        .requestFullscreen()
                        .catch(() =>
                          setToast(
                            "Fullscreen is unavailable in this browser.",
                          ),
                        );
                    }}
                  >
                    Fullscreen
                  </Button>
                )}
              </div>
            </div>
            {data.error && (
              <ErrorState
                message={data.error}
                retry={() => void data.refresh()}
              />
            )}
            {unavailable > 0 && (
              <div className="degraded-banner">
                <Icon name="incident" size={16} />
                {unavailable} source{unavailable === 1 ? " is" : "s are"}{" "}
                unavailable. Available evidence remains visible; missing values
                are not inferred.
                <Button onClick={() => void data.refresh()}>Reconnect</Button>
              </div>
            )}
            <Suspense fallback={<Skeleton />}>{renderRoute()}</Suspense>
          </main>
          <footer className="command-footer">
            <span>
              <Icon name="shield" size={13} />
              AUTHORIZED CYBER RANGE
            </span>
            <span>CYBER RANGE COMMAND SYSTEM · Human-led operations</span>
            <span>
              {data.events.length.toLocaleString()} buffered events / 5,000
            </span>
          </footer>
        </div>
        {palette && (
          <Dialog
            title="Command palette & global search"
            onClose={() => setPalette(false)}
          >
            <label className="search-label">
              Find a workspace, asset, incident, event or service
              <input
                autoFocus
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search authorized entities…"
                onKeyDown={(e) => {
                  if (e.key === "ArrowDown") {
                    e.preventDefault();
                    document
                      .querySelector<HTMLButtonElement>(
                        ".command-results button",
                      )
                      ?.focus();
                  }
                }}
              />
            </label>
            <div className="command-results">
              {searchResults.map((r, i) => (
                <button
                  key={`${r.type}:${r.id}`}
                  onClick={r.go}
                  onKeyDown={(e) => {
                    const list = Array.from(
                      document.querySelectorAll<HTMLButtonElement>(
                        ".command-results button",
                      ),
                    );
                    if (e.key === "ArrowDown") {
                      e.preventDefault();
                      list[(i + 1) % list.length]?.focus();
                    }
                    if (e.key === "ArrowUp") {
                      e.preventDefault();
                      list[(i + list.length - 1) % list.length]?.focus();
                    }
                  }}
                >
                  <span>
                    <b>{r.title}</b>
                    <small>{r.id}</small>
                  </span>
                  <span>
                    {r.type}
                    <Icon name="arrow" size={14} />
                  </span>
                </button>
              ))}
              {!searchResults.length && (
                <EmptyState
                  title="No authorized results"
                  detail="Try a workspace name, asset ID or incident title."
                />
              )}
            </div>
            <small className="muted">
              {searchStatus} Search includes authorized catalog and loaded
              evidence. Tab / ↑ ↓ to navigate, Enter to open, Escape to close.
            </small>
          </Dialog>
        )}
        {notifications && (
          <Drawer
            title="Notification center"
            onClose={() => setNotifications(false)}
          >
            <p className="muted">
              Grouped by severity. Repeated signals are consolidated into their
              incident.
            </p>
            {urgent.length ? (
              urgent.map((i) => (
                <button
                  className="notice-row"
                  key={str(i.id)}
                  onClick={() => {
                    navigate("incidents", str(i.id));
                    setNotifications(false);
                  }}
                >
                  <StatusBadge tone="critical">
                    {display(i.severity)}
                  </StatusBadge>
                  <span>{display(i.title)}</span>
                  <small>{str(i.id)}</small>
                </button>
              ))
            ) : (
              <EmptyState
                title="No urgent notifications"
                detail="Critical incidents and SLA breaches will be grouped here."
              />
            )}
            {data.notices.slice(0, 12).map((n) => (
              <div className="notice-row" key={n.id}>
                <StatusBadge
                  tone={n.topic === "safety" ? "warning" : "neutral"}
                >
                  {n.topic}
                </StatusBadge>
                <span>
                  {display(
                    n.payload.event_type ||
                      n.payload.event ||
                      n.payload.phase ||
                      n.payload.category,
                  )}
                </span>
                <time>{time(n.received / 1000)}</time>
              </div>
            ))}
          </Drawer>
        )}
        {inspector && (
          <Drawer
            title={
              inspector.type === "event" ? "Event evidence" : "Asset inspector"
            }
            onClose={() => setInspector(null)}
          >
            {inspector.type === "event" ? (
              selectedEvent ? (
                <>
                  <StatusBadge
                    tone={
                      selectedEvent.actor === "red" ? "warning" : "operational"
                    }
                  >
                    {selectedEvent.event_type}
                  </StatusBadge>
                  <dl className="facts">
                    <dt>Event ID</dt>
                    <dd className="mono">{selectedEvent.event_id}</dd>
                    <dt>Timestamp</dt>
                    <dd>{time(selectedEvent.timestamp)}</dd>
                    <dt>Correlation ID</dt>
                    <dd className="mono">
                      {selectedEvent.trace_id || "Unavailable"}
                    </dd>
                    <dt>MITRE mapping</dt>
                    <dd>
                      {techniques(selectedEvent).join(", ") ||
                        "Not provided by source"}
                    </dd>
                  </dl>
                  <div className="toolbar">
                    <Button
                      onClick={() => {
                        void navigator.clipboard
                          .writeText(selectedEvent.event_id)
                          .then(() => setToast("Event ID copied"))
                          .catch(() =>
                            setToast(
                              "Clipboard unavailable; select the ID above.",
                            ),
                          );
                      }}
                    >
                      Copy event ID
                    </Button>
                    <Button
                      onClick={() => inspectAsset(selectedEvent.target_asset)}
                    >
                      Inspect asset
                    </Button>
                    {str(selectedEvent.metadata.incident_id) &&
                      session.capabilities.includes("incidents") && (
                        <Button
                          onClick={() => {
                            navigate(
                              "incidents",
                              str(selectedEvent.metadata.incident_id),
                            );
                            setInspector(null);
                          }}
                        >
                          Jump to incident
                        </Button>
                      )}
                    {session.capabilities.includes("replay") && (
                      <Button
                        onClick={() => {
                          navigate("replay", selectedEvent.event_id);
                          setInspector(null);
                        }}
                      >
                        Jump to replay
                      </Button>
                    )}
                  </div>
                  <pre className="raw-payload">
                    {JSON.stringify(selectedEvent, null, 2)}
                  </pre>
                </>
              ) : (
                <EmptyState
                  title="Event is outside the current buffer"
                  detail="Open replay to inspect retained exercise history."
                />
              )
            ) : (
              <>
                <img
                  className="asset-atmosphere"
                  src={`${import.meta.env.BASE_URL}brand/sector-${inspector.id}.webp`}
                  alt=""
                  onError={(e) => {
                    e.currentTarget.style.display = "none";
                  }}
                />
                <h3>{selectedAsset?.name || inspector.id}</h3>
                <dl className="facts">
                  <dt>Identity</dt>
                  <dd className="mono">{inspector.id}</dd>
                  <dt>Protocol inventory</dt>
                  <dd>{selectedAsset?.protocol || "Unavailable"}</dd>
                  <dt>Authorized scope</dt>
                  <dd>Isolated training range</dd>
                  <dt>Health / latency</dt>
                  <dd>
                    See measured source status; unknown values are not inferred.
                  </dd>
                </dl>
                {!assetDetail ? (
                  <Skeleton label="Loading asset context" />
                ) : (
                  <>
                    <h3>Training vulnerability context</h3>
                    {objects(assetDetail.vulnerabilities).length ? (
                      objects(assetDetail.vulnerabilities).map((v) => (
                        <div className="evidence-row" key={str(v.id)}>
                          <b>
                            {str(v.id)} · {str(v.name)}
                          </b>
                          <p>{str(v.description)}</p>
                          <small>
                            {Array.isArray(v.mitre_attack)
                              ? v.mitre_attack.join(", ")
                              : "No mapping supplied"}
                          </small>
                        </div>
                      ))
                    ) : (
                      <p className="muted">
                        Vulnerability details are unavailable for this role or
                        asset.
                      </p>
                    )}
                  </>
                )}
                <h3>Recent observed events</h3>
                {data.events
                  .filter((e) => e.target_asset === inspector.id)
                  .slice(0, 10)
                  .map((e) => (
                    <button
                      className="notice-row"
                      key={e.event_id}
                      onClick={() => inspectEvent(e.event_id)}
                    >
                      <time>{time(e.timestamp)}</time>
                      <span>{e.event_type}</span>
                      <Icon name="chevron" size={14} />
                    </button>
                  ))}
              </>
            )}
          </Drawer>
        )}
        {copilot && (
          <Drawer title="AI assistance" onClose={() => setCopilot(false)}>
            <Suspense fallback={<Skeleton />}>
              <Copilot />
            </Suspense>
          </Drawer>
        )}
        {toast && (
          <div className="toast" role="status">
            {toast}
          </div>
        )}
      </div>
    </CommandContext.Provider>
  );
}
