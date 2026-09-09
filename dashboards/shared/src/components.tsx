import {
  Component,
  useEffect,
  useId,
  useRef,
  type ButtonHTMLAttributes,
  type ReactNode,
} from "react";
export type Tone =
  | "neutral"
  | "operational"
  | "warning"
  | "critical"
  | "healthy"
  | "intelligence";
const symbols: Record<Tone, string> = {
  neutral: "−",
  operational: "◉",
  warning: "△",
  critical: "!",
  healthy: "✓",
  intelligence: "◇",
};
export function Icon({ name, size = 18 }: { name: string; size?: number }) {
  const paths: Record<string, ReactNode> = {
    command: (
      <>
        <path d="M12 2 3 7v10l9 5 9-5V7Z" />
        <path d="m3 7 9 5 9-5M12 12v10M7.5 4.5l9 5" />
      </>
    ),
    overview: (
      <>
        <rect x="3" y="3" width="7" height="7" rx="1" />
        <rect x="14" y="3" width="7" height="7" rx="1" />
        <rect x="3" y="14" width="7" height="7" rx="1" />
        <rect x="14" y="14" width="7" height="7" rx="1" />
      </>
    ),
    activity: <path d="M2 12h5l3-8 4 16 3-8h5" />,
    network: (
      <>
        <rect x="8" y="2" width="8" height="6" rx="1" />
        <path d="M12 8v6M5 14h14M5 14v3M19 14v3" />
        <rect x="2" y="17" width="6" height="5" rx="1" />
        <rect x="16" y="17" width="6" height="5" rx="1" />
      </>
    ),
    shield: (
      <>
        <path d="M12 2 3 6v6c0 6 9 10 9 10s9-4 9-10V6Z" />
        <path d="m8 12 3 3 5-6" />
      </>
    ),
    incident: (
      <>
        <path d="m12 3 10 18H2Z" />
        <path d="M12 9v5M12 17v1" />
      </>
    ),
    search: (
      <>
        <circle cx="10" cy="10" r="6" />
        <path d="m15 15 6 6" />
      </>
    ),
    clock: (
      <>
        <circle cx="12" cy="12" r="9" />
        <path d="M12 7v5l4 2" />
      </>
    ),
    settings: (
      <>
        <path d="M4 6h16M4 12h16M4 18h16" />
        <circle cx="8" cy="6" r="2" />
        <circle cx="16" cy="12" r="2" />
        <circle cx="9" cy="18" r="2" />
      </>
    ),
    replay: (
      <>
        <path d="M3 10a9 9 0 1 1 2 8M3 4v6h6" />
        <path d="m10 8 6 4-6 4Z" />
      </>
    ),
    report: (
      <>
        <path d="M5 2h10l4 4v16H5Z" />
        <path d="M9 10h6M9 14h6M9 18h4" />
      </>
    ),
    users: (
      <>
        <circle cx="9" cy="7" r="3" />
        <path d="M3 21v-4a6 6 0 0 1 12 0v4M16 4a3 3 0 0 1 0 6M18 13a5 5 0 0 1 3 5v3" />
      </>
    ),
    server: (
      <>
        <rect x="3" y="3" width="18" height="7" rx="2" />
        <rect x="3" y="14" width="18" height="7" rx="2" />
        <path d="M7 6h1M7 17h1M12 6h5M12 17h5" />
      </>
    ),
    flag: (
      <>
        <path d="M5 22V3c5-4 9 4 14 0v11c-5 4-9-4-14 0" />
      </>
    ),
    bell: (
      <>
        <path d="M5 17h14l-2-3V9A5 5 0 0 0 7 9v5ZM9 21h6" />
      </>
    ),
    arrow: <path d="M4 12h16m-6-6 6 6-6 6" />,
    chevron: <path d="m9 5 7 7-7 7" />,
    close: <path d="m5 5 14 14M19 5 5 19" />,
    menu: <path d="M3 6h18M3 12h18M3 18h18" />,
    expand: <path d="M8 3H3v5M16 3h5v5M3 16v5h5M21 16v5h-5" />,
    bolt: <path d="m14 2-11 12h8l-1 8 11-13h-8Z" />,
    satellite: (
      <>
        <path d="m4 4 16 16M7 3l-4 4 5 5 4-4ZM16 12l-4 4 5 5 4-4Z" />
        <circle cx="12" cy="12" r="3" />
      </>
    ),
    factory: (
      <>
        <path d="M3 21V11l6-4v5l6-5v14ZM15 21h6L19 3h-3l-1 8M6 16v2M10 16v2" />
      </>
    ),
    water: (
      <path d="M12 2C9 7 4 11 4 15a8 8 0 0 0 16 0c0-4-5-8-8-13ZM8 15a4 4 0 0 0 4 4" />
    ),
    plane: <path d="m12 2 2 8 8 5v2l-8-2v5l2 2-4-1-4 1 2-2v-5l-8 2v-2l8-5Z" />,
    train: (
      <>
        <rect x="5" y="2" width="14" height="17" rx="3" />
        <path d="M5 10h14M12 2v8M8 14h1M15 14h1M8 19l-3 3M16 19l3 3" />
      </>
    ),
    medical: (
      <>
        <rect x="3" y="3" width="18" height="18" rx="2" />
        <path d="M12 7v10M7 12h10" />
      </>
    ),
  };
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {paths[name] || paths.command}
    </svg>
  );
}
export function StatusBadge({
  children,
  tone = "neutral",
}: {
  children: ReactNode;
  tone?: Tone;
}) {
  return (
    <span className={`cr-badge cr-tone-${tone}`}>
      <span aria-hidden="true">{symbols[tone]}</span>
      {children}
    </span>
  );
}
export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <StatusBadge
      tone={
        severity === "critical"
          ? "critical"
          : severity === "high"
            ? "warning"
            : severity === "medium"
              ? "intelligence"
              : "neutral"
      }
    >
      {severity}
    </StatusBadge>
  );
}
export function Button({
  children,
  tone = "neutral",
  className = "",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { tone?: Tone }) {
  return (
    <button
      type="button"
      className={`cr-button cr-button-${tone} ${className}`}
      {...props}
    >
      {children}
    </button>
  );
}
export function Panel({
  title,
  children,
  actions,
  className = "",
}: {
  title: string;
  children: ReactNode;
  actions?: ReactNode;
  className?: string;
}) {
  const id = useId();
  return (
    <section className={`cr-panel ${className}`} aria-labelledby={id}>
      <div className="cr-panel-heading">
        <h2 id={id}>{title}</h2>
        {actions}
      </div>
      {children}
    </section>
  );
}
export function MetricCard({
  label,
  value,
  detail,
  tone = "neutral",
  icon = "activity",
}: {
  label: string;
  value: ReactNode;
  detail?: ReactNode;
  tone?: Tone;
  icon?: string;
}) {
  return (
    <div className={`cr-metric cr-tone-${tone}`}>
      <div className="cr-metric-label">
        <span>{label}</span>
        <Icon name={icon} />
      </div>
      <strong>{value}</strong>
      <small>{detail ?? "No additional measurement"}</small>
    </div>
  );
}
export function EmptyState({
  title,
  detail,
  action,
  illustration,
}: {
  title: string;
  detail?: ReactNode;
  action?: ReactNode;
  illustration?: string;
}) {
  return (
    <div className="cr-empty">
      {illustration && (
        <img
          className="cr-empty-illustration"
          src={illustration}
          alt=""
          loading="lazy"
          onError={(e) => {
            e.currentTarget.style.display = "none";
          }}
        />
      )}
      <span className="cr-empty-icon">
        <Icon name="network" size={28} />
      </span>
      <h3>{title}</h3>
      {detail && <p>{detail}</p>}
      {action}
    </div>
  );
}
export function ErrorState({
  message,
  retry,
}: {
  message: string;
  retry?: () => void;
}) {
  return (
    <div className="cr-error" role="alert">
      <Icon name="incident" />
      <div>
        <strong>Unable to load this view</strong>
        <p>{message}</p>
      </div>
      {retry && <Button onClick={retry}>Retry</Button>}
    </div>
  );
}
export function Skeleton({ label = "Loading workspace" }: { label?: string }) {
  return (
    <div className="cr-skeleton" role="status">
      <span>{label}…</span>
      <div />
      <div />
      <div />
    </div>
  );
}
export function Dialog({
  title,
  children,
  onClose,
  wide = false,
}: {
  title: string;
  children: ReactNode;
  onClose: () => void;
  wide?: boolean;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  const callback = useRef(onClose);
  callback.current = onClose;
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    const dialog = ref.current;
    dialog?.showModal();
    return () => {
      dialog?.close();
      previous?.focus();
    };
  }, []);
  return (
    <dialog
      ref={ref}
      className={`cr-dialog ${wide ? "cr-dialog-wide" : ""}`}
      aria-labelledby={titleId}
      onCancel={(e) => {
        e.preventDefault();
        callback.current();
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget) callback.current();
      }}
    >
      <div className="cr-dialog-content">
        <header>
          <h2 id={titleId}>{title}</h2>
          <Button aria-label="Close dialog" onClick={onClose}>
            <Icon name="close" />
          </Button>
        </header>
        {children}
      </div>
    </dialog>
  );
}
export function Drawer({
  title,
  children,
  onClose,
}: {
  title: string;
  children: ReactNode;
  onClose: () => void;
}) {
  return (
    <Dialog title={title} onClose={onClose} wide>
      <div className="cr-inspector">{children}</div>
    </Dialog>
  );
}
export function DataTable({
  columns,
  rows,
  caption,
}: {
  columns: { key: string; label: string }[];
  rows: Record<string, ReactNode>[];
  caption: string;
}) {
  return (
    <div
      className="cr-table-scroll"
      tabIndex={0}
      role="region"
      aria-label={caption}
    >
      <table className="cr-table">
        <caption className="cr-sr-only">{caption}</caption>
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c.key} scope="col">
                {c.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i}>
              {columns.map((c) => (
                <td key={c.key}>{r[c.key] ?? "Unavailable"}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
      {!rows.length && (
        <EmptyState
          title="No records"
          detail="Records will appear when this source provides data."
        />
      )}
    </div>
  );
}
export function Timeline({
  items,
}: {
  items: {
    id: string;
    time: string;
    title: string;
    detail?: ReactNode;
    tone?: Tone;
  }[];
}) {
  return (
    <ol className="cr-timeline">
      {items.map((i) => (
        <li key={i.id} className={`cr-tone-${i.tone || "neutral"}`}>
          <time>{i.time}</time>
          <span className="cr-timeline-dot" />
          <div>
            <strong>{i.title}</strong>
            {i.detail && <p>{i.detail}</p>}
          </div>
        </li>
      ))}
    </ol>
  );
}
export function WorkspaceBar({ workspace }: { workspace: string }) {
  const gateway =
    location.pathname.startsWith("/blue") ||
    location.pathname.startsWith("/ops") ||
    location.pathname.startsWith("/red");
  const href = gateway
    ? "/control/"
    : `${location.protocol}//${location.hostname}:5180/`;
  return (
    <div className="cr-workspace-bar">
      <a href={href}>
        <Icon name="command" />
        <b>CYBER RANGE COMMAND</b>
      </a>
      <span>/</span>
      <span>{workspace}</span>
      <span className="cr-workspace-scope">AUTHORIZED TRAINING RANGE</span>
    </div>
  );
}
export class ErrorBoundary extends Component<
  { children: ReactNode },
  { error: boolean }
> {
  state = { error: false };
  static getDerivedStateFromError() {
    return { error: true };
  }
  render() {
    return this.state.error ? (
      <ErrorState
        message="The workspace encountered an unexpected error. Reload to reconnect to current data."
        retry={() => location.reload()}
      />
    ) : (
      this.props.children
    );
  }
}
