import { Activity, Check, KeyRound, Settings2, ShieldCheck, X } from "lucide-react";
import { Logo } from "../components/Sidebar";
import { Badge, Chain } from "../components/ui";

/**
 * Illustrative console window for the workflow section. Built from the real
 * console primitives so the page shows the product as it looks; the data is
 * an example run and connects to nothing.
 */

const NAV = [
  { label: "Setup", icon: Settings2, step: 0 },
  { label: "Activity", icon: Activity, step: 1 },
  { label: "Approvals", icon: KeyRound, step: 2 },
  { label: "Tool integrity", icon: ShieldCheck, step: -1 },
];

function RunPanel() {
  return (
    <div className="shot-panel">
      <div className="shot-heading">
        <span>Setup</span>
        <h4>Explicit run</h4>
      </div>
      <dl className="shot-meta">
        <dt>Run</dt>
        <dd className="mono">run_7f3a2c</dd>
        <dt>Intent</dt>
        <dd>Triage issue #218 and record a summary</dd>
        <dt>Grants</dt>
        <dd><Badge>None</Badge></dd>
        <dt>Coverage</dt>
        <dd><Badge tone="green" dot>Explicit run</Badge></dd>
      </dl>
      <p className="shot-note">Every call that follows is attributed to this run.</p>
    </div>
  );
}

function ActivityPanel({ approved }: { approved: boolean }) {
  return (
    <div className="shot-panel">
      <div className="shot-heading">
        <span>Activity</span>
        <h4>run_7f3a2c</h4>
      </div>
      <table className="table shot-table">
        <thead>
          <tr><th>Decision</th><th>Tool call</th><th>Server</th></tr>
        </thead>
        <tbody>
          {approved && (
            <>
              <tr><td><Badge tone="neutral" dot>Replay refused</Badge></td><td className="mono">postgres.run_query</td><td>database</td></tr>
              <tr><td><Badge tone="green" dot>Dispatched once</Badge></td><td className="mono">postgres.run_query</td><td>database</td></tr>
            </>
          )}
          <tr><td><Badge tone="green" dot>Allowed</Badge></td><td className="mono">github.get_issue</td><td>github</td></tr>
        </tbody>
      </table>
      <p className="shot-note">
        {approved ? (
          <><Check size={13} /> Approval claimed once. A second claim for the same call is refused.</>
        ) : (
          <><i className="shot-dot amber" /> Untrusted context recorded for this run.</>
        )}
      </p>
    </div>
  );
}

function ApprovalsPanel() {
  return (
    <div className="shot-panel">
      <div className="shot-heading">
        <span>Approvals</span>
        <h4>1 pending</h4>
      </div>
      <table className="table shot-table">
        <thead>
          <tr><th>Tool call</th><th>Status</th><th>Expiry</th></tr>
        </thead>
        <tbody>
          <tr className="selected">
            <td><span className="mono">postgres.run_query</span><div className="cell-sub">database / default-approval</div></td>
            <td><Badge tone="amber" dot>Pending</Badge></td>
            <td className="mono shot-expiry">Expires in 1:42</td>
          </tr>
        </tbody>
      </table>
      <p className="shot-note"><i className="shot-dot amber" /> The destination is not called while the request is pending.</p>
    </div>
  );
}

function ReviewPanel() {
  return (
    <div className="shot-panel shot-review">
      <div className="shot-heading">
        <span>Review request</span>
        <h4 className="mono">postgres.run_query</h4>
      </div>
      <p className="shot-reason">Untrusted input preceded this action; approval required</p>
      <pre className="shot-code">{'{\n  "sql": "UPDATE customers SET email = …"\n}'}</pre>
      <Chain nodes={["github.get_issue", "postgres.run_query"]} heldLast />
      <dl className="shot-meta compact">
        <dt>Bound to</dt>
        <dd>run, call, arguments digest, schema, policy version</dd>
        <dt>Expires</dt>
        <dd className="mono">1:42</dd>
      </dl>
      <div className="shot-actions">
        <span className="btn danger sm"><X size={13} /> Deny call</span>
        <span className="btn primary sm"><Check size={13} /> Approve exact call</span>
      </div>
    </div>
  );
}

export function ConsoleShot({ step }: { step: number }) {
  const activeNav = step === 0 ? 0 : step === 1 || step === 4 ? 1 : 2;
  const panels = [<RunPanel key="run" />, <ActivityPanel key="activity" approved={false} />, <ApprovalsPanel key="approvals" />, <ReviewPanel key="review" />, <ActivityPanel key="receipt" approved />];
  return (
    <div className="console-shot" aria-hidden="true">
      <div className="shot-toolbar">
        <span className="shot-dots"><i /><i /><i /></span>
        <span>elytra · local console</span>
        <span className="shot-tag">ILLUSTRATIVE</span>
      </div>
      <div className="shot-body">
        <nav className="shot-nav">
          <span className="shot-brand"><Logo size={15} /> elytra</span>
          {NAV.map(({ label, icon: Icon, step: s }) => (
            <span key={label} className={s === activeNav ? "on" : ""}>
              <Icon size={14} /> {label}
              {label === "Approvals" && (step === 2 || step === 3) && <b>1</b>}
            </span>
          ))}
        </nav>
        <div className="shot-stage">
          {panels.map((panel, i) => (
            <div key={i} className={`shot-state ${i === step ? "active" : ""}`}>
              {panel}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
