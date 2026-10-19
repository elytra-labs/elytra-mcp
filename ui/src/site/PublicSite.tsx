import { useEffect, useState } from "react";
import {
  ArrowRight,
  ArrowUpRight,
  Check,
  Code2,
  Fingerprint,
  Menu,
  ShieldCheck,
  X,
} from "lucide-react";
import { Logo } from "../components/Sidebar";
import { Code } from "../components/ui";
import "./styles/site-base.css";
import "./styles/home.css";
import HeroVisual from "./HeroVisual";
import { BoundarySection } from "./BoundarySection";
import { scrollToElement, SmoothScroll } from "./motion/SmoothScroll";

const CLOUD = import.meta.env.VITE_DEPLOY_TARGET === 'cloud';

/** Hosted sign-in is offered only once the deployment's backend answers; until then the site leads with the local install. */
let hostedCheck: Promise<boolean> | null = null;
function useHostedReady() {
  const [ready, setReady] = useState(false);
  useEffect(() => {
    if (!CLOUD) return;
    hostedCheck ??= fetch("/api/cloud/v1/config").then((r) => r.ok).catch(() => false);
    let live = true;
    void hostedCheck.then((ok) => live && setReady(ok));
    return () => { live = false; };
  }, []);
  return ready;
}
const REPO = "https://github.com/elytra-labs/elytra-mcp";
const INSTALL = `pipx install elytra-mcp   # or: python3 -m pip install elytra-mcp
elytra setup`;
const SOURCE_INSTALL = `git clone https://github.com/elytra-labs/elytra-mcp.git
cd elytra-mcp
(cd ui && npm ci && npm run build)
python3 -m pip install .`;
const hostedInstall = (origin: string) => `pipx install 'elytra-mcp[cloud]'
elytra login --cloud-url ${origin}
elytra up`;
const STEPS = [
  {
    label: "Read external context",
    tool: "github.get_issue",
    state: "Observed",
    note: "Issue content is external input. It does not grant the agent permission to use another tool.",
    type: "read",
  },
  {
    label: "Review the proposed action",
    tool: "postgres.run_query",
    state: "Held for review",
    note: "The run proposes a database write outside its exact grants. The destination is not called while approval is pending.",
    type: "held",
  },
  {
    label: "Make an explicit decision",
    tool: "Exact call · single execution",
    state: "Operator decision",
    note: "Approve this specific call or deny it. Approval is bound to its run, tool, arguments, and policy version; the connected client must claim it.",
    type: "decision",
  },
];

function Header({ currentPath }: { currentPath: string }) {
  const hosted = useHostedReady();
  const START = hosted ? "/signup" : "/docs";
  const [open, setOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  useEffect(() => {
    const update = () => setScrolled(window.scrollY > 40);
    update();
    window.addEventListener("scroll", update, { passive: true });
    return () => window.removeEventListener("scroll", update);
  }, []);
  return (
    <header className={`site-header ${scrolled || open ? "scrolled" : ""}`}>
      <a className="site-brand" href="/" aria-label="Elytra home">
        <Logo size={23} />
        <span>elytra</span>
      </a>
      <button
        className="site-menu"
        aria-expanded={open}
        aria-controls="site-navigation"
        aria-label={open ? "Close menu" : "Open menu"}
        onClick={() => setOpen(!open)}
      >
        {open ? <X size={20} /> : <Menu size={20} />}
      </button>
      <nav
        id="site-navigation"
        onClick={() => setOpen(false)}
        onKeyDown={(event) => {
          if (event.key === "Escape") {
            setOpen(false);
            document.querySelector<HTMLButtonElement>(".site-menu")?.focus();
          }
        }}
        className={open ? "site-nav open" : "site-nav"}
        aria-label="Main navigation"
      >
        <a href="/#product">Product</a>
        <a href="/#how-it-works">How it works</a>
        <a href="/docs" aria-current={currentPath === "/docs" ? "page" : undefined}>
          Documentation
        </a>
        <a href="/security" aria-current={currentPath === "/security" ? "page" : undefined}>
          Security
        </a>
        {hosted && <a href="/login">Sign in</a>}
        <a href={REPO} target="_blank" rel="noreferrer">
          GitHub <ArrowUpRight size={12} />
        </a>
        <a className="site-button small" href={START}>
          {hosted ? "Get started free" : "Get started"} <ArrowRight size={13} />
        </a>
      </nav>
    </header>
  );
}
function Footer() {
  return (
    <footer className="site-footer">
      <div>
        <a className="site-brand" href="/">
          <Logo size={19} />
          <span>elytra</span>
        </a>
        <p>
          Inspect the action.
          <br />
          Keep the decision yours.
        </p>
      </div>
      <nav aria-label="Resources">
        <a href="/docs">Documentation</a>
        <a href="/security">Security & data</a>
        <a href="/changelog">Changelog</a>
        <a href="/download">Install locally</a>
      </nav>
      <nav aria-label="Project">
        <a href={REPO}>
          Source code <ArrowUpRight size={12} />
        </a>
        <a href={`${REPO}/issues`}>
          Support & feedback <ArrowUpRight size={12} />
        </a>
        <a href={`${REPO}/security/policy`}>
          Report a vulnerability <ArrowUpRight size={12} />
        </a>
      </nav>
      <span className="site-footer-note">
        Early access software. Supported boundaries are documented.
      </span>
    </footer>
  );
}
function ProductIllustration({
  active = 1,
  onSelectStep,
}: {
  active?: number;
  onSelectStep?: (step: number) => void;
}) {
  return (
    <div
      className="product-window"
      aria-label="Illustrative example of a tool call held for review"
    >
      <div className="window-toolbar">
        <span className="window-dots">
          <i />
          <i />
          <i />
        </span>
        <span>elytra / runs / issue-triage</span>
        <span className="illustration-label">ILLUSTRATIVE EXAMPLE</span>
      </div>
      <div className="illustration-layout">
        <div className="mini-sidebar">
          <Logo size={19} />
          <span className={active === 0 ? "mini-selected" : ""}>Run activity</span>
          <span className={active !== 0 ? "mini-selected" : ""}>Approvals</span>
          <span>Tool integrity</span>
          <span>Policies</span>
          <div className="mini-local">Local workspace</div>
        </div>
        <div className="illustration-main">
          <div className="illustration-title">
            <div>
              <span className="site-eyebrow">EXPLICIT RUN</span>
              <h3>Investigate issue #218</h3>
            </div>
            <span className={`run-badge ${STEPS[active].type}`}>{STEPS[active].state}</span>
          </div>
          <div className="run-flow">
            <button
              type="button"
              className={`flow-point ${active === 0 ? "flow-active" : ""}`}
              onClick={() => onSelectStep?.(0)}
              aria-pressed={active === 0}
            >
              <span className="point-icon">
                <Code2 size={19} />
              </span>
              <strong>GitHub</strong>
              <span>External context</span>
            </button>
            <div className="flow-line" />
            <button
              type="button"
              className={`flow-point ${active === 1 ? "flow-active" : ""}`}
              onClick={() => onSelectStep?.(1)}
              aria-pressed={active === 1}
            >
              <span className="point-icon elytra">
                <Logo size={20} />
              </span>
              <strong>Elytra</strong>
              <span>Policy evaluation</span>
            </button>
            <div className="flow-line held" />
            <button
              type="button"
              className={`flow-point ${active === 2 ? "flow-active" : ""}`}
              onClick={() => onSelectStep?.(2)}
              aria-pressed={active === 2}
            >
              <span className="point-icon held">
                <ShieldCheck size={20} />
              </span>
              <strong>PostgreSQL</strong>
              <span>Approval required</span>
            </button>
          </div>
          <div className={`illustration-event ${STEPS[active].type}`}>
            <div className="event-marker" />
            <div>
              <span className="illustration-time">
                {active === 0
                  ? "OBSERVED CALL"
                  : active === 2
                    ? "EXACT CALL BOUNDARY"
                    : "PROPOSED CALL"}
              </span>
              <strong>
                {active === 0 ? "github.get_issue" : "postgres.run_query"}
              </strong>
              <code>
                {active === 0
                  ? "External issue content received"
                  : active === 2
                    ? "run + tool + arguments + policy version"
                    : "UPDATE customers SET email = …"}
              </code>
            </div>
            <span className="held-label">
              {active === 0 ? "Observed" : active === 2 ? "Review" : "Held"}
            </span>
          </div>
          <div className="illustration-explanation">
            <ShieldCheck size={17} />
            <div>
              <strong>
                {active === 0
                  ? "External content remains external input."
                  : active === 2
                    ? "Your decision applies to this call once."
                    : "A read does not grant permission to write."}
              </strong>
              <p>{STEPS[active].note}</p>
            </div>
          </div>
          <div className="illustration-bottom">
            <span>Destination not called</span>
            <span>
              Run-scoped decision <Check size={12} />
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
function Home() {
  const hosted = useHostedReady();
  const START = hosted ? "/signup" : "/docs";
  return (
    <>
      <section className="elytra-hero">
        <HeroVisual />
        <div className="hero-topline">
          <a href="/security">
            <i /> {hosted ? "YOUR RUNTIME. SHARED CONTROL." : "LOCAL SOFTWARE. EXPLICIT CONTROL."} <ArrowUpRight size={12} />
          </a>
          <span>{hosted ? "OPEN FREE BETA / OPEN SOURCE" : "EARLY ACCESS / OPEN SOURCE"}</span>
        </div>
        <div className="hero-composition">
          <div className="hero-copy">
            <span className="hero-category">
              THE MCP EXECUTION CONTROL PLANE
            </span>
            <h1>
              Let agents act.
              <br />
              <em>On your terms.</em>
            </h1>
            <p>
              Between what an agent reads and what it does, there should be a
              decision you can trust.
            </p>
            <p className="hero-detail">
              Inspect tool calls. Set permissions. Review consequential actions
              before they run.
            </p>
            <div className="site-actions">
              <a className="site-button primary" href={START}>
                {hosted ? "Get started free" : "Start building with Elytra"} <ArrowRight size={16} />
              </a>
              <a className="hero-demo-link" href="/demo/">
                Explore the workflow <ArrowUpRight size={14} />
              </a>
            </div>
            <a className="hero-install" href="/docs#installation">
              <span aria-hidden="true">$</span> pipx install elytra-mcp
              <ArrowUpRight size={13} />
            </a>
            <div className="hero-platforms">
              <span>WORKS WITH</span>
              <span>Claude Code</span>
              <i />
              <span>Codex</span>
              <i />
              <span>Grok</span>
              <i />
              <span>Antigravity</span>
            </div>
          </div>
        </div>
        <div className="hero-endnote">
          <span>01 / CONTROL AT THE POINT OF ACTION</span>
          <a href="#product">
            THE DETAILS <span>↓</span>
          </a>
        </div>
      </section>
      <section id="product" className="editorial-intro">
        <div className="section-label">
          <span>01 / THE PROBLEM</span>
          <span>READ ≠ PERMISSION</span>
        </div>
        <div className="editorial-copy">
          <h2>
            Your agent reads
            <br />
            the whole internet.
            <br />
            <em>
              It shouldn’t take
              <br />
              orders from it.
            </em>
          </h2>
          <div>
            <p>
              An issue, an email, a tool response. Useful context can carry
              instructions you never authorized.
            </p>
            <p>
              Elytra checks the next action against the permissions you actually
              gave. Keep the context useful. Keep the action accountable.
            </p>
            <a href="/security" className="site-text-link">
              Understand the security boundary <ArrowUpRight size={15} />
            </a>
          </div>
        </div>
      </section>
      <BoundarySection />
      <section className="principles-section">
        <div className="section-label">
          <span>03 / THE SYSTEM</span>
          <span>SMALL BOUNDARY. CLEAR RESPONSIBILITY.</span>
        </div>
        <h2>
          The tools are powerful.
          <br />
          <em>The permissions are precise.</em>
        </h2>
        <div className="principles-grid">
          <article>
            <span className="principle-number">01</span>
            <Code2 size={25} />
            <h3>Every run has an identity.</h3>
            <p>
              Connect your Python agent with an explicit run. Its permissions
              and decisions stay attached to that task, across MCP servers.
            </p>
            <a href="/docs#integration">
              Connect an agent <ArrowUpRight size={14} />
            </a>
          </article>
          <article>
            <span className="principle-number">02</span>
            <ShieldCheck size={25} />
            <h3>Every approval has a limit.</h3>
            <p>
              Review a specific tool call and its arguments. An approval is
              bound to that call, run, and policy version, for one claim.
            </p>
            <a href="/docs#permissions">
              See the approval model <ArrowUpRight size={14} />
            </a>
          </article>
          <article>
            <span className="principle-number">03</span>
            <Fingerprint size={25} />
            <h3>Changed tools get a review.</h3>
            <p>
              Know which tool metadata you classified. Unknown capabilities and
              changed fingerprints return to review before protected use.
            </p>
            <a href="/security#tool-integrity">
              Understand tool integrity <ArrowUpRight size={14} />
            </a>
          </article>
        </div>
      </section>
      <section className="local-section">
        <div className="section-label">
          <span>04 / YOUR ENVIRONMENT</span>
          <span>LOCAL BY DEFAULT</span>
        </div>
        <div className="local-layout">
          <div>
            <h2>
              Close to your tools.
              <br />
              <em>Under your control.</em>
            </h2>
            <p>
              {hosted ? "Your tools execute on your machine. Your team reviews redacted activity, versioned policies, and exact-call approvals in a shared workspace. MCP credentials and full results stay local." : "The runtime, console, and decision records live on your machine. No hosted team service is required. Start with one workflow and inspect the boundary yourself."}
            </p>
            <a className="site-text-link" href="/security">
              Data handling & supported boundaries <ArrowUpRight size={15} />
            </a>
          </div>
          <div className="local-diagram">
            <div className="local-diagram-title">YOUR LOCAL ENVIRONMENT</div>
            <div className="local-agent">
              YOUR PYTHON AGENT <span>explicit run identity</span>
            </div>
            <div className="local-connector" />
            <div className="local-runtime">
              <Logo size={30} />
              <strong>elytra</strong>
              <span>Inspect → Evaluate → Decide</span>
            </div>
            <div className="local-connector" />
            <div className="local-tools">
              <span>GitHub</span>
              <span>Database</span>
              <span>Your MCP server</span>
            </div>
            <p>
              Only calls routed through the supported integration are covered.
            </p>
          </div>
        </div>
      </section>
      <section className="site-final">
        <HeroVisual variant="ambient" />
        <span className="site-eyebrow">A GOOD PLACE TO START</span>
        <h2>
          One agent.
          <br />
          One workflow.
          <br />
          <em>Your decision.</em>
        </h2>
        <div className="site-actions">
          <a className="site-button primary" href={START}>
            {hosted ? "Create your workspace" : "Build your first boundary"} <ArrowRight size={16} />
          </a>
          <a className="site-text-link" href={REPO}>
            Explore the source <ArrowUpRight size={14} />
          </a>
        </div>
        <p>Early access software. Read the supported boundaries before use.</p>
      </section>
    </>
  );
}
function Walkthrough() {
  const [step, setStep] = useState(0);
  return (
    <div className="walkthrough">
      <span className="site-eyebrow">
        PRODUCT WALKTHROUGH · ILLUSTRATIVE ONLY
      </span>
      <h1>
        A read. A proposed write.
        <br />A decision you can inspect.
      </h1>
      <p className="walkthrough-lead">
        This interactive example uses no external services and connects to no
        runtime. It explains the decision flow.
      </p>
      <ProductIllustration active={step} onSelectStep={setStep} />
      <div className="walkthrough-controls">
        <div
          className="walkthrough-tabs"
          role="tablist"
          aria-label="Walkthrough steps"
        >
          {STEPS.map((s, i) => (
            <button
              id={`walkthrough-tab-${i}`}
              aria-controls="walkthrough-panel"
              role="tab"
              aria-selected={step === i}
              tabIndex={step === i ? 0 : -1}
              key={s.type}
              onKeyDown={(event) => {
                if (event.key === "ArrowRight" || event.key === "ArrowLeft") {
                  event.preventDefault();
                  const next =
                    (step + (event.key === "ArrowRight" ? 1 : 2)) %
                    STEPS.length;
                  setStep(next);
                  document.getElementById(`walkthrough-tab-${next}`)?.focus();
                }
              }}
              onClick={() => setStep(i)}
            >
              {i + 1}. {s.label}
            </button>
          ))}
        </div>
        <section
          id="walkthrough-panel"
          role="tabpanel"
          aria-labelledby={`walkthrough-tab-${step}`}
        >
          <span className="site-eyebrow">{STEPS[step].state}</span>
          <h2>{STEPS[step].tool}</h2>
          <p>{STEPS[step].note}</p>
          <button
            className="site-button secondary"
            onClick={() => setStep((step + 1) % STEPS.length)}
          >
            {step === 2 ? "Start again" : "Next step"} <ArrowRight size={14} />
          </button>
        </section>
      </div>
      <div className="doc-note">
        The illustration is an explanation, not evidence of a connected
        deployment. Run the local verification workflow to inspect your own
        execution records.
      </div>
      <a className="site-button primary" href="/docs">
        Set up a real workflow <ArrowRight size={15} />
      </a>
    </div>
  );
}
function Docs() {
  const hosted = useHostedReady();
  return (
    <div className="docs-layout">
      <aside className="docs-nav">
        <span className="site-eyebrow">DOCUMENTATION</span>
        <a href="#installation">Installation</a>
        <a href="#connect-agent">Protect your agent</a>
        <a href="#first-run">First run</a>
        <a href="#integration">Python integration</a>
        <a href="#permissions">Permissions & approvals</a>
        <a href="#desktop-hosts">Host sessions</a>
        <a href="#troubleshooting">Troubleshooting</a>
        <a href="#uninstall">Upgrade & uninstall</a>
      </aside>
      <article className="doc-content">
        <span className="site-eyebrow">GET STARTED</span>
        <h1>
          One workflow.
          <br />
          An explicit boundary.
        </h1>
        <p className="doc-lead">
          Elytra is an early access local runtime and console for inspecting MCP
          actions. Start with a Python agent that can provide a reliable run
          identity.
        </p>
        {hosted && <section id="hosted-workspace">
          <h2>Connect your hosted workspace</h2>
          <p><a href="/signup">Sign in with GitHub or Google</a>, create a workspace, then install the runtime on the machine where your MCP tools execute. Identity sign-in does not grant repository access.</p>
          <Code>{`elytra up
# In another terminal:
elytra login --cloud-url ${window.location.origin}`}</Code>
          <p>The cloud connector requires version 0.4.0a1 or newer. Stop any running standalone server first. The CLI opens a one-time browser confirmation. Check the device name, verification code, and selected workspace. The runtime connects outbound over HTTPS; keep local ports private. Start or restart elytra up after login to use its separate managed database.</p>
          <p>Review the synchronized tool metadata in <a href="/app/">your dashboard</a>. Use the protected Python integration below with an explicit run identity. Verify a harmless read, then confirm a held fixture cannot mutate its destination.</p>
          <div className="doc-note">Free beta limits: one owned workspace, three members, two devices, and 500 uploaded events per workspace daily. Cloud capacity is shared and finite. Activity is retained for 24 hours; bounded approvals and audit records for seven days. There are no automatic paid upgrades.</div>
        </section>}
        <section id="installation">
          <h2>Install</h2>
          <p>
            Use Python 3.11 or newer. Elytra is published on PyPI as{" "}
            <a href="https://pypi.org/project/elytra-mcp/">elytra-mcp</a>; pipx keeps it in its own
            environment. Setup is guided and asks before it changes anything.
          </p>
          <Code>{hosted ? hostedInstall(window.location.origin) : INSTALL}</Code>
          <p>
            Setup runs the runtime in the background and opens the local console with a
            one-time pairing link. To pair later, run elytra connect --open. For
            manual pairing, run elytra connect --code and enter that code in the
            console. To run the runtime in the foreground instead, use elytra up --open.
          </p>
          <div className="doc-note">
            To install from a source checkout, build the console first (Node.js 22.12+):
          </div>
          <Code>{SOURCE_INSTALL}</Code>
        </section>
        <section id="connect-agent">
          <h2>Protect Claude Code, Codex, Grok or Antigravity</h2>
          <p>
            One command puts your coding agent behind local guardrails. Elytra checks the agent&apos;s
            own actions (shell commands, file edits, web access) through the agent&apos;s hook system,
            and its MCP tools through Elytra&apos;s proxy. Elytra never receives your tools&apos;
            credentials: each tool keeps its own keys on your machine.
          </p>
          <Code>{`elytra setup     # guided, about a minute
# restart your agent, then work as usual
elytra open      # review held actions
elytra uninstall # restore every agent configuration`}</Code>
          <p>
            Setup runs the runtime in the background, installs action hooks for Claude Code, Codex,
            Grok and Antigravity, and wraps local MCP servers (also for Cursor, Claude Desktop, Windsurf
            and VS Code) with a backup. Codex asks you once to trust Elytra&apos;s plugin. Recognized
            MCP servers get suggested classifications; anything unlisted or changed waits for your review.
          </p>
          <dl>
            <dt>Reads</dt>
            <dd>Reading files, searching, git status and diff. Always run.</dd>
            <dt>Untrusted web reads</dt>
            <dd>Fetching pages, issues and pull requests. Run, and mark the session as untrusted.</dd>
            <dt>Edits and unrecognized commands</dt>
            <dd>File edits, commits, builds, scripts. Treated as writes.</dd>
            <dt>Sends</dt>
            <dd>git push, POST requests, comments, publishing, uploads.</dd>
            <dt>Deletes and history rewrites</dt>
            <dd>rm -r, DROP TABLE, force push, hard reset, git clean. Always need a decision.</dd>
          </dl>
          <dl>
            <dt>Balanced (default)</dt>
            <dd>Reads run. Writes run in a clean session. Writes after the agent reads untrusted content, sends, and deletes or payments ask you. Sending data out after untrusted reads is blocked.</dd>
            <dt>Cautious</dt>
            <dd>Every write and send asks you.</dd>
            <dt>Autonomous</dt>
            <dd>Only destructive or financial actions ask you. Sending data out after untrusted reads is blocked.</dd>
          </dl>
          <p>
            When an action needs you, Claude Code and Grok show their own prompt with Elytra&apos;s reason.
            Codex and Antigravity, and any agent running with permissions bypassed, wait up to ten
            minutes while Elytra sends a desktop notification. Change presets or disconnect an agent on
            the console&apos;s Guardrails page.
          </p>
          <div className="doc-note">
            Coverage is per agent host process, not per conversation. Shell classification is a
            heuristic, and an agent can still act outside its hooks (for example through a script it
            writes and runs, which is checked only as an unrecognized command). Read{" "}
            <a href="/security">what host sessions establish</a>.
          </div>
        </section>
        <section id="first-run">
          <h2>Verify the first run</h2>
          <ol>
            <li>
              Open the local console and select <strong>Setup</strong>. A new
              workspace starts empty.
            </li>
            <li>
              Review coverage and tools. Read each tool’s metadata before
              acknowledging its fingerprint and capability category.
            </li>
            <li>
              Create a named run. Begin with no exact grants; consequential
              actions can then require review.
            </li>
            <li>
              Use the run identity and token in your Python integration. Route
              tool execution through the guarded call boundary.
            </li>
            <li>
              Run a harmless read and a fixture that proposes a write. Confirm
              the records belong to your run and that a held call does not reach
              the destination.
            </li>
          </ol>
          <p>
            The <a href="/app/#/setup">local setup console</a> is available on
            the machine running Elytra. A hosted copy of this website cannot
            connect to your localhost runtime.
          </p>
        </section>
        <section id="integration">
          <h2>Connect your Python agent</h2>
          <p>
            Each task needs its own run. Reuse the run across that task’s MCP
            servers; do not share it across unrelated conversations. Use the
            exact integration example in your local Setup screen, which reflects
            your installed runtime.
          </p>
          <Code>{`from mirage_mcp.sdk import RuntimeClient

# Pairing credentials and a run token are secrets.
# See the local Setup screen for a complete integration.
client = RuntimeClient()`}</Code>
          <p>
            A guarded tool call first evaluates with the runtime. Allowed calls
            dispatch to the destination; held calls await an exact approval;
            denied or expired calls must not dispatch. Direct calls around this
            boundary are outside coverage.
          </p>
          <a className="site-text-link" href={`${REPO}/tree/main/examples`}>
            Integration examples in the repository <ArrowUpRight size={14} />
          </a>
        </section>
        <section id="permissions">
          <h2>Permissions and approvals</h2>
          <p>
            A run’s intent describes the task for an operator. It does not
            automatically authorize actions. Exact grants bind a server, tool,
            and arguments; the runtime also applies classification, schema
            checks, and saved policies.
          </p>
          <p>
            Before approving a call, inspect its source lineage and complete
            arguments through a trusted channel. An approval applies once to the
            recorded call and its policy version. Changed arguments, an expired
            request, or a different run require a new decision.
          </p>
          <div className="doc-note">
            Approval does not itself execute a tool. The connected client must
            claim the approved request and dispatch it once.
          </div>
        </section>
        <section id="desktop-hosts">
          <h2>Host sessions and explicit runs</h2>
          <p>
            Agents set up with elytra setup are grouped by the process that launched their MCP
            servers. Claude Code starts one session per running claude process; Claude Desktop and
            Cursor usually share one session per app launch. That is broader than a single
            conversation, and it errs toward asking more often, not less.
          </p>
          <p>
            For per-task identity, use the Python integration with an explicit run. It ties every call
            to one task you created and can carry exact grants.
          </p>
        </section>
        <section id="troubleshooting">
          <h2>Troubleshooting</h2>
          <dl>
            <dt>The console cannot connect</dt>
            <dd>
              Confirm the CLI is still running and open its printed address. Run
              elytra connect --open to pair this browser. An internet-hosted
              website cannot access a local runtime.
            </dd>
            <dt>No tools or events appear</dt>
            <dd>
              Register tools through the integration and make a guarded call.
              Discovery alone does not send calls through Elytra.
            </dd>
            <dt>A call remains held</dt>
            <dd>
              Check Approvals and its expiry. Ensure the originating client is
              still waiting and uses the same run identity.
            </dd>
            <dt>A tool schema changed</dt>
            <dd>
              Review the new metadata and fingerprint. Reclassify only if you
              trust the new version and understand its capabilities.
            </dd>
          </dl>
          <p>
            For support, <a href={`${REPO}/issues`}>open an issue</a> with the
            version and a sanitized reproduction. Never include tokens, pairing
            codes, customer payloads, or database files.
          </p>
        </section>
        <section id="uninstall">
          <h2>Upgrade or uninstall</h2>
          <p>
            Upgrade with <code>pipx upgrade elytra-mcp</code>, then run{" "}
            <code>elytra service restart</code>. Restarting cancels held calls; agents
            reopen their sessions automatically. Inspect the changelog first.
          </p>
          <p>
            To uninstall, run <code>elytra uninstall</code> to restore every agent
            configuration and remove the background service, then{" "}
            <code>pipx uninstall elytra-mcp</code>.
            Local records remain until you explicitly delete the runtime data
            directory. Deleting those files permanently removes your audit
            history.
          </p>
        </section>
      </article>
    </div>
  );
}
function Security() {
  const hosted = useHostedReady();
  return (
    <article className="doc-content single-doc">
      <span className="site-eyebrow">SECURITY & DATA</span>
      <h1>
        Trust requires
        <br />a visible boundary.
      </h1>
      <p className="doc-lead">
        Elytra is early access security tooling. Understand what your
        integration routes through it, what it records, and what it cannot
        establish.
      </p>
      <section>
        <h2>What is covered</h2>
        <p>
          The supported Python integration supplies an explicit run identity
          across MCP servers. Calls routed through that integration are checked
          by the local runtime before destination execution. Calls made directly
          or through unintegrated clients are outside this boundary.
        </p>
        <p>
          Agents set up with elytra setup use host sessions: calls are grouped by the agent host
          process that launched the MCP servers, using a host credential that can open sessions but
          cannot classify tools, change policy, or approve calls. Host sessions are broader than one
          conversation. Remote MCP servers that the host reaches over HTTP are not covered.
        </p>
        <p>
          Permissions, saved policies, tool metadata checks, and approval
          records contribute to decisions. Text provenance is supporting
          evidence. It does not prove intent or detect every malicious
          instruction.
        </p>
      </section>
      <section id="tool-integrity">
        <h2>Tool integrity and classification</h2>
        <p>
          Tools are identified by server, name, and a SHA-256 fingerprint of
          their metadata. An operator reviews metadata and assigns a capability
          category. Unknown or changed tools require review before protected
          execution.
        </p>
        <p>
          Fingerprinting identifies a version, not a trustworthy implementation.
          A malicious server can misdescribe its tools or change behavior
          without changing its advertised schema.
        </p>
      </section>
      <section>
        <h2>Data stays with the runtime</h2>
        <p>
          By default, the runtime stores decision records in a local SQLite
          database. Records can include run intent, tool identifiers, arguments
          previews, provenance evidence, policy versions, and approval
          decisions. Treat this directory as sensitive.
        </p>
        <p>
          Recognized secret patterns are redacted in stored previews. Pattern
          matching cannot identify all secrets; it does not make arbitrary
          payloads safe to publish. Review exported records before sharing them.
        </p>
        <p>
          {hosted ? "When you connect Elytra Cloud, the runtime uploads bounded, redacted tool definitions, run summaries, call argument previews, digests, policy versions, approval requests, and compact activity. Full tool results, MCP credentials, local owner tokens, and run tokens stay on your machine. Review data before connecting: automatic redaction cannot recognize every secret." : "This public site does not connect to your local runtime. The local console communicates with its same-origin runtime. No hosted team service is required for standalone use."}
        </p>
      </section>
      {hosted && <section>
        <h2>Hosted management and retention</h2>
        <p>GitHub or Google supplies your account identity. Supabase stores workspace membership and management records; the Elytra API authenticates management requests. Members can read workspace data. Owners and admins can change policies and decide approvals. Invitation links are email-bound and expire after seven days.</p>
        <p>Cloud activity expires after 24 hours; approval, command, and audit history is bounded to seven days. Expired records are hidden from activity views and physically removed by the next successful daily cleanup. Device revocation takes effect in cloud immediately; a runtime may retain its existing management lease for up to five minutes. Lost connectivity cannot grant new permissions. Capacity exhaustion makes cloud management unavailable rather than upgrading your account.</p>
        <p>Delete a workspace or account from dashboard settings to revoke cloud access and remove its cloud records. Local databases and external tool processes are not erased by cloud deletion. This beta does not promise uninterrupted availability or provider backups.</p>
      </section>}
      <section>
        <h2>Local access and credentials</h2>
        <p>
          The runtime binds to loopback by default. Browser access requires
          pairing; mutations require a valid session and approved origin. Run
          tokens grant access to their run and should be handled as credentials.
        </p>
        <p>
          Do not expose the local runtime directly to the internet. Local
          administrators, compromised dependencies, and software with access to
          your process or data directory remain outside its protection boundary.
        </p>
      </section>
      <section>
        <h2>Approval integrity</h2>
        <p>
          An approval is bound to one pending call, its argument digest, run,
          and policy version. It has an expiry. The originating integration must
          claim it before dispatch, and a denial or invalid approval must
          prevent dispatch.
        </p>
        <p>
          A crash after dispatch can leave execution uncertain. Exactly one
          claim prevents duplicate authorization; it cannot provide a
          transaction across an arbitrary remote tool and the local database.
          Inspect the destination before retrying an uncertain action.
        </p>
      </section>
      <section>
        <h2>Evidence and limitations</h2>
        <p>
          Synthetic regression scenarios are development checks. They are not
          measurements of general protection, production false positives, or
          competitor performance. We do not claim perfect detection or zero
          overhead.
        </p>
        <p>
          Elytra is not a replacement for sandboxing, least-privilege service
          credentials, network controls, destination authorization, or review of
          high impact operations.
        </p>
      </section>
      <section>
        <h2>Report a vulnerability</h2>
        <p>
          Use the repository’s{" "}
          <a href={`${REPO}/security/policy`}>
            security reporting instructions
          </a>
          . Do not post secrets, exploit payloads affecting a live system, or
          customer data in a public issue. General bugs and sanitized feedback
          can use <a href={`${REPO}/issues`}>GitHub Issues</a>.
        </p>
      </section>
    </article>
  );
}
function Changelog() {
  const hosted = useHostedReady();
  return (
    <article className="doc-content single-doc">
      <span className="site-eyebrow">CHANGELOG</span>
      <h1>
        Building a boundary
        <br />
        you can inspect.
      </h1>
      <p className="doc-lead">
        Changes are available in source. A published release and a source
        checkout are different distribution states.
      </p>
      <section>
        <span className="changelog-tag">UNRELEASED · EARLY ACCESS</span>
        <h2>Explicit runs and a complete product entry point</h2>
        <ul>
          <li>
            Public homepage, installation guide, security model, and
            illustrative walkthrough.
          </li>
          <li>
            Fresh local workspace and setup flow for tool review and explicit
            run creation.
          </li>
          <li>
            Run-scoped execution, exact call approvals, and runtime policy
            enforcement.
          </li>
          <li>Local session pairing and packaged console resources.</li>
          <li>
            Evaluation results labeled as synthetic; unsupported baseline claims
            withdrawn.
          </li>
        </ul>
        <a className="site-text-link" href={`${REPO}/commits/main`}>
          View source history <ArrowUpRight size={14} />
        </a>
      </section>
      <section>
        <h2>Release availability</h2>
        <p>
          Releases are published on{" "}
          <a href="https://pypi.org/project/elytra-mcp/">PyPI as elytra-mcp</a>, with
          release notes on this page. {hosted ? "The hosted dashboard is an open free beta. Install a runtime release that supports elytra login to connect it." : "Standalone use does not require a hosted team account."}
        </p>
      </section>
    </article>
  );
}
function Download() {
  const hosted = useHostedReady();
  return (
    <article className="doc-content single-doc">
      <span className="site-eyebrow">INSTALL ELYTRA</span>
      <h1>
        Your workflow.
        <br />
        Your local runtime.
      </h1>
      <p className="doc-lead">
        {hosted ? "Install the runtime where your tools execute, then connect it to your hosted workspace. Standalone local use is also available without an account." : "Install from PyPI. There is no account to create and no hosted service to connect."}
      </p>
      <section>
        <h2>Install</h2>
        <Code>{hosted ? hostedInstall(window.location.origin) : INSTALL}</Code>
        <p>
          Python 3.11 or newer is required. The package includes the local console;
          building from source needs Node.js 22.12+ for the console.
        </p>
        <div className="site-actions">
          <a className="site-button primary" href="/docs">
            Full installation guide <ArrowRight size={15} />
          </a>
          <a className="site-button secondary" href={`${REPO}/releases`}>
            Check release artifacts <ArrowUpRight size={14} />
          </a>
        </div>
      </section>
      <section>
        <h2>Already running locally?</h2>
        <p>
          Open the address printed by your CLI, then run elytra connect --open
          to pair the browser. On that local server, the console is available at{" "}
          <code>/app/</code>.
        </p>
        <p>
          This site does not auto-discover, connect to, or send requests to
          services on your computer.
        </p>
      </section>
    </article>
  );
}
export function PublicSite() {
  const [path, setPath] = useState(
    () => window.location.pathname.replace(/\/+$/, "") || "/",
  );
  useEffect(() => {
    const sync = () =>
      setPath(window.location.pathname.replace(/\/+$/, "") || "/");
    window.addEventListener("popstate", sync);
    return () => window.removeEventListener("popstate", sync);
  }, []);
  const title =
    path === "/docs"
      ? "Documentation"
      : path === "/security"
        ? "Security & data"
        : path === "/changelog"
          ? "Changelog"
          : path === "/download"
            ? "Install"
            : path === "/demo"
              ? "Walkthrough"
              : "Inspect MCP actions";
  useEffect(() => {
    document.title = `${title} · Elytra`;
  }, [title]);
  const page =
    path === "/docs" ? (
      <Docs />
    ) : path === "/security" ? (
      <Security />
    ) : path === "/changelog" ? (
      <Changelog />
    ) : path === "/download" ? (
      <Download />
    ) : path === "/demo" ? (
      <Walkthrough />
    ) : path === "/" ? (
      <Home />
    ) : (
      <article className="doc-content single-doc">
        <h1>Page not found.</h1>
        <p>
          Return to the <a href="/">homepage</a> or{" "}
          <a href="/docs">documentation</a>.
        </p>
      </article>
    );
  return (
    <div
      className={`public-site ${path === "/" ? "public-home" : "public-document"}`}
      onClick={(event) => {
        if (
          event.defaultPrevented ||
          event.button !== 0 ||
          event.metaKey ||
          event.ctrlKey ||
          event.shiftKey ||
          event.altKey
        )
          return;
        const anchor = (event.target as HTMLElement | null)?.closest("a");
        if (!anchor || anchor.target || anchor.hasAttribute("download")) return;
        const href = anchor.getAttribute("href");
        if (!href || href.startsWith("#")) return;
        let url: URL;
        try {
          url = new URL(href, window.location.origin);
        } catch {
          return;
        }
        if (url.origin !== window.location.origin) return;
        if (
          /^\/(?:app(?:\/|$)|login(?:\/|$)|signup(?:\/|$)|auth\/callback(?:\/|$))/.test(
            url.pathname,
          )
        )
          return;
        const nextPath = url.pathname.replace(/\/+$/, "") || "/";
        if (
          !["/", "/docs", "/security", "/changelog", "/download", "/demo"].includes(
            nextPath,
          )
        )
          return;
        event.preventDefault();
        window.history.pushState({}, "", url.pathname + url.search + url.hash);
        setPath(nextPath);
        window.requestAnimationFrame(() => {
          if (url.hash) {
            const target = document.getElementById(url.hash.slice(1));
            if (target) {
              scrollToElement(target);
              return;
            }
          }
          scrollToElement(null);
          document.getElementById("site-main")?.focus({ preventScroll: true });
        });
      }}
    >
      <SmoothScroll />
      <a className="skip-link" href="#site-main">
        Skip to content
      </a>
      <Header currentPath={path} />
      <main id="site-main" tabIndex={-1}>
        {page}
      </main>
      <Footer />
    </div>
  );
}
