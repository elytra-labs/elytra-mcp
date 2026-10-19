import React, { useId, useRef, useState } from 'react';
import { Check, Copy, X } from 'lucide-react';
import { copyText, decisionMeta, toolLabel, type Tone } from '../lib/format';
import { useDialogFocus } from '../lib/useDialogFocus';

/* ---------- Badge ---------- */

export function Badge({
  tone = 'neutral',
  dot = false,
  square = false,
  children,
  title,
}: {
  tone?: Tone;
  dot?: boolean;
  square?: boolean;
  children: React.ReactNode;
  title?: string;
}) {
  return (
    <span className={`badge ${tone !== 'neutral' ? tone : ''} ${square ? 'square' : ''}`} title={title}>
      {dot && <span className="dot" />}
      {children}
    </span>
  );
}

export function DecisionBadge({ decision }: { decision: string }) {
  const m = decisionMeta(decision);
  return (
    <Badge tone={m.tone} dot>
      {m.label}
    </Badge>
  );
}

export function Dot({ tone = 'neutral' }: { tone?: Tone }) {
  return <span className={`dot ${tone}`} />;
}

/* ---------- Page header ---------- */

export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description?: React.ReactNode;
  actions?: React.ReactNode;
}) {
  return (
    <div className="page-header">
      <div>
        <h1 className="page-title">{title}</h1>
        {description && <p className="page-desc">{description}</p>}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </div>
  );
}

/* ---------- Card ---------- */

export function Card({
  title,
  description,
  action,
  children,
  footer,
  bodyClass = 'card-body',
  plainHeader = false,
  style,
}: {
  title?: React.ReactNode;
  description?: React.ReactNode;
  action?: React.ReactNode;
  children: React.ReactNode;
  footer?: React.ReactNode;
  bodyClass?: string;
  plainHeader?: boolean;
  style?: React.CSSProperties;
}) {
  return (
    <section className="card" style={style}>
      {(title || action) && (
        <header className={`card-header ${plainHeader ? 'plain' : ''}`}>
          <div style={{ minWidth: 0 }}>
            {title && <h2 className="card-title">{title}</h2>}
            {description && <p className="card-desc">{description}</p>}
          </div>
          {action}
        </header>
      )}
      <div className={bodyClass}>{children}</div>
      {footer && <footer className="card-footer">{footer}</footer>}
    </section>
  );
}

/* ---------- Stat ---------- */

export function Stat({
  label,
  value,
  unit,
  hint,
  icon,
  tone,
}: {
  label: string;
  value: React.ReactNode;
  unit?: string;
  hint?: React.ReactNode;
  icon?: React.ReactNode;
  tone?: Tone;
}) {
  return (
    <div className="card stat">
      <div className="stat-label">
        {icon}
        {label}
      </div>
      <div className="stat-value" style={tone && tone !== 'neutral' ? { color: `var(--${tone})` } : undefined}>
        {value}
        {unit && <span className="stat-unit">{unit}</span>}
      </div>
      {hint && <div className="stat-hint">{hint}</div>}
    </div>
  );
}

/* ---------- Segmented control ---------- */

export function Segmented<T extends string>({
  value,
  onChange,
  options,
}: {
  value: T;
  onChange: (v: T) => void;
  options: { value: T; label: React.ReactNode; count?: number; icon?: React.ReactNode }[];
}) {
  return (
    <div className="seg" role="tablist">
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          role="tab"
          aria-selected={value === o.value}
          className={value === o.value ? 'on' : ''}
          onClick={() => onChange(o.value)}
        >
          {o.icon}
          {o.label}
          {o.count !== undefined && <span className="seg-count">{o.count}</span>}
        </button>
      ))}
    </div>
  );
}

/* ---------- Switch ---------- */

export function Switch({
  checked,
  onChange,
  label,
  disabled = false,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label?: string;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      className={`switch ${checked ? 'on' : ''}`}
      onClick={(e) => {
        e.stopPropagation();
        onChange(!checked);
      }}
    />
  );
}

/* ---------- Copy button ---------- */

export function CopyButton({ text, className = 'btn ghost xs', label }: { text: string; className?: string; label?: string }) {
  const [done, setDone] = useState(false);
  const [failed, setFailed] = useState(false);
  return (
    <button
      type="button"
      className={className}
      onClick={(e) => {
        e.stopPropagation();
        copyText(text).then(() => {
          setFailed(false);
          setDone(true);
          window.setTimeout(() => setDone(false), 1400);
        }).catch(() => setFailed(true));
      }}
      title={failed ? 'Copy failed. Select and copy the text manually.' : 'Copy'}
      aria-label={failed ? 'Copy failed' : done ? 'Copied' : label || 'Copy'}
    >
      {done ? <Check size={13} /> : <Copy size={13} />}
      {label && <span>{done ? 'Copied' : label}</span>}
    </button>
  );
}

/* ---------- Code ---------- */

function highlightJson(src: string): React.ReactNode[] {
  const out: React.ReactNode[] = [];
  const re = /("(?:\\.|[^"\\])*")(\s*:)?|\b(-?\d+(?:\.\d+)?)\b|\b(true|false|null)\b/g;
  let last = 0;
  let m: RegExpExecArray | null;
  let i = 0;
  while ((m = re.exec(src))) {
    if (m.index > last) out.push(src.slice(last, m.index));
    if (m[1]) {
      out.push(
        <span key={i++} className={m[2] ? 'k' : 's'}>
          {m[1]}
        </span>
      );
      if (m[2]) out.push(m[2]);
    } else {
      out.push(
        <span key={i++} className="n">
          {m[0]}
        </span>
      );
    }
    last = m.index + m[0].length;
  }
  if (last < src.length) out.push(src.slice(last));
  return out;
}

export function Code({ children, json = false, copy = true }: { children: string; json?: boolean; copy?: boolean }) {
  return (
    <pre className="code">
      {copy && (
        <span className="copy">
          <CopyButton text={children} />
        </span>
      )}
      {json ? highlightJson(children) : children}
    </pre>
  );
}

/* ---------- Lineage chain ---------- */

export function Chain({ nodes, blockedLast = false, heldLast = false }: { nodes: string[]; blockedLast?: boolean; heldLast?: boolean }) {
  return (
    <div className="chain">
      {nodes.map((n, i) => {
        const last = i === nodes.length - 1;
        const cls = last && blockedLast ? 'red' : last && heldLast ? 'amber' : '';
        const label = n === 'context_core' ? 'agent context' : n === 'user_prompt' ? 'user prompt' : toolLabel(n);
        return (
          <React.Fragment key={`${n}-${i}`}>
            <span className={`chain-node ${cls}`}>{label}</span>
            {!last && <span className="chain-sep">→</span>}
          </React.Fragment>
        );
      })}
    </div>
  );
}

/* ---------- Empty ---------- */

export function Empty({ icon, title, children }: { icon?: React.ReactNode; title: string; children?: React.ReactNode }) {
  return (
    <div className="empty">
      {icon && <div className="empty-icon">{icon}</div>}
      <div className="empty-title">{title}</div>
      {children && <div style={{ maxWidth: 360 }}>{children}</div>}
    </div>
  );
}

/* ---------- Sheet ---------- */

export function Sheet({
  open,
  onClose,
  title,
  subtitle,
  children,
  footer,
}: {
  open: boolean;
  onClose: () => void;
  title: React.ReactNode;
  subtitle?: React.ReactNode;
  children: React.ReactNode;
  footer?: React.ReactNode;
}) {
  const ref = useRef<HTMLElement>(null);
  const titleId = useId();
  useDialogFocus(open, ref, onClose);

  if (!open) return null;
  return (
    <>
      <div className="overlay" onClick={onClose} />
      <aside ref={ref} className="sheet" role="dialog" aria-modal="true" aria-labelledby={titleId} tabIndex={-1}>
        <header className="sheet-header">
          <div style={{ minWidth: 0 }}>
            <h2 id={titleId} className="sheet-title">{title}</h2>
            {subtitle && <div className="sheet-sub">{subtitle}</div>}
          </div>
          <button type="button" className="btn ghost icon sm" onClick={onClose} aria-label="Close">
            <X size={15} />
          </button>
        </header>
        <div className="sheet-body">{children}</div>
        {footer && <footer className="sheet-footer">{footer}</footer>}
      </aside>
    </>
  );
}

/* ---------- Meter ---------- */

export function Meter({ value, tone = 'neutral' }: { value: number; tone?: Tone }) {
  const color = tone === 'neutral' ? 'var(--text-3)' : `var(--${tone})`;
  return (
    <div className="meter">
      <span style={{ width: `${Math.max(0, Math.min(100, value))}%`, background: color }} />
    </div>
  );
}

/* ---------- Skeleton rows ---------- */

export function SkeletonRows({ rows = 5 }: { rows?: number }) {
  return (
    <div style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="skeleton" style={{ height: 14, width: `${88 - ((i * 13) % 40)}%` }} />
      ))}
    </div>
  );
}
