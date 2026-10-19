/**
 * Hosted public site only. The local console and source builds compile this to nothing.
 * Page views use Vercel Web Analytics (cookieless). Conversion events are first-party
 * counts that store only the event name and the day.
 */
const ENABLED = import.meta.env.VITE_DEPLOY_TARGET === 'cloud' && import.meta.env.PROD;

export type SiteEvent = 'install_copied' | 'github_clicked' | 'signin_started_github' | 'signin_started_google' | 'signin_completed';

export function countEvent(event: SiteEvent) {
  if (!ENABLED) return;
  void fetch('/api/cloud/v1/events', {
    method: 'POST', keepalive: true,
    headers: { 'Content-Type': 'application/json', 'X-Elytra-Request': '1' },
    body: JSON.stringify({ event }),
  }).catch(() => {});
}

let started = false;
export function startPageAnalytics() {
  if (!ENABLED || started) return;
  started = true;
  void import('@vercel/analytics').then(({ inject }) => inject({
    // Report the path only: never query strings or fragments.
    beforeSend: (event) => { const url = new URL(event.url); return { ...event, url: url.origin + url.pathname }; },
  })).catch(() => {});
}

const INSTALL = /\bpipx? install\b/;
let lastInstall = 0;
function installCopied() {
  // A copy button may fall back to a copy event; count one copy, not two.
  if (Date.now() - lastInstall < 1000) return;
  lastInstall = Date.now();
  countEvent('install_copied');
}

/** Counts install commands copied (button or keyboard) and repository links clicked. */
export function trackSiteClicks(root: Document) {
  if (!ENABLED) return () => {};
  // Capture phase: copy buttons stop propagation.
  const onClick = (event: MouseEvent) => {
    const target = event.target as Element | null;
    const copy = target?.closest('pre.code .copy');
    if (copy && INSTALL.test(copy.closest('pre')?.textContent || '')) return installCopied();
    const link = target?.closest('a');
    if (link && /^https:\/\/github\.com\/elytra-labs\//.test(link.href)) countEvent('github_clicked');
  };
  const onCopy = () => { if (INSTALL.test(root.getSelection()?.toString() || '')) installCopied(); };
  root.addEventListener('click', onClick, true);
  root.addEventListener('copy', onCopy);
  return () => { root.removeEventListener('click', onClick, true); root.removeEventListener('copy', onCopy); };
}
