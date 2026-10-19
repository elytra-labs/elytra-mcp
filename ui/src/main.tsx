import React from 'react';
import ReactDOM from 'react-dom/client';
import './styles/theme.css';

const App = React.lazy(() => import('./App').then(module => ({ default: module.App })));
const PublicSite = React.lazy(() => import('./site/PublicSite').then(module => ({ default: module.PublicSite })));
const CloudApp = React.lazy(() => import('./cloud/CloudApp').then(module => ({ default: module.CloudApp })));

const pathname = window.location.pathname;
const cloudRoute = import.meta.env.VITE_DEPLOY_TARGET === 'cloud' && /^\/(?:app(?:\/|$)|login(?:\/|$)|signup(?:\/|$)|auth\/callback(?:\/|$))/.test(pathname);
const localAppRoute = /^\/app(?:\/|$)/.test(pathname) && ['127.0.0.1', 'localhost', '[::1]'].includes(window.location.hostname);

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <React.Suspense fallback={<main style={{ padding: 40, color: 'var(--text-2)' }} role="status">Opening Elytra…</main>}>
      {cloudRoute ? <CloudApp /> : localAppRoute ? <App /> : <PublicSite />}
    </React.Suspense>
  </React.StrictMode>
);
