/**
 * The hosted workspace dashboard is a separate service and is not part of the
 * open-source build. The local console and website never route here: main.tsx
 * only loads this module when built with `--mode cloud`.
 */
export function CloudApp() {
  return (
    <main style={{ padding: 32, fontFamily: 'system-ui, sans-serif' }}>
      <p>The hosted workspace is not included in the open-source build.</p>
      <p><a href="/">Back to Elytra</a></p>
    </main>
  );
}
