import { Hono } from 'hono';
import { applySecurityHeaders } from './security-headers';

/**
 * Phase 2 placeholder. The OAuth authorization server, Google sign-in and account pages are
 * added in phase 4 (docs/DESIGN.md §12). Until then the Worker answers only a holding page and
 * a health check.
 */
const app = new Hono<{ Bindings: Env }>();

app.use('*', async (c, next) => {
  await next();
  applySecurityHeaders(c.res.headers);
});

app.get('/', (c) =>
  c.html(
    '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
      '<meta name="viewport" content="width=device-width, initial-scale=1">' +
      '<title>2earl login</title></head><body><h1>2earl login</h1>' +
      '<p>This service is not open yet.</p></body></html>',
  ),
);

app.get('/healthz', (c) => c.json({ status: 'ok' }));

app.notFound((c) => c.json({ error: 'not_found' }, 404));

app.onError((err, c) => {
  // Never echo error details to the client; they may contain request data.
  console.error('unhandled error', err instanceof Error ? err.name : 'unknown');
  return c.json({ error: 'server_error' }, 500);
});

export default app satisfies ExportedHandler<Env>;
