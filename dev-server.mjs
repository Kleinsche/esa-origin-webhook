/**
 * 本地调试服务器（可选）：把 Node HTTP 请求转成 Web 标准 Request 交给 esa.js 处理
 *   cp .env.example .env  →  填写凭证  →  npm run dev  →  http://localhost:8787/update-origin
 */

import { createServer } from 'node:http';
import { readFileSync, existsSync } from 'node:fs';

if (existsSync(new URL('./.env', import.meta.url))) {
  const content = readFileSync(new URL('./.env', import.meta.url), 'utf8');
  for (const line of content.split(/\r?\n/)) {
    const match = /^\s*([\w.-]+)\s*=\s*(.*)\s*$/.exec(line);
    if (!match) continue;
    const [, key, rawValue] = match;
    if (key.startsWith('#') || process.env[key]) continue;
    process.env[key] = rawValue.replace(/^["']|["']$/g, '').trim();
  }
}

const { default: handler } = await import('./esa.js');

const port = Number(process.env.PORT) || 8787;

createServer(async (req, res) => {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const body = Buffer.concat(chunks);

  const url = new URL(req.url, `http://localhost:${port}`);
  const headers = new Headers();
  Object.entries(req.headers).forEach(([key, value]) => {
    if (value === undefined) return;
    headers.set(key, Array.isArray(value) ? value.join(', ') : value);
  });

  const request = new Request(url, {
    method: req.method,
    headers,
    body: req.method === 'GET' || req.method === 'HEAD' ? undefined : body,
  });

  const response = await handler.fetch(request, process.env);
  const buffer = Buffer.from(await response.arrayBuffer());

  res.writeHead(response.status, Object.fromEntries(response.headers));
  res.end(buffer);
}).listen(port, () => {
  // eslint-disable-next-line no-console
  console.log(`esa-origin-webhook dev server: http://localhost:${port}/update-origin`);
});
