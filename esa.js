/**
 * 阿里云 ESA 边缘函数入口：通过 HTTP Webhook 更新 ESA 加速域名的回源地址与回源端口
 *
 * 路由（与 edgeone 版本保持一致）：
 *   GET  /update-origin?domain=www.example.com&ip=1.2.3.4   更新（需 ESA_ALLOW_GET_UPDATE=true）
 *   GET  /update-origin?domain=www.example.com              查询（需 ESA_ALLOW_DESCRIBE=true）
 *   POST /update-origin  { "secret": "...", "domain": "...", "ip": "..." }
 *
 * 说明：
 *   - ESA 用「站点 SiteId + 记录（加速域名）」定位，回源地址可能落在两个位置：
 *       1) 记录引用的源地址池（RecordSourceType=OP，池内 Origins[].Address 为回源地址）
 *       2) 记录值本身（普通域名源站的 CNAME，或代理加速的 A/AAAA 记录）
 *     脚本会自动判断，也可用 originPoolId 显式指定源地址池。
 *   - 回源协议（http/https/follow）与回源端口是站点级「回源规则」，
 *     仅在请求显式传入 httpPort / httpsPort / originProtocol 时才修改；
 *     优先匹配该域名的规则，其次匹配全局配置，都没有则新建一条按域名匹配的规则。
 */

import { EsaClient, EsaApiError, mapEsaCodeToStatus } from './lib/esa-client.js';

const ROUTE_PATH = '/update-origin';

/** ESA 边缘函数（Pages）入口：export default { fetch(request, env, ctx) } */
export default {
  async fetch(request, env, ctx) {
    return handleRequest(request, env);
  },
};

export async function handleRequest(request, env = {}) {
  const corsOrigin = getEnv(env, 'ESA_CORS_ORIGIN') || '*';

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders(corsOrigin) });
  }

  let pathname = '/';
  try {
    pathname = new URL(request.url).pathname.replace(/\/+$/, '') || '/';
    if (pathname !== ROUTE_PATH) {
      return json({ error: 'Not Found', message: `仅支持 ${ROUTE_PATH} 路由` }, 404, corsOrigin);
    }
  } catch {
    return json({ error: 'Bad Request', message: '非法请求 URL' }, 400, corsOrigin);
  }

  const requestId = request.headers.get('x-request-id') || `req-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`;
  const isGet = request.method === 'GET' || request.method === 'HEAD';
  const source = isGet ? new URL(request.url).searchParams : await readJsonBody(request);
  if (source instanceof Response) return source;

  try {
    if (isGet) {
      const hasDomain = Boolean(source.get('domain'));
      const hasOrigin = Boolean(source.get('ip') || source.get('origin'));
      if (hasDomain && hasOrigin) {
        if (getEnv(env, 'ESA_ALLOW_GET_UPDATE') !== 'true') {
          return json(
            {
              error: 'Method Not Allowed',
              message: 'GET 更新已关闭；如需启用请设置环境变量 ESA_ALLOW_GET_UPDATE=true，或改用 POST 请求',
            },
            405,
            corsOrigin,
          );
        }
        return await updateOrigin(env, source, { corsOrigin, requestId });
      }
      if (hasDomain) {
        if (getEnv(env, 'ESA_ALLOW_DESCRIBE') !== 'true') {
          return json(
            { error: 'Method Not Allowed', message: 'GET 查询已关闭；如需启用请设置环境变量 ESA_ALLOW_DESCRIBE=true' },
            405,
            corsOrigin,
          );
        }
        return await describeOrigin(env, source, { corsOrigin, requestId });
      }
      return json({ error: 'Bad Request', message: '缺少参数 domain' }, 400, corsOrigin);
    }

    if (request.method === 'POST') return await updateOrigin(env, source, { corsOrigin, requestId });

    return json({ error: 'Method Not Allowed', message: `不支持的请求方法 ${request.method}` }, 405, corsOrigin);
  } catch (err) {
    return handleError(err, corsOrigin);
  }
}

/* ---------------------------------------------------------------------------------- */
/*                                        查询                                         */
/* ---------------------------------------------------------------------------------- */

async function describeOrigin(env, source, { corsOrigin, requestId }) {
  const client = buildClient(env);
  const siteId = resolveSiteId(env, source);
  if (!siteId) return json({ error: 'Bad Request', message: '缺少 siteId，请传参或在环境变量 ESA_SITE_ID 中配置' }, 400, corsOrigin);
  if (!/^\d{5,20}$/.test(siteId)) return json({ error: 'Bad Request', message: 'siteId 非法，ESA 站点 ID 为纯数字' }, 400, corsOrigin);

  const domain = normalizeDomain(source.get('domain'));
  if (!domain) return json({ error: 'Bad Request', message: 'domain 非法' }, 400, corsOrigin);
  checkDomainWhitelist(env, domain);

  const record = await client.findRecord(siteId, domain);
  if (!record) {
    return json({ error: 'Not Found', message: `站点 ${siteId} 下未找到记录（加速域名）${domain}` }, 404, corsOrigin);
  }

  const detail = await client.getRecord(record.RecordId);
  const pool = await client.findOriginPoolByRecord(siteId, { recordId: record.RecordId, recordName: record.RecordName });
  const rule = await findOriginRule(client, siteId, domain);

  return json(
    {
      ok: true,
      requestId,
      domain: record.RecordName || domain,
      ...describeState(detail || record, pool, rule),
    },
    200,
    corsOrigin,
  );
}

/* ---------------------------------------------------------------------------------- */
/*                                        更新                                         */
/* ---------------------------------------------------------------------------------- */

async function updateOrigin(env, source, { corsOrigin, requestId }) {
  const client = buildClient(env);

  /* 鉴权 */
  const secret = pick(source, 'secret', 'token');
  if (!checkSecret(env, secret)) {
    return json({ error: 'Unauthorized', message: 'invalid secret' }, 401, corsOrigin);
  }

  /* 站点与域名 */
  const siteId = resolveSiteId(env, source);
  if (!siteId) return json({ error: 'Bad Request', message: '缺少 siteId' }, 400, corsOrigin);
  if (!/^\d{5,20}$/.test(siteId)) return json({ error: 'Bad Request', message: 'siteId 非法，ESA 站点 ID 为纯数字' }, 400, corsOrigin);

  const domain = normalizeDomain(pick(source, 'domain'));
  if (!domain) return json({ error: 'Bad Request', message: 'domain 非法' }, 400, corsOrigin);
  checkDomainWhitelist(env, domain);

  /* 新源站地址 */
  const separator = getEnv(env, 'ESA_ORIGIN_SEPARATOR') || ',';
  const addresses = normalizeOrigins(pick(source, 'ip', 'origin', 'origins', 'value'), separator);
  if (!addresses.length) return json({ error: 'Bad Request', message: '缺少 ip' }, 400, corsOrigin);
  for (const address of addresses) {
    if (!isValidOrigin(address)) return json({ error: 'Bad Request', message: `ip 非法：${address}` }, 400, corsOrigin);
  }

  /* 回源端口与协议 */
  const httpPort = normalizePort(pick(source, 'httpPort', 'http_port', 'originHttpPort'));
  if (httpPort === false) return json({ error: 'Bad Request', message: 'httpPort 非法，应为 1-65535' }, 400, corsOrigin);
  const httpsPort = normalizePort(pick(source, 'httpsPort', 'https_port', 'originHttpsPort'));
  if (httpsPort === false) return json({ error: 'Bad Request', message: 'httpsPort 非法，应为 1-65535' }, 400, corsOrigin);
  const originProtocol = normalizeOriginScheme(pick(source, 'originProtocol', 'origin_protocol', 'originScheme', 'scheme'));
  if (originProtocol === false) return json({ error: 'Bad Request', message: 'originProtocol 非法，应为 http / https / follow' }, 400, corsOrigin);

  const dryRun = pick(source, 'dryRun', 'dry_run', 'dryrun') === 'true' || getEnv(env, 'ESA_DRY_RUN') === 'true';

  /* 定位记录 */
  const record = await client.findRecord(siteId, domain);
  if (!record) {
    return json({ error: 'Not Found', message: `站点 ${siteId} 下未找到记录（加速域名）${domain}` }, 404, corsOrigin);
  }
  const detail = await client.getRecord(record.RecordId);
  const recordInfo = detail && detail.RecordId ? detail : record;

  /* 定位源站写入位置 */
  const poolIdFromRequest = String(pick(source, 'originPoolId', 'poolId', 'pool') || '').trim();
  const poolIdFromEnv = (getEnv(env, 'ESA_ORIGIN_POOL_ID') || '').trim();
  const explicitPoolId = poolIdFromRequest || poolIdFromEnv;

  let pool = null;
  let target = 'record'; // 默认写「记录值」

  if (explicitPoolId) {
    const { pools } = await client.listOriginPools(siteId, { pageSize: 200 });
    pool = pools.find((item) => String(item.Id) === String(explicitPoolId)) || null;
    if (!pool) return json({ error: 'Not Found', message: `站点 ${siteId} 下未找到源地址池 ${explicitPoolId}` }, 404, corsOrigin);
    target = 'pool';
  } else if (String(recordInfo.RecordSourceType || '').toUpperCase() === 'OP') {
    pool = await client.findOriginPoolByRecord(siteId, { recordId: recordInfo.RecordId, recordName: recordInfo.RecordName });
    if (!pool) {
      return json(
        {
          error: 'Not Found',
          message: `记录 ${domain} 的源站类型为源地址池（OP），但未找到其引用的源地址池；请在请求中传入 originPoolId`,
        },
        404,
        corsOrigin,
      );
    }
    target = 'pool';
  } else {
    /* 记录值即源站地址：CNAME（普通域名源站）或代理的 A/AAAA 记录 */
    const recordType = String(recordInfo.RecordType || '').toUpperCase();
    const allIp = addresses.every((address) => isIpLike(address));
    if (recordType === 'CNAME' && allIp) {
      return json(
        {
          error: 'Bad Request',
          message: '该记录是 CNAME（普通域名源站），记录值必须是域名；若要回源到 IP，请改用源地址池，或在请求中传入 originPoolId',
        },
        400,
        corsOrigin,
      );
    }
    if ((recordType === 'A' || recordType === 'AAAA') && addresses.some((address) => !isIpLike(address))) {
      return json({ error: 'Bad Request', message: `该记录类型为 ${recordType}，回源地址必须是 IP` }, 400, corsOrigin);
    }
  }

  /* 回源规则（协议与端口） */
  const needRuleUpdate = httpPort !== null || httpsPort !== null || originProtocol !== null;
  let rule = null;
  if (needRuleUpdate) rule = await findOriginRule(client, siteId, domain);

  const before = describeState(recordInfo, pool, rule);
  const afterState = {
    ...before,
    originPool: target === 'pool' && pool
      ? {
          ...before.originPool,
          origins: buildOrigins((pool.Origins || []), addresses, defaultWeight(env)).map((item) => ({
            address: item.Address,
            enabled: item.Enabled,
            weight: item.Weight,
          })),
        }
      : before.originPool,
    origin: target === 'record' ? addresses.join(separator) : before.origin,
    originScheme: originProtocol ?? before.originScheme,
    httpOriginPort: httpPort ?? before.httpOriginPort,
    httpsOriginPort: httpsPort ?? before.httpsOriginPort,
  };

  const notes = [];
  if (target === 'pool') notes.push(`回源地址写入源地址池「${pool.Name}」（Id: ${pool.Id}）`);
  else notes.push(`回源地址写入记录值（${recordInfo.RecordType} 记录）`);
  if (originProtocol === 'follow') notes.push('回源协议为 follow（跟随协议）时，实际端口由 OriginHttpPort / OriginHttpsPort 决定');
  if (rule) notes.push(`回源端口/协议写入已有回源规则 ConfigId=${rule.ConfigId}（${rule.ConfigType}）`);
  else if (needRuleUpdate) notes.push('站点下暂无可用回源规则，将按该域名新建一条回源规则');

  if (dryRun) {
    return json(
      {
        ok: true,
        dryRun: true,
        message: dryRunMessage(httpPort, httpsPort, originProtocol),
        requestId,
        domain: recordInfo.RecordName || domain,
        siteId,
        writeTo: target === 'pool' ? 'originPool' : 'record',
        before,
        after: afterState,
        notes,
      },
      200,
      corsOrigin,
    );
  }

  /* 写入源站地址 */
  let requestIdFromApi = '';
  let readableBefore = null;

  if (target === 'pool') {
    const origins = buildOrigins(pool.Origins || [], addresses, defaultWeight(env));
    readableBefore = await client.updateOriginPool({ siteId, id: pool.Id, origins });
    requestIdFromApi = readableBefore.requestId || '';
  } else {
    const params = { RecordId: recordInfo.RecordId };
    params.Data = { Value: addresses.join(separator) };
    readableBefore = await client.updateRecord(params);
    requestIdFromApi = readableBefore.requestId || '';
  }

  /* 写入回源协议与端口 */
  let ruleResult = null;
  if (needRuleUpdate) {
    if (rule) {
      const payload = { SiteId: siteId, ConfigId: rule.ConfigId };
      if (rule.ConfigType !== 'global') {
        /* 非全局配置回传原规则内容，避免被空值覆盖 */
        if (rule.RuleName) payload.RuleName = rule.RuleName;
        if (rule.Rule) payload.Rule = rule.Rule;
        if (rule.RuleEnable) payload.RuleEnable = rule.RuleEnable;
      }
      if (originProtocol !== null) payload.OriginScheme = originProtocol;
      if (httpPort !== null) payload.OriginHttpPort = String(httpPort);
      if (httpsPort !== null) payload.OriginHttpsPort = String(httpsPort);
      ruleResult = await client.updateOriginRule(payload);
    } else {
      if (getEnv(env, 'ESA_ALLOW_CREATE_ORIGIN_RULE') === 'false') {
        return json(
          {
            error: 'Not Found',
            message: '站点下未找到回源规则，且已通过 ESA_ALLOW_CREATE_ORIGIN_RULE=false 禁止自动创建；请先在 ESA 控制台创建回源规则',
            requestId: requestIdFromApi,
          },
          404,
          corsOrigin,
        );
      }
      const payload = {
        SiteId: siteId,
        RuleName: `webhook-${domain}`.slice(0, 100),
        Rule: `(http.host eq "${domain}")`,
        RuleEnable: 'on',
      };
      if (originProtocol !== null) payload.OriginScheme = originProtocol;
      if (httpPort !== null) payload.OriginHttpPort = String(httpPort);
      if (httpsPort !== null) payload.OriginHttpsPort = String(httpsPort);
      ruleResult = await client.createOriginRule(payload);
    }
  }

  /* 回读确认 */
  const recordAfter = await client.getRecord(recordInfo.RecordId);
  const poolAfter = target === 'pool'
    ? await client.findOriginPoolByRecord(siteId, { recordId: recordInfo.RecordId, recordName: recordInfo.RecordName })
    : null;
  const ruleAfter = needRuleUpdate ? await findOriginRule(client, siteId, domain) : rule;

  return json(
    {
      ok: true,
      dryRun: false,
      message: dryRunMessage(httpPort, httpsPort, originProtocol),
      requestId: requestIdFromApi || requestId,
      domain: recordInfo.RecordName || domain,
      siteId,
      writeTo: target === 'pool' ? 'originPool' : 'record',
      before,
      after: describeState(recordAfter || recordInfo, poolAfter || (target === 'pool' ? pool : null), ruleAfter),
      notes,
      ruleRequestId: ruleResult?.requestId || '',
    },
    200,
    corsOrigin,
  );
}

/* ---------------------------------------------------------------------------------- */
/*                                       辅助函数                                       */
/* ---------------------------------------------------------------------------------- */

function buildClient(env) {
  return new EsaClient({
    accessKeyId: getEnv(env, 'ESA_ACCESS_KEY_ID') || getEnv(env, 'ALIBABA_CLOUD_ACCESS_KEY_ID'),
    accessKeySecret: getEnv(env, 'ESA_ACCESS_KEY_SECRET') || getEnv(env, 'ALIBABA_CLOUD_ACCESS_KEY_SECRET'),
    securityToken: getEnv(env, 'ESA_SECURITY_TOKEN') || getEnv(env, 'ALIBABA_CLOUD_SECURITY_TOKEN'),
    endpoint: getEnv(env, 'ESA_API_ENDPOINT') || undefined,
    timeoutMs: getEnv(env, 'ESA_API_TIMEOUT_MS') || undefined,
  });
}

/** 环境变量：优先取边缘函数传入的 env，其次 globalThis.env，最后 process.env（本地调试） */
function getEnv(env, key) {
  const fromArg = env && typeof env === 'object' ? env[key] : undefined;
  if (fromArg !== undefined && fromArg !== null && fromArg !== '') return String(fromArg);
  const fromGlobal = typeof globalThis !== 'undefined' && globalThis.env && typeof globalThis.env === 'object'
    ? globalThis.env[key]
    : undefined;
  if (fromGlobal !== undefined && fromGlobal !== null && fromGlobal !== '') return String(fromGlobal);
  const fromProcess = typeof process !== 'undefined' && process.env ? process.env[key] : undefined;
  return fromProcess === undefined || fromProcess === null ? '' : String(fromProcess);
}

function pick(source, ...keys) {
  for (const key of keys) {
    const value = source instanceof URLSearchParams ? source.get(key) : source?.[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return '';
}

function resolveSiteId(env, source) {
  return String(pick(source, 'siteId', 'site_id', 'site') || getEnv(env, 'ESA_SITE_ID') || '').trim();
}

function checkSecret(env, secret) {
  const expected = getEnv(env, 'WEBHOOK_TOKEN') || getEnv(env, 'WEBHOOK_SECRET');
  if (!expected) return true;
  if (!secret) return false;
  const provided = new TextEncoder().encode(String(secret));
  const wanted = new TextEncoder().encode(String(expected));
  return provided.length === wanted.length && timingSafeEqualCompat(provided, wanted);
}

function timingSafeEqualCompat(a, b) {
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}

function checkDomainWhitelist(env, domain) {
  const list = getEnv(env, 'ESA_ALLOWED_DOMAINS');
  if (!list) return;
  const allowed = list
    .split(',')
    .map((item) => normalizeDomain(item.trim()))
    .filter(Boolean);
  if (!allowed.includes(domain)) {
    const err = new Error(`domain 不在白名单内：${domain}`);
    err.status = 403;
    err.payload = { error: 'Forbidden', message: `domain 不在白名单内：${domain}` };
    throw err;
  }
}

function normalizeDomain(value) {
  const domain = String(value || '').trim().toLowerCase().replace(/\.$/, '');
  if (!domain || !/^[a-z0-9-_*.]{1,253}$/.test(domain)) return '';
  if (!domain.includes('.')) return '';
  return domain;
}

function normalizeOrigins(value, separator) {
  const raw = String(value || '').trim();
  if (!raw) return [];
  return raw
    .split(separator)
    .map((item) => item.trim())
    .filter(Boolean);
}

function isValidOrigin(value) {
  if (!value || value.length > 253) return false;
  /* 纯数字点分 / 含冒号的形式必须是一个合法 IP，避免把 999.999.999.999 当成域名放行 */
  if (/^[\d.]+$/.test(value) || value.includes(':')) return isIPv4(value) || isIPv6(value);
  if (isIPv4(value) || isIPv6(value)) return true;
  const domainPattern = /^(?=.{1,253}$)([a-z0-9](-*[a-z0-9])*)(\.[a-z0-9](-*[a-z0-9])*)*$/i;
  if (domainPattern.test(value) && value.includes('.')) return true;
  return /^https?:\/\/[^\s/$.?#].[^\s]*$/i.test(value);
}

function isIpLike(value) {
  return isIPv4(value) || isIPv6(value);
}

function isIPv4(value) {
  if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(value)) return false;
  return value.split('.').every((part) => {
    const num = Number(part);
    return num >= 0 && num <= 255 && String(num) === String(Number(part));
  });
}

function isIPv6(value) {
  if (!value.includes(':')) return false;
  return /^[0-9a-f:]{2,45}$/i.test(value);
}

function normalizePort(value) {
  const raw = String(value ?? '').trim();
  if (!raw) return null;
  if (!/^\d{1,5}$/.test(raw)) return false;
  const port = Number(raw);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return false;
  return port;
}

function normalizeOriginScheme(value) {
  const raw = String(value ?? '').trim().toLowerCase();
  if (!raw) return null;
  if (raw === 'follow' || raw === 'http' || raw === 'https') return raw;
  return false;
}

function defaultWeight(env) {
  const raw = Number(getEnv(env, 'ESA_ORIGIN_WEIGHT'));
  if (!Number.isInteger(raw) || raw < 0 || raw > 100) return 100;
  return raw;
}

/**
 * 构造写入源地址池的 Origins（全量覆盖）
 * 尽量复用原有条目的 Name / Type / Enabled / Weight / Header，只替换地址，避免误改配置
 */
function buildOrigins(previous, addresses, weight) {
  const prev = Array.isArray(previous) ? previous : [];
  return addresses.map((address, index) => {
    const base = prev[index] || {};
    const item = {
      Address: address,
      Name: base.Name || `origin${index + 1}`,
      Enabled: base.Enabled === undefined ? true : Boolean(base.Enabled),
      Type: base.Type || 'ip_domain',
      Weight: Number.isInteger(Number(base.Weight)) ? Number(base.Weight) : weight,
    };
    if (base.Header && typeof base.Header === 'object') item.Header = base.Header;
    if (base.AuthConf && typeof base.AuthConf === 'object') item.AuthConf = base.AuthConf;
    if (base.IpVersionPolicy) item.IpVersionPolicy = base.IpVersionPolicy;
    return item;
  });
}

/** 找到该域名对应的回源规则：优先按 http.host 匹配，其次取全局配置 */
async function findOriginRule(client, siteId, domain) {
  const { configs } = await client.listOriginRules(siteId, { pageSize: 200 });
  if (!configs.length) return null;
  const quoted = [`"${domain}"`, `'${domain}'`, `\u0022${domain}\u0022`];
  const matched = configs.filter((item) => {
    if (String(item.ConfigType || '').toLowerCase() === 'global') return false;
    const rule = String(item.Rule || '');
    return quoted.some((token) => rule.includes(token));
  });
  if (matched.length) return matched[0];
  return configs.find((item) => String(item.ConfigType || '').toLowerCase() === 'global') || null;
}

function describeState(record, pool, rule) {
  return {
    recordId: record?.RecordId ?? null,
    recordType: record?.RecordType ?? null,
    proxied: record?.Proxied ?? null,
    sourceType: record?.RecordSourceType ?? null,
    origin: record?.Data?.Value ?? null,
    originPool: pool
      ? {
          id: pool.Id ?? null,
          name: pool.Name ?? null,
          origins: (pool.Origins || []).map((item) => ({
            address: item.Address ?? null,
            enabled: item.Enabled ?? null,
            weight: item.Weight ?? null,
          })),
        }
      : null,
    originScheme: rule?.OriginScheme ?? null,
    httpOriginPort: rule?.OriginHttpPort ?? null,
    httpsOriginPort: rule?.OriginHttpsPort ?? null,
  };
}

function dryRunMessage(httpPort, httpsPort, originProtocol) {
  const parts = ['origin updated'];
  if (httpPort !== null) parts.push(`http port=${httpPort}`);
  if (httpsPort !== null) parts.push(`https port=${httpsPort}`);
  if (originProtocol !== null) parts.push(`scheme=${originProtocol}`);
  return parts.join(', ');
}

async function readJsonBody(request) {
  const raw = await request.text();
  if (!raw) return {};
  try {
    return JSON.parse(raw);
  } catch {
    return json({ error: 'Bad Request', message: '请求体不是合法 JSON' }, 400, '*');
  }
}

function corsHeaders(origin) {
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Request-Id',
    'Access-Control-Max-Age': '86400',
  };
}

function json(data, status = 200, corsOrigin = '*') {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...corsHeaders(corsOrigin) },
  });
}

function handleError(err, corsOrigin) {
  if (err instanceof EsaApiError) {
    return json(
      { error: err.code || 'EsaApiError', message: err.message, esaRequestId: err.requestId || '' },
      mapEsaCodeToStatus(err.code),
      corsOrigin,
    );
  }
  if (err && err.payload) return json(err.payload, err.status || 400, corsOrigin);
  if (err && /missing credentials|AccessKey/i.test(String(err.message))) {
    return json({ error: 'Server Misconfigured', message: '缺少 AccessKey 配置' }, 500, corsOrigin);
  }
  return json({ error: 'Internal Error', message: String(err?.message || err) }, 500, corsOrigin);
}
