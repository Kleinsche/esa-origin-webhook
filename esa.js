/**
 * 闃块噷浜?ESA 杈圭紭鍑芥暟鍏ュ彛锛氶€氳繃 HTTP Webhook 鏇存柊 ESA 鍔犻€熷煙鍚嶇殑鍥炴簮鍦板潃涓庡洖婧愮鍙?
 *
 * 璺敱锛堜笌 edgeone 鐗堟湰淇濇寔涓€鑷达級锛?
 *   GET  /update-origin?domain=www.example.com&ip=1.2.3.4   鏇存柊锛堥渶 ESA_ALLOW_GET_UPDATE=true锛?
 *   GET  /update-origin?domain=www.example.com              鏌ヨ锛堥渶 ESA_ALLOW_DESCRIBE=true锛?
 *   POST /update-origin  { "secret": "...", "domain": "...", "ip": "..." }
 *
 * 璇存槑锛?
 *   - ESA 鐢ㄣ€岀珯鐐?SiteId + 璁板綍锛堝姞閫熷煙鍚嶏級銆嶅畾浣嶏紝鍥炴簮鍦板潃鍙兘钀藉湪涓や釜浣嶇疆锛?
 *       1) 璁板綍寮曠敤鐨勬簮鍦板潃姹狅紙RecordSourceType=OP锛屾睜鍐?Origins[].Address 涓哄洖婧愬湴鍧€锛?
 *       2) 璁板綍鍊兼湰韬紙鏅€氬煙鍚嶆簮绔欑殑 CNAME锛屾垨浠ｇ悊鍔犻€熺殑 A/AAAA 璁板綍锛?
 *     鑴氭湰浼氳嚜鍔ㄥ垽鏂紝涔熷彲鐢?originPoolId 鏄惧紡鎸囧畾婧愬湴鍧€姹犮€?
 *   - 鍥炴簮鍗忚锛坔ttp/https/follow锛変笌鍥炴簮绔彛鏄珯鐐圭骇銆屽洖婧愯鍒欍€嶏紝
 *     浠呭湪璇锋眰鏄惧紡浼犲叆 httpPort / httpsPort / originProtocol 鏃舵墠淇敼锛?
 *     浼樺厛鍖归厤璇ュ煙鍚嶇殑瑙勫垯锛屽叾娆″尮閰嶅叏灞€閰嶇疆锛岄兘娌℃湁鍒欐柊寤轰竴鏉℃寜鍩熷悕鍖归厤鐨勮鍒欍€?
 */

import { EsaClient, EsaApiError, mapEsaCodeToStatus } from './lib/esa-client.js';

const ROUTE_PATH = '/update-origin';

/** ESA 杈圭紭鍑芥暟锛圥ages锛夊叆鍙ｏ細export default { fetch(request, env, ctx) } */
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
      return json({ error: 'Not Found', message: `浠呮敮鎸?${ROUTE_PATH} 璺敱` }, 404, corsOrigin);
    }
  } catch {
    return json({ error: 'Bad Request', message: '闈炴硶璇锋眰 URL' }, 400, corsOrigin);
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
              message: 'GET 鏇存柊宸插叧闂紱濡傞渶鍚敤璇疯缃幆澧冨彉閲?ESA_ALLOW_GET_UPDATE=true锛屾垨鏀圭敤 POST 璇锋眰',
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
            { error: 'Method Not Allowed', message: 'GET 鏌ヨ宸插叧闂紱濡傞渶鍚敤璇疯缃幆澧冨彉閲?ESA_ALLOW_DESCRIBE=true' },
            405,
            corsOrigin,
          );
        }
        return await describeOrigin(env, source, { corsOrigin, requestId });
      }
      return json({ error: 'Bad Request', message: '缂哄皯鍙傛暟 domain' }, 400, corsOrigin);
    }

    if (request.method === 'POST') return await updateOrigin(env, source, { corsOrigin, requestId });

    return json({ error: 'Method Not Allowed', message: `涓嶆敮鎸佺殑璇锋眰鏂规硶 ${request.method}` }, 405, corsOrigin);
  } catch (err) {
    return handleError(err, corsOrigin);
  }
}

/* ---------------------------------------------------------------------------------- */
/*                                        鏌ヨ                                         */
/* ---------------------------------------------------------------------------------- */

async function describeOrigin(env, source, { corsOrigin, requestId }) {
  const client = buildClient(env);
  const siteId = resolveSiteId(env, source);
  if (!siteId) return json({ error: 'Bad Request', message: '缂哄皯 siteId锛岃浼犲弬鎴栧湪鐜鍙橀噺 ESA_SITE_ID 涓厤缃? }, 400, corsOrigin);
  if (!/^\d{5,20}$/.test(siteId)) return json({ error: 'Bad Request', message: 'siteId 闈炴硶锛孍SA 绔欑偣 ID 涓虹函鏁板瓧' }, 400, corsOrigin);

  const domain = normalizeDomain(source.get('domain'));
  if (!domain) return json({ error: 'Bad Request', message: 'domain 闈炴硶' }, 400, corsOrigin);
  checkDomainWhitelist(env, domain);

  const record = await client.findRecord(siteId, domain);
  if (!record) {
    return json({ error: 'Not Found', message: `绔欑偣 ${siteId} 涓嬫湭鎵惧埌璁板綍锛堝姞閫熷煙鍚嶏級${domain}` }, 404, corsOrigin);
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
/*                                        鏇存柊                                         */
/* ---------------------------------------------------------------------------------- */

async function updateOrigin(env, source, { corsOrigin, requestId }) {
  /* 閴存潈锛氬繀椤绘棭浜庢瀯寤哄鎴风锛屽惁鍒欏嚟璇佺己澶辨椂浼氬厛鎶?missing credentials锛屽鑷撮壌鏉冨け璐ヤ篃琚姤鎴?500 */
  const secret = pick(source, 'secret', 'token');
  if (!checkSecret(env, secret)) {
    return json({ error: 'Unauthorized', message: 'invalid secret' }, 401, corsOrigin);
  }

  const client = buildClient(env);

  /* 绔欑偣涓庡煙鍚?*/
  const siteId = resolveSiteId(env, source);
  if (!siteId) return json({ error: 'Bad Request', message: '缂哄皯 siteId' }, 400, corsOrigin);
  if (!/^\d{5,20}$/.test(siteId)) return json({ error: 'Bad Request', message: 'siteId 闈炴硶锛孍SA 绔欑偣 ID 涓虹函鏁板瓧' }, 400, corsOrigin);

  const domain = normalizeDomain(pick(source, 'domain'));
  if (!domain) return json({ error: 'Bad Request', message: 'domain 闈炴硶' }, 400, corsOrigin);
  checkDomainWhitelist(env, domain);

  /* 鏂版簮绔欏湴鍧€ */
  const separator = getEnv(env, 'ESA_ORIGIN_SEPARATOR') || ',';
  const addresses = normalizeOrigins(pick(source, 'ip', 'origin', 'origins', 'value'), separator);
  if (!addresses.length) return json({ error: 'Bad Request', message: '缂哄皯 ip' }, 400, corsOrigin);
  for (const address of addresses) {
    if (!isValidOrigin(address)) return json({ error: 'Bad Request', message: `ip 闈炴硶锛?{address}` }, 400, corsOrigin);
  }

  /* 鍥炴簮绔彛涓庡崗璁?*/
  const httpPort = normalizePort(pick(source, 'httpPort', 'http_port', 'originHttpPort'));
  if (httpPort === false) return json({ error: 'Bad Request', message: 'httpPort 闈炴硶锛屽簲涓?1-65535' }, 400, corsOrigin);
  const httpsPort = normalizePort(pick(source, 'httpsPort', 'https_port', 'originHttpsPort'));
  if (httpsPort === false) return json({ error: 'Bad Request', message: 'httpsPort 闈炴硶锛屽簲涓?1-65535' }, 400, corsOrigin);
  const originProtocol = normalizeOriginScheme(pick(source, 'originProtocol', 'origin_protocol', 'originScheme', 'scheme'));
  if (originProtocol === false) return json({ error: 'Bad Request', message: 'originProtocol 闈炴硶锛屽簲涓?http / https / follow' }, 400, corsOrigin);

  const dryRun = pick(source, 'dryRun', 'dry_run', 'dryrun') === 'true' || getEnv(env, 'ESA_DRY_RUN') === 'true';

  /* 瀹氫綅璁板綍 */
  const record = await client.findRecord(siteId, domain);
  if (!record) {
    return json({ error: 'Not Found', message: `绔欑偣 ${siteId} 涓嬫湭鎵惧埌璁板綍锛堝姞閫熷煙鍚嶏級${domain}` }, 404, corsOrigin);
  }
  const detail = await client.getRecord(record.RecordId);
  const recordInfo = detail && detail.RecordId ? detail : record;

  /* 瀹氫綅婧愮珯鍐欏叆浣嶇疆 */
  const poolIdFromRequest = String(pick(source, 'originPoolId', 'poolId', 'pool') || '').trim();
  const poolIdFromEnv = (getEnv(env, 'ESA_ORIGIN_POOL_ID') || '').trim();
  const explicitPoolId = poolIdFromRequest || poolIdFromEnv;

  let pool = null;
  let target = 'record'; // 榛樿鍐欍€岃褰曞€笺€?

  if (explicitPoolId) {
    const { pools } = await client.listOriginPools(siteId, { pageSize: 200 });
    pool = pools.find((item) => String(item.Id) === String(explicitPoolId)) || null;
    if (!pool) return json({ error: 'Not Found', message: `绔欑偣 ${siteId} 涓嬫湭鎵惧埌婧愬湴鍧€姹?${explicitPoolId}` }, 404, corsOrigin);
    target = 'pool';
  } else if (String(recordInfo.RecordSourceType || '').toUpperCase() === 'OP') {
    pool = await client.findOriginPoolByRecord(siteId, { recordId: recordInfo.RecordId, recordName: recordInfo.RecordName });
    if (!pool) {
      return json(
        {
          error: 'Not Found',
          message: `璁板綍 ${domain} 鐨勬簮绔欑被鍨嬩负婧愬湴鍧€姹狅紙OP锛夛紝浣嗘湭鎵惧埌鍏跺紩鐢ㄧ殑婧愬湴鍧€姹狅紱璇峰湪璇锋眰涓紶鍏?originPoolId`,
        },
        404,
        corsOrigin,
      );
    }
    target = 'pool';
  } else {
    /* 璁板綍鍊煎嵆婧愮珯鍦板潃锛欳NAME锛堟櫘閫氬煙鍚嶆簮绔欙級鎴栦唬鐞嗙殑 A/AAAA 璁板綍 */
    /* RecordType 鍙兘鏄?A/AAAA 杩欐牱鐨勭粍鍚堝€硷紝鎸?/ 鎷嗗垎鍚庡啀鍒ゅ畾 */
    const recordTypes = String(recordInfo.RecordType || '').toUpperCase().split('/');
    const allIp = addresses.every((address) => isIpLike(address));
    if (recordTypes.includes('CNAME') && allIp) {
      return json(
        {
          error: 'Bad Request',
          message: '璇ヨ褰曟槸 CNAME锛堟櫘閫氬煙鍚嶆簮绔欙級锛岃褰曞€煎繀椤绘槸鍩熷悕锛涜嫢瑕佸洖婧愬埌 IP锛岃鏀圭敤婧愬湴鍧€姹狅紝鎴栧湪璇锋眰涓紶鍏?originPoolId',
        },
        400,
        corsOrigin,
      );
    }
    if ((recordTypes.includes('A') || recordTypes.includes('AAAA')) && addresses.some((address) => !isIpLike(address))) {
      return json({ error: 'Bad Request', message: `璇ヨ褰曠被鍨嬩负 ${recordInfo.RecordType}锛屽洖婧愬湴鍧€蹇呴』鏄?IP` }, 400, corsOrigin);
    }
  }

  /* 鍥炴簮瑙勫垯锛堝崗璁笌绔彛锛?*/
  const needRuleUpdate = httpPort !== null || httpsPort !== null || originProtocol !== null;
  /* newRule=true锛氳烦杩囧凡鏈夎鍒欏尮閰嶏紝涓鸿鍩熷悕鏂板缓涓€鏉″洖婧愯鍒欙紙閬垮厤绔彛鍐欒繘鍏ㄥ眬閰嶇疆锛?*/
  const forceNewRule = pick(source, 'newRule', 'createRule', 'forceNewRule') === 'true';
  let rule = null;
  if (needRuleUpdate && !forceNewRule) rule = await findOriginRule(client, siteId, domain);

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
  if (target === 'pool') notes.push(`鍥炴簮鍦板潃鍐欏叆婧愬湴鍧€姹犮€?{pool.Name}銆嶏紙Id: ${pool.Id}锛塦);
  else notes.push(`鍥炴簮鍦板潃鍐欏叆璁板綍鍊硷紙${recordInfo.RecordType} 璁板綍锛塦);
  if (originProtocol === 'follow') notes.push('鍥炴簮鍗忚涓?follow锛堣窡闅忓崗璁級鏃讹紝瀹為檯绔彛鐢?OriginHttpPort / OriginHttpsPort 鍐冲畾');
  if (rule) notes.push(`鍥炴簮绔彛/鍗忚鍐欏叆宸叉湁鍥炴簮瑙勫垯 ConfigId=${rule.ConfigId}锛?{rule.ConfigType}锛塦);
  else if (needRuleUpdate) notes.push('绔欑偣涓嬫殏鏃犲彲鐢ㄥ洖婧愯鍒欙紝灏嗘寜璇ュ煙鍚嶆柊寤轰竴鏉″洖婧愯鍒?);

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

  /* 鍐欏叆婧愮珯鍦板潃 */
  let requestIdFromApi = '';
  let readableBefore = null;

  if (target === 'pool') {
    const origins = buildOrigins(pool.Origins || [], addresses, defaultWeight(env));
    readableBefore = await client.updateOriginPool({ siteId, id: pool.Id, origins });
    requestIdFromApi = readableBefore.requestId || '';
  } else {
    /* ESA 鐨?Data 蹇呴』鏄?JSON 瀛楃涓诧紝涓旈敭涓哄皬鍐?value锛堜紶瀵硅薄鎴?Data.Value 浼氭姤 MissingData锛?*/
    const params = { RecordId: recordInfo.RecordId };
    params.Data = JSON.stringify({ value: addresses.join(separator) });
    readableBefore = await client.updateRecord(params);
    requestIdFromApi = readableBefore.requestId || '';
  }

  /* 鍐欏叆鍥炴簮鍗忚涓庣鍙?*/
  let ruleResult = null;
  if (needRuleUpdate) {
    if (rule) {
      const payload = { SiteId: siteId, ConfigId: rule.ConfigId };
      if (rule.ConfigType !== 'global') {
        /* 闈炲叏灞€閰嶇疆鍥炰紶鍘熻鍒欏唴瀹癸紝閬垮厤琚┖鍊艰鐩?*/
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
            message: '绔欑偣涓嬫湭鎵惧埌鍥炴簮瑙勫垯锛屼笖宸查€氳繃 ESA_ALLOW_CREATE_ORIGIN_RULE=false 绂佹鑷姩鍒涘缓锛涜鍏堝湪 ESA 鎺у埗鍙板垱寤哄洖婧愯鍒?,
            requestId: requestIdFromApi,
          },
          404,
          corsOrigin,
        );
      }
      const payload = {
        SiteId: siteId,
        RuleName: `webhook-${domain}`.slice(0, 100),
        Rule: hostRuleExpression(domain),
        RuleEnable: 'on',
      };
      if (originProtocol !== null) payload.OriginScheme = originProtocol;
      if (httpPort !== null) payload.OriginHttpPort = String(httpPort);
      if (httpsPort !== null) payload.OriginHttpsPort = String(httpsPort);
      ruleResult = await client.createOriginRule(payload);
    }
  }

  /* 鍥炶纭 */
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
/*                                       杈呭姪鍑芥暟                                       */
/* ---------------------------------------------------------------------------------- */

function buildClient(env) {
  const accessKeyId = getEnv(env, 'ESA_ACCESS_KEY_ID') || getEnv(env, 'ALIBABA_CLOUD_ACCESS_KEY_ID');
  const accessKeySecret = getEnv(env, 'ESA_ACCESS_KEY_SECRET') || getEnv(env, 'ALIBABA_CLOUD_ACCESS_KEY_SECRET');

  /* 鍑瘉缂哄け鏃剁粰鍑烘槑纭彁绀猴細鍙洖鏄鹃敭鍚嶄笌缂哄け椤癸紝缁濅笉鍥炴樉鍊?*/
  const missing = [];
  if (!accessKeyId) missing.push('ESA_ACCESS_KEY_ID');
  if (!accessKeySecret) missing.push('ESA_ACCESS_KEY_SECRET');
  if (missing.length) {
    const err = new Error(`missing credentials: ${missing.join(', ')}`);
    err.status = 500;
    err.payload = {
      error: 'Server Misconfigured',
      message: `缂哄皯 AccessKey 閰嶇疆锛氳繍琛屾椂 env 涓湭璇诲彇鍒?${missing.join(' / ')}`,
      missingEnv: missing,
      /* envKeyCount=0 鍩烘湰鍙垽瀹氥€岃繍琛屾椂鐜鍙橀噺鏁翠綋娌℃敞鍏ャ€嶏細澶氬崐閰嶅湪浜嗐€屾瀯寤轰俊鎭?鈫?鐜鍙橀噺銆嶆垨閰嶅湪浜嗗埆鐨勭幆澧?*/
      envKeyCount: env && typeof env === 'object' ? Object.keys(env).length : 0,
      hint: '璇峰湪 ESA 鎺у埗鍙般€屽嚱鏁板拰Pages 鈫?椤圭洰 鈫?鐜鍙橀噺/瀵嗛挜銆嶉厤缃紙涓嶆槸銆屾瀯寤轰俊鎭?鈫?鐜鍙橀噺銆嶏級锛屼繚瀛樺悗閲嶆柊閮ㄧ讲涓€娆★紱鍙橀噺鍚嶅尯鍒嗗ぇ灏忓啓锛屽€奸灏句笉瑕佸甫绌烘牸鎴栨崲琛?,
    };
    throw err;
  }

  return new EsaClient({
    accessKeyId,
    accessKeySecret,
    securityToken: getEnv(env, 'ESA_SECURITY_TOKEN') || getEnv(env, 'ALIBABA_CLOUD_SECURITY_TOKEN'),
    endpoint: getEnv(env, 'ESA_API_ENDPOINT') || undefined,
    timeoutMs: getEnv(env, 'ESA_API_TIMEOUT_MS') || undefined,
  });
}

/** 鐜鍙橀噺锛氫紭鍏堝彇杈圭紭鍑芥暟浼犲叆鐨?env锛屽叾娆?globalThis.env锛屾渶鍚?process.env锛堟湰鍦拌皟璇曪級 */
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
    const err = new Error(`domain 涓嶅湪鐧藉悕鍗曞唴锛?{domain}`);
    err.status = 403;
    err.payload = { error: 'Forbidden', message: `domain 涓嶅湪鐧藉悕鍗曞唴锛?{domain}` };
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
  /* 绾暟瀛楃偣鍒?/ 鍚啋鍙风殑褰㈠紡蹇呴』鏄竴涓悎娉?IP锛岄伩鍏嶆妸 999.999.999.999 褰撴垚鍩熷悕鏀捐 */
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
 * 鏋勯€犲啓鍏ユ簮鍦板潃姹犵殑 Origins锛堝叏閲忚鐩栵級
 * 灏介噺澶嶇敤鍘熸湁鏉＄洰鐨?Name / Type / Enabled / Weight / Header锛屽彧鏇挎崲鍦板潃锛岄伩鍏嶈鏀归厤缃?
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

/**
 * 鐢熸垚鍥炴簮瑙勫垯鐨勫尮閰嶈〃杈惧紡
 * 鏅€氬煙鍚嶇敤 eq锛涙硾鍩熷悕锛?.example.com锛塭q 涓嶆敮鎸侀€氶厤锛屾鍒?matches 鍙堜粎楂樼骇鐗?浼佷笟鐗堝彲鐢紝
 * 鍥犳缁熶竴鐢?ends_with 鍖归厤鍩熷悕鍚庣紑锛屽 (ends_with(http.host, ".example.com"))
 */
function hostRuleExpression(domain) {
  if (!domain.startsWith('*.')) return `(http.host eq "${domain}")`;
  return `(ends_with(http.host, "${domain.slice(1)}"))`;
}

/** 鎵惧埌璇ュ煙鍚嶅搴旂殑鍥炴簮瑙勫垯锛氫紭鍏堟寜 http.host 鍖归厤锛屽叾娆″彇鍏ㄥ眬閰嶇疆 */
async function findOriginRule(client, siteId, domain) {
  const { configs } = await client.listOriginRules(siteId, { pageSize: 200 });
  if (!configs.length) return null;
  const quoted = [`"${domain}"`, `'${domain}'`, `\u0022${domain}\u0022`];
  /* ends_with 瑙勫垯閲屽啓鐨勬槸 ".example.com" 鍚庣紑锛屾硾鍩熷悕鏃朵竴骞跺尮閰?*/
  if (domain.startsWith('*.')) quoted.push(`"${domain.slice(1)}"`);
  const matched = configs.filter((item) => {
    if (String(item.ConfigType || '').toLowerCase() === 'global') return false;
    const rule = String(item.Rule || '');
    if (quoted.some((token) => rule.includes(token))) return true;
    /* 鍏滃簳锛欵SA 鎺у埗鍙板缓鐨勮鍒欏彲鑳芥妸鍩熷悕鏀惧湪 RuleName锛孯ule 鍐欐垚 true */
    return String(item.RuleName || '').toLowerCase() === String(domain).toLowerCase();
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
    return json({ error: 'Bad Request', message: '璇锋眰浣撲笉鏄悎娉?JSON' }, 400, '*');
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
    return json({ error: 'Server Misconfigured', message: '缂哄皯 AccessKey 閰嶇疆' }, 500, corsOrigin);
  }
  return json({ error: 'Internal Error', message: String(err?.message || err) }, 500, corsOrigin);
}
