/**
 * 阿里云 ESA（边缘安全加速）开放 API 客户端
 *
 * 接口风格：RPC（签名算法 ACS3-HMAC-SHA256）
 *   请求参数放在 QueryString，请求体为空（Hash = 空串的 SHA256）
 *   查询类接口（List/Get 开头）使用 GET，写入类接口使用 POST；
 *   ESA 网关会校验方法，不匹配会返回 UnsupportedHTTPMethod
 *   Authorization: ACS3-HMAC-SHA256 Credential=<AccessKeyId>,SignedHeaders=...,Signature=...
 *   签名密钥就是 AccessKeySecret 本身（不再拼接 "&"）
 *
 *   待签名字符串 = "ACS3-HMAC-SHA256\n" + hex(SHA256(CanonicalRequest))
 *   CanonicalRequest = METHOD\nCanonicalURI\nCanonicalQueryString\nCanonicalHeaders\nSignedHeaders\nHashedRequestPayload
 *
 * 本项目用到的 ESA OpenAPI（版本 2024-09-10）：
 *   记录（加速域名）：ListRecords / GetRecord / UpdateRecord
 *   源地址池：ListOriginPools / UpdateOriginPool
 *   回源规则（协议与端口）：ListOriginRules / CreateOriginRule / UpdateOriginRule
 *
 * 使用 Web Crypto（crypto.subtle / crypto.getRandomValues），可在边缘函数与 Node 18+ 中运行。
 */

const API_VERSION = '2024-09-10';
const SIGN_ALGORITHM = 'ACS3-HMAC-SHA256';
const DEFAULT_ENDPOINT = 'https://esa.cn-hangzhou.aliyuncs.com';
const DEFAULT_TIMEOUT_MS = 15000;

const encoder = new TextEncoder();

function toHex(buffer) {
  const bytes = new Uint8Array(buffer);
  let out = '';
  for (let i = 0; i < bytes.length; i += 1) {
    out += bytes[i].toString(16).padStart(2, '0');
  }
  return out;
}

async function sha256Hex(input) {
  const data = typeof input === 'string' ? encoder.encode(input) : input;
  return toHex(await crypto.subtle.digest('SHA-256', data));
}

async function hmacSha256Hex(secret, message) {
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  return toHex(await crypto.subtle.sign('HMAC', key, encoder.encode(message)));
}

/** RFC 3986 百分号编码：不编码 -_.~ 与字母数字，其余（含 !'()*）全部编码 */
export function percentEncode(value) {
  return encodeURIComponent(String(value))
    .replace(/[!'()*]/g, (ch) => `%${ch.charCodeAt(0).toString(16).toUpperCase()}`)
    .replace(/%7E/gi, '~');
}

function randomNonce() {
  if (typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID().replace(/-/g, '');
  }
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return toHex(bytes);
}

/**
 * 把嵌套的请求参数展开成 RPC 风格的扁平结构：
 *   { Origins: [{ Address: '1.2.3.4', Enabled: true }] } => { 'Origins.1.Address': '1.2.3.4', 'Origins.1.Enabled': 'true' }
 */
export function flattenParams(params) {
  const out = {};
  const walk = (key, value) => {
    if (value === undefined || value === null || value === '') return;
    if (Array.isArray(value)) {
      value.forEach((item, index) => walk(`${key}.${index + 1}`, item));
      return;
    }
    if (typeof value === 'object') {
      Object.entries(value).forEach(([subKey, subValue]) => walk(key ? `${key}.${subKey}` : subKey, subValue));
      return;
    }
    out[key] = typeof value === 'boolean' ? (value ? 'true' : 'false') : String(value);
  };
  Object.entries(params || {}).forEach(([key, value]) => walk(key, value));
  return out;
}

export function buildCanonicalQueryString(flatParams) {
  return Object.keys(flatParams)
    .sort()
    .map((key) => `${percentEncode(key)}=${percentEncode(flatParams[key])}`)
    .join('&');
}

/**
 * 计算 ACS3-HMAC-SHA256 签名
 * @returns {Promise<{authorization: string, headers: Record<string,string>, canonicalQueryString: string, canonicalRequest: string, stringToSign: string, debug: object}>}
 */
export async function buildSignature({
  accessKeyId,
  accessKeySecret,
  action,
  host,
  flatParams = {},
  date,
  nonce,
  payloadHash,
  securityToken = '',
  canonicalUri = '/',
  method = 'POST',
  contentType = '',
}) {
  const canonicalQueryString = buildCanonicalQueryString(flatParams);

  const headers = {
    host,
    'x-acs-action': action,
    'x-acs-version': API_VERSION,
    'x-acs-date': date,
    'x-acs-signature-nonce': nonce,
    'x-acs-content-sha256': payloadHash,
  };
  if (securityToken) headers['x-acs-security-token'] = securityToken;
  if (contentType) headers['content-type'] = contentType;

  const sortedKeys = Object.keys(headers).sort();
  const signedHeaders = sortedKeys.join(';');
  const canonicalHeaders = `${sortedKeys.map((key) => `${key}:${String(headers[key]).trim()}`).join('\n')}\n`;

  const canonicalRequest = [
    method,
    canonicalUri,
    canonicalQueryString,
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join('\n');

  const stringToSign = `${SIGN_ALGORITHM}\n${await sha256Hex(canonicalRequest)}`;
  const signature = await hmacSha256Hex(accessKeySecret, stringToSign);
  const authorization = `${SIGN_ALGORITHM} Credential=${accessKeyId},SignedHeaders=${signedHeaders},Signature=${signature}`;

  return {
    authorization,
    headers,
    canonicalQueryString,
    canonicalRequest,
    stringToSign,
    debug: {
      payloadHash,
      canonicalQueryString,
      canonicalHeaders,
      signedHeaders,
      canonicalRequest,
      stringToSign,
      signature,
    },
  };
}

/** ESA 业务错误：携带阿里云的 Code / RequestId，便于定位 */
export class EsaApiError extends Error {
  constructor(code, message, requestId = '', httpStatus = 0) {
    super(message || code);
    this.name = 'EsaApiError';
    this.code = code;
    this.requestId = requestId;
    this.httpStatus = httpStatus;
  }
}

export class EsaClient {
  constructor({ accessKeyId, accessKeySecret, securityToken, endpoint = DEFAULT_ENDPOINT, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
    if (!accessKeyId || !accessKeySecret) {
      throw new Error('missing credentials: 需要 AccessKeyId 与 AccessKeySecret');
    }
    this.accessKeyId = accessKeyId;
    this.accessKeySecret = accessKeySecret;
    this.securityToken = securityToken || '';
    this.endpoint = String(endpoint || DEFAULT_ENDPOINT).replace(/\/+$/, '');
    this.timeoutMs = Number(timeoutMs) > 0 ? Number(timeoutMs) : DEFAULT_TIMEOUT_MS;
    this.host = new URL(this.endpoint).host;
  }

  /**
   * 发起一次 OpenAPI 调用（RPC 风格：参数放 QueryString，请求体为空）
   * ESA 网关按接口限制方法：List / Get / Describe 开头的接口只能用 GET，其余写入接口用 POST
   */
  async call(action, params = {}) {
    const method = /^(List|Get|Describe)/.test(action) ? 'GET' : 'POST';
    const flatParams = flattenParams(params);
    const date = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
    const nonce = randomNonce();
    const payloadHash = await sha256Hex('');

    const signed = await buildSignature({
      accessKeyId: this.accessKeyId,
      accessKeySecret: this.accessKeySecret,
      action,
      host: this.host,
      flatParams,
      date,
      nonce,
      payloadHash,
      securityToken: this.securityToken,
      method,
    });

    const url = `${this.endpoint}/?${signed.canonicalQueryString}`;
    const headers = { ...signed.headers, Authorization: signed.authorization, Accept: 'application/json' };

    let response;
    try {
      response = await fetchWithTimeout(url, { method, headers }, this.timeoutMs);
    } catch (err) {
      if (err instanceof EsaApiError) throw err;
      const reason = err?.name === 'AbortError' ? 'timeout' : err?.message || 'network error';
      throw new EsaApiError('NetworkError', `ESA API 请求失败（${reason}）`, '', 0);
    }

    const rawText = await response.text();
    let body = {};
    try {
      body = rawText ? JSON.parse(rawText) : {};
    } catch {
      throw new EsaApiError('InvalidResponse', `ESA 返回了非 JSON 内容：${rawText.slice(0, 200)}`, '', response.status);
    }

    // RPC 风格的错误直接放在顶层：{ Code, Message, RequestId, ... }
    if (body.Code) {
      throw new EsaApiError(body.Code, body.Message || body.Code, body.RequestId || '', response.status);
    }
    if (!response.ok) {
      throw new EsaApiError('HttpError', `HTTP ${response.status}：${rawText.slice(0, 200)}`, body.RequestId || '', response.status);
    }
    return body;
  }

  /* ---------------------------------- 记录（加速域名） ---------------------------------- */

  /** 查询站点下的 DNS 记录列表 */
  async listRecords(siteId, { recordName = '', matchType = 'exact', type = '', proxied = null, pageNumber = 1, pageSize = 200 } = {}) {
    const params = { SiteId: siteId, PageNumber: pageNumber, PageSize: pageSize };
    if (recordName) {
      params.RecordName = recordName;
      params.RecordMatchType = matchType;
    }
    if (type) params.Type = type;
    if (proxied !== null && proxied !== undefined) params.Proxied = Boolean(proxied) ? 'true' : 'false';
    const res = await this.call('ListRecords', params);
    return { records: res.Records || [], total: res.Total ?? res.TotalCount ?? null, requestId: res.RequestId };
  }

  /** 按记录名精确查找一条记录；若同时存在代理与非代理记录，优先返回加速（Proxied）记录 */
  async findRecord(siteId, recordName) {
    const { records } = await this.listRecords(siteId, { recordName, matchType: 'exact' });
    const exact = records.filter((item) => String(item.RecordName).toLowerCase() === String(recordName).toLowerCase());
    if (!exact.length) return null;
    return exact.find((item) => item.Proxied === true) || exact[0];
  }

  /** 获取记录详情（含 Data.Value、RecordSourceType 等） */
  async getRecord(recordId) {
    const res = await this.call('GetRecord', { RecordId: recordId });
    return res.Record || res;
  }

  /** 更新记录（用于「普通域名源站」的 CNAME / 代理的 A·AAAA 记录：记录值就是源站地址） */
  async updateRecord(record) {
    const res = await this.call('UpdateRecord', record);
    return { recordId: res.RecordId ?? record.RecordId ?? null, requestId: res.RequestId };
  }

  /* ------------------------------------ 源地址池 ------------------------------------ */

  /** 查询站点下的源地址池 */
  async listOriginPools(siteId, { name = '', matchType = 'exact', pageNumber = 1, pageSize = 200 } = {}) {
    const params = { SiteId: siteId, PageNumber: pageNumber, PageSize: pageSize };
    if (name) {
      params.Name = name;
      params.MatchType = matchType;
    }
    const res = await this.call('ListOriginPools', params);
    return { pools: res.Pools || [], total: res.Total ?? res.TotalCount ?? null, requestId: res.RequestId };
  }

  /**
   * 找到某条记录（加速域名）实际引用的源地址池
   * 优先按 References.DnsRecords[].Id 精确匹配，其次按池名与记录名匹配
   */
  async findOriginPoolByRecord(siteId, { recordId = null, recordName = '' } = {}) {
    const { pools } = await this.listOriginPools(siteId, { pageSize: 200 });
    if (recordId) {
      const byRef = pools.find((pool) => {
        const refs = Array.isArray(pool.References?.DnsRecords) ? pool.References.DnsRecords : [];
        return refs.some((ref) => String(ref.Id) === String(recordId));
      });
      if (byRef) return byRef;
    }
    if (recordName) {
      return pools.find((pool) => String(pool.Name).toLowerCase() === String(recordName).toLowerCase()) || null;
    }
    return null;
  }

  /** 全量更新源地址池中的源站地址（Origins 为覆盖式写入） */
  async updateOriginPool({ siteId, id, origins, enabled = null }) {
    const params = { SiteId: siteId, Id: id, Origins: origins };
    if (enabled !== null && enabled !== undefined) params.Enabled = Boolean(enabled) ? 'true' : 'false';
    const res = await this.call('UpdateOriginPool', params);
    return { id: res.Id ?? id, requestId: res.RequestId };
  }

  /* ------------------------------ 回源规则（协议与端口） ------------------------------ */

  /** 查询站点的回源规则（含全局配置） */
  async listOriginRules(siteId, { configType = '', pageNumber = 1, pageSize = 200 } = {}) {
    const params = { SiteId: siteId, PageNumber: pageNumber, PageSize: pageSize };
    if (configType) params.ConfigType = configType;
    const res = await this.call('ListOriginRules', params);
    return { configs: res.Configs || [], total: res.Total ?? res.TotalCount ?? null, requestId: res.RequestId };
  }

  /** 新建一条回源规则（按 http.host 精确匹配某个加速域名） */
  async createOriginRule(rule) {
    const res = await this.call('CreateOriginRule', rule);
    return { configId: res.ConfigId ?? null, requestId: res.RequestId };
  }

  /** 更新已有回源规则；全局配置（ConfigType=global）只能改端口与协议 */
  async updateOriginRule(rule) {
    const res = await this.call('UpdateOriginRule', rule);
    return { configId: res.ConfigId ?? rule.ConfigId ?? null, requestId: res.RequestId };
  }
}

async function fetchWithTimeout(url, init, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

/** 把 ESA 的业务错误码映射成对调用方友好的 HTTP 状态码 */
export function mapEsaCodeToStatus(code = '') {
  const value = String(code);
  if (/InvalidAccessKeyId|SignatureDoesNotMatch|IncompleteSignature|InvalidSecurityToken|ExpiredToken/i.test(value)) return 403;
  if (/Invalid|Param|Malformed|Format|Missing|Required|NotValid|Length|TooLong/i.test(value)) return 400;
  if (/NotFound|NotExist|NotFoundSite|Record\.NotFound/i.test(value)) return 404;
  if (/Forbidden|NoPermission|Unauthorized|Denied|Auth/i.test(value)) return 403;
  if (/Throttl|LimitExceeded|RequestLimit|FlowLimit/i.test(value)) return 429;
  return 502;
}

export { DEFAULT_ENDPOINT, DEFAULT_TIMEOUT_MS, API_VERSION, SIGN_ALGORITHM };
