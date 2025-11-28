import crypto from 'node:crypto';
import SwiftAuthenticator from './SwiftAuthenticator.js';
import {fetchWithRetry} from './http.js';
import {Readable} from "node:stream";

/** Structured logger interface (JSON lines). */
export interface Logger {
  log(level: 'debug' | 'info' | 'warn' | 'error', message: string, fields?: Record<string, unknown>): void;
}

/** Minimal JSON logger to stdout. Replace with pino/winston if you like. */
export class JsonLogger implements Logger {
  log(level: 'debug' | 'info' | 'warn' | 'error', message: string, fields?: Record<string, unknown>): void {
    const line = {
      ts: new Date().toISOString(),
      level,
      msg: message,
      ...(fields ?? {}),
    };
    console.log(JSON.stringify(line));
  }
}

export interface SwiftAdapterOptions {
  /** Swift public endpoint base, e.g. https://swift.example.com/v1 */
  baseUrl: string;
  /** Keystone/Swift project (tenant) ID */
  projectId: string;
  /** Swift container name */
  container: string;

  /** Keystone (Identity v3) auth URL */
  authUrl: string;
  /** Keystone user ID (not name) */
  userId: string;
  /** Keystone password/secret */
  password: string;

  /** When true, getFileLocation returns the direct Swift URL */
  directAccess?: boolean;

  /** Optional structured logger (defaults to JsonLogger) */
  logger?: Logger;
}

/** Options for creating a file (PUT). */
export interface CreateFileOptions {
  /** MIME type for the object, e.g. "image/png" */
  contentType?: string;
  /** Additional headers to forward to Swift */
  headers?: Record<string, string>;
  /**
   * If provided, enforce *create only* semantics:
   * - If `true`, sends `If-None-Match: *` (don’t overwrite existing object).
   * - If a string, sends `If-Match: <value>` (update only if current ETag matches).
   */
  conditional?: true | string;
  /**
   * Provide a precomputed MD5 hex to use as the ETag header. If omitted,
   * the adapter computes MD5 over the payload and supplies it to Swift.
   */
  etagHex?: string;
}

/** Options for deleting a file (DELETE). */
export interface DeleteFileOptions {
  /** Require ETag match: sends `If-Match: <etag>` */
  ifMatchETag?: string;
  /** Treat 404 as success (idempotent delete). Default: true */
  ignoreNotFound?: boolean;
}

/** Result metadata returned by metadata-aware calls. */
export interface ObjectMeta {
  etag?: string;
  lastModified?: string;
  contentType?: string;
  contentLength?: number;
}

/** FileConfig used to build public-facing URLs. */
export interface FileConfig {
  mount: string;
  applicationId: string;
}

/**
 * SwiftAdapter
 *
 * High-level, resilient client for OpenStack Swift:
 *  - Single-flight, expiry-aware Keystone auth (via SwiftAuthenticator)
 *  - Robust retries/backoff for transient errors (via fetchWithRetry)
 *  - ETag integrity and conditional requests (If-Match / If-None-Match)
 *  - Structured JSON logs with correlation IDs
 */
export default class SwiftAdapter {
  private readonly baseUrl: string;
  private readonly directAccess: boolean;
  private readonly authenticator: SwiftAuthenticator;
  private readonly logger: Logger;

  constructor(options: SwiftAdapterOptions) {
    this.baseUrl = `${options.baseUrl}/AUTH_${options.projectId}/${options.container}`;
    this.directAccess = options.directAccess ?? false;
    this.logger = options.logger ?? new JsonLogger();

    this.authenticator = new SwiftAuthenticator({
      projectId: options.projectId,
      authUrl: options.authUrl,
      userId: options.userId,
      password: options.password,
      clockSkewSec: 60,
    });
  }

  /**
   * Upload (PUT) an object to Swift with ETag integrity and optional conditional headers.
   *
   * - Computes MD5 and sends as `ETag` unless `options.etagHex` is provided.
   * - Create-only: `conditional: true` → `If-None-Match: *`.
   * - Update-if-match: `conditional: "<etag>"` → `If-Match: <etag>`.
   *
   * @param filename  Object name within the container
   * @param data      Buffer or string payload
   * @param options   Content-Type, conditional headers, and extra headers
   * @returns         Object metadata (ETag, Last-Modified, Content-Type, Length)
   * @throws          Error with HTTP context on failure
   */
  public async createFile(
    filename: string,
    data: Buffer | string,
    options: CreateFileOptions = {}
  ): Promise<ObjectMeta> {
    const url = `${this.baseUrl}/${encodeURIComponent(filename)}`;
    const reqId = this.newRequestId();

    const etag = options.etagHex ?? this.computeMD5Hex(data);
    const headers: Record<string, string> = {
      'ETag': etag,
      ...(options.contentType ? {'Content-Type': options.contentType} : {}),
      ...(options.headers ?? {}),
    };

    if (options.conditional === true) {
      headers['If-None-Match'] = '*';
    } else if (typeof options.conditional === 'string') {
      headers['If-Match'] = options.conditional;
    }

    this.log('info', 'swift.put.begin', {reqId, filename, url, headers: redactHeaders(headers)});

    const res = await this.authFetchWithRetry(url, {
      method: 'PUT',
      headers,
      body: this.toBody(data),
    }, {allowPutRetry503: true, reqId});

    const bodyText = await safeText(res);
    this.log('info', 'swift.put.end', {
      reqId, filename, status: res.status, statusText: res.statusText, body: bodyText?.slice(0, 300),
    });

    // Creation success
    if (res.status === 201)
      return extractMeta(res);

    // 412: precondition failed (ETag mismatch or object exists when If-None-Match: *)
    if (res.status === 412)
      throw httpError('Swift PUT precondition failed (412)', res, {reqId, filename});

    // 422: ETag/content-MD5 mismatch (Swift may use 422 for bad ETag)
    if (res.status === 422)
      throw httpError('Swift PUT failed: ETag/content MD5 mismatch (422)', res, {reqId, filename});

    throw httpError(`Swift PUT failed: ${res.status} ${res.statusText}`, res, {reqId, filename});
  }

  /**
   * Delete (DELETE) an object, optionally requiring a specific ETag with `If-Match`.
   *
   * @param filename       Object name
   * @param options        If-Match ETag and 404 handling
   * @returns              void
   * @throws               Error on unexpected status
   */
  public async deleteFile(filename: string, options: DeleteFileOptions = {}): Promise<void> {
    const url = `${this.baseUrl}/${encodeURIComponent(filename)}`;
    const reqId = this.newRequestId();

    const headers: Record<string, string> = {};
    if (options.ifMatchETag) headers['If-Match'] = options.ifMatchETag;

    this.log('info', 'swift.delete.begin', {reqId, filename, url, headers});

    const res = await this.authFetchWithRetry(url, {method: 'DELETE', headers}, {reqId});
    const bodyText = await safeText(res);

    this.log('info', 'swift.delete.end', {
      reqId, filename, status: res.status, statusText: res.statusText, body: bodyText?.slice(0, 300),
    });

    if (res.status === 204) return;

    if ((options.ignoreNotFound ?? true) && res.status === 404) return;

    if (res.status === 412) {
      throw httpError('Swift DELETE precondition failed (412 If-Match)', res, {reqId, filename});
    }

    throw httpError(`Swift DELETE failed: ${res.status} ${res.statusText}`, res, {reqId, filename});
  }

  /**
   * Download (GET) an object as raw bytes.
   * Backwards-compatible with your old signature.
   *
   * @param filename  Object name
   * @returns         Buffer with object content
   * @throws          Error on non-200
   */
  public async getFileData(filename: string): Promise<Buffer> {
    const {data} = await this.getFile(filename);
    return data;
  }

  /**
   * Download (GET) an object and return content + metadata (ETag, Content-Type, etc.).
   *
   * @param filename  Object name
   * @returns         { data, meta }
   * @throws          Error on non-200
   */
  public async getFile(filename: string): Promise<{ data: Buffer; meta: ObjectMeta }> {
    const url = `${this.baseUrl}/${encodeURIComponent(filename)}`;
    const reqId = this.newRequestId();

    this.log('info', 'swift.get.begin', {reqId, filename, url});

    const res = await this.authFetchWithRetry(url, {method: 'GET'}, {reqId});
    const meta = extractMeta(res);

    if (res.status !== 200) {
      const bodyText = await safeText(res);
      this.log('warn', 'swift.get.error', {
        reqId, filename, status: res.status, statusText: res.statusText, body: bodyText?.slice(0, 300),
      });
      throw httpError(`Swift GET failed: ${res.status} ${res.statusText}`, res, {reqId, filename});
    }

    const arrayBuffer = await res.arrayBuffer();
    const data = Buffer.from(arrayBuffer);

    this.log('info', 'swift.get.end', {reqId, filename, status: res.status, etag: meta.etag});
    return {data, meta};
  }

  /**
   * HEAD the object to retrieve metadata without downloading the body.
   *
   * @param filename  Object name
   * @returns         Object metadata (ETag, Last-Modified, Content-Type, Length)
   * @throws          Error on non-200
   */
  public async headFile(filename: string): Promise<ObjectMeta> {
    const url = `${this.baseUrl}/${encodeURIComponent(filename)}`;
    const reqId = this.newRequestId();

    this.log('debug', 'swift.head.begin', {reqId, filename, url});

    const res = await this.authFetchWithRetry(url, {method: 'HEAD'}, {reqId});
    const meta = extractMeta(res);

    if (res.status !== 200) {
      const bodyText = await safeText(res);
      this.log('warn', 'swift.head.error', {
        reqId, filename, status: res.status, statusText: res.statusText, body: bodyText?.slice(0, 300),
      });
      throw httpError(`Swift HEAD failed: ${res.status} ${res.statusText}`, res, {reqId, filename});
    }

    this.log('debug', 'swift.head.end', {reqId, filename, status: res.status, etag: meta.etag});
    return meta;
  }

  /**
   * Compute a client-facing URL (either direct Swift URL or your files proxy).
   *
   * @param config   App config (mount + appId)
   * @param filename Object name
   * @returns        Resolved URL string
   */
  public getFileLocation(config: FileConfig, filename: string): string {
    const encoded = encodeURIComponent(filename);
    if (this.directAccess) {
      return `${this.baseUrl}/${encoded}`;
    }
    return `${config.mount}/files/${config.applicationId}/${encoded}`;
  }

  /**
   * NEW: Upload a file to Swift as a STREAM (no buffering)
   */
  public async createFileStream(
    filename: string,
    stream: Readable | NodeJS.ReadableStream,
    options: CreateFileOptions = {},
  ): Promise<ObjectMeta> {
    const url = `${this.baseUrl}/${encodeURIComponent(filename)}`;
    const reqId = this.newRequestId();
    const headers: Record<string,string> = {
      ...(options.contentType ? {'Content-Type': options.contentType} : {}),
      ...(options.headers ?? {}),
    };
    if (options.etagHex) {
      headers['ETag'] = options.etagHex;
    }
    if (options.conditional === true) headers['If-None-Match'] = '*';
    else if (typeof options.conditional === 'string') headers['If-Match'] = options.conditional;
    this.log('info','swift.put.stream.begin',{reqId,filename,url});
    const res = await this.authFetchWithRetry(url,{
      method:'PUT',
      headers,
      body:stream as any,
    },{reqId});
    const txt = await safeText(res);
    this.log('info','swift.put.stream.end',{reqId,filename,status:res.status,body:txt?.slice(0,200)});
    if(res.status===201) return extractMeta(res);
    throw httpError(`Swift PUT stream failed ${res.status}`,res,{reqId,filename});
  }

  // ===== Internals ==========================================================

  private async authFetchWithRetry(
    url: string,
    init: RequestInit,
    opts?: { allowPutRetry503?: boolean; reqId?: string },
  ): Promise<Response> {
    const reqId = opts?.reqId ?? this.newRequestId();
    const token = await this.authenticator.getToken();

    const withAuth: any = {
      ...init,
      headers: {
        ...(init.headers ?? {}),
        'X-Auth-Token': token,
      },
    };

    // If streaming - ensure Node fetch duplex is present
    if (withAuth.body && typeof withAuth.body === 'object') {
      withAuth.duplex = 'half';
    }

    const policy = {
      forceRetryMethods: opts?.allowPutRetry503 ? {PUT: [503]} : {},
    };

    let res = await fetchWithRetry(url, withAuth, policy);

    if (res.status === 401 || res.status === 403) {
      this.log('warn', 'swift.auth.invalid', {reqId, status: res.status, statusText: res.statusText});
      this.authenticator.invalidate();
      const fresh = await this.authenticator.getToken();

      const retryInit: any = {
        ...init,
        headers: {
          ...(init.headers ?? {}),
          'X-Auth-Token': fresh,
        },
      };

      if (retryInit.body && typeof retryInit.body === 'object') {
        retryInit.duplex = 'half';
      }

      res = await fetchWithRetry(url, retryInit, policy);
    }

    return res;
  }


  private computeMD5Hex(data: Buffer | string): string {
    const h = crypto.createHash('md5');
    if (typeof data === 'string') h.update(data, 'utf8');
    else h.update(data);
    return h.digest('hex');
  }

  private newRequestId(): string {
    // lightweight correlation ID
    return Math.random().toString(36).slice(2, 10) + Math.random().toString(36).slice(2, 10);
  }

  private log(level: 'debug' | 'info' | 'warn' | 'error', msg: string, fields?: Record<string, unknown>) {
    this.logger.log(level, msg, fields);
  }

  // Normalize Buffer|string to a BodyInit-compatible type
  private toBody(data: Buffer | string): BodyInit {
    if (typeof data === 'string') return data;
    // Buffer is a Uint8Array; returning a new Uint8Array is always BodyInit
    return new Uint8Array(data);
  }
}

// ===== Helpers ==============================================================

function extractMeta(res: Response): ObjectMeta {
  const etag = res.headers.get('etag') ?? undefined;
  const lastModified = res.headers.get('last-modified') ?? undefined;
  const contentType = res.headers.get('content-type') ?? undefined;
  const lenStr = res.headers.get('content-length');
  const contentLength = typeof lenStr === 'string' ? Number(lenStr) : undefined;
  // @ts-ignore
  return {etag, lastModified, contentType, contentLength};
}

async function safeText(res: Response): Promise<string | null> {
  try {
    const t = await res.text();
    return t ?? null;
  } catch {
    return null;
  }
}

function httpError(message: string, res: Response, ctx?: Record<string, unknown>): Error {
  const err = new Error(message);
  (err as any).http = {
    status: res.status,
    statusText: res.statusText,
    headers: Object.fromEntries(res.headers.entries()),
    ...ctx,
  };
  return err;
}

function redactHeaders(h: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(h)) {
    const key = k.toLowerCase();
    if (key === 'authorization' || key === 'x-auth-token') {
      out[k] = '***';
    } else {
      out[k] = v;
    }
  }
  return out;
}
