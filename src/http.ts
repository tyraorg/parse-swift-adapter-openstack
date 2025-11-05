// A resilient fetch wrapper with exponential backoff + jitter, per-attempt timeout,
// and smart retry rules for transient errors.

export type RetryPolicy = {
  /** Max total retry attempts (not counting the first try). Default: 4 */
  maxRetries?: number;
  /** Base backoff in ms. Grows exponentially. Default: 200 */
  baseDelayMs?: number;
  /** Max backoff in ms. Default: 4000 */
  maxDelayMs?: number;
  /** Extra jitter ratio [0..1], applied to each delay. Default: 0.2 (±20%) */
  jitterRatio?: number;
  /** Per-attempt timeout in ms. Default: 8000 */
  attemptTimeoutMs?: number;
  /** Status codes worth retrying. */
  retryOnStatus?: number[];
  /** Retry on network errors like ECONNRESET, ETIMEDOUT... Default: true */
  retryOnNetworkErrors?: boolean;
  /** Methods considered safe/idempotent for retries. Default: GET, HEAD, DELETE */
  idempotentMethods?: string[];
  /** Force retries even for non-idempotent methods (e.g., PUT) when status is 503. Default: {} */
  forceRetryMethods?: Record<string, number[]>; // e.g. { PUT: [503] }
};

export const defaultRetryPolicy: Required<RetryPolicy> = {
  maxRetries: 4,
  baseDelayMs: 200,
  maxDelayMs: 4000,
  jitterRatio: 0.2,
  attemptTimeoutMs: 8000,
  retryOnStatus: [408, 425, 429, 500, 502, 503, 504],
  retryOnNetworkErrors: true,
  idempotentMethods: ['GET', 'HEAD', 'DELETE'],
  forceRetryMethods: {},
};

export type FetchLike = typeof fetch;

export async function fetchWithRetry(
  url: string,
  init: RequestInit = {},
  policy: RetryPolicy = {},
  _fetch: FetchLike = fetch
): Promise<Response> {
  const cfg: Required<RetryPolicy> = {...defaultRetryPolicy, ...policy};
  const method = (init.method ?? 'GET').toUpperCase();

  const mayRetryStatus = (status: number) => {
    if (cfg.retryOnStatus.includes(status)) {
      if (cfg.idempotentMethods.includes(method)) return true;
      const forced = cfg.forceRetryMethods[method];
      return Array.isArray(forced) && forced.includes(status);
    }
    return false;
  };

  const sleep = (ms: number) =>
    new Promise((r) => setTimeout(r, ms));

  const backoff = (attempt: number) => {
    const exp = Math.min(cfg.maxDelayMs, cfg.baseDelayMs * Math.pow(2, attempt));
    const jitter = exp * cfg.jitterRatio * (Math.random() * 2 - 1); // ±jitterRatio
    return Math.max(0, Math.round(exp + jitter));
  };

  let lastErr: unknown;

  for (let attempt = 0; attempt <= cfg.maxRetries; attempt++) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), cfg.attemptTimeoutMs);

    try {
      const res = await _fetch(url, {...init, signal: controller.signal});

      if (!mayRetryStatus(res.status)) {
        clearTimeout(timeout);
        return res;
      }

      // Transient status—retry if we still have attempts left
      if (attempt < cfg.maxRetries) {
        clearTimeout(timeout);
        await sleep(backoff(attempt));
        continue;
      }

      clearTimeout(timeout);
      return res; // give the caller the final response (likely an error)
    } catch (err: any) {
      clearTimeout(timeout);
      lastErr = err;

      const isAbort = err?.name === 'AbortError';
      const isNetErr =
        cfg.retryOnNetworkErrors &&
        !isAbort; // treat timeouts/connection resets as retriable

      if (!isNetErr || attempt >= cfg.maxRetries) {
        throw err;
      }

      await sleep(backoff(attempt));
    }
  }

  // Should not reach, but TypeScript wants a return/throw
  throw lastErr ?? new Error('fetchWithRetry failed unexpectedly');
}
