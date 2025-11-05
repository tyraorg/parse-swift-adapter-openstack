import {EventEmitter} from 'events';

export interface SwiftAuthenticatorOptions {
  projectId: string;
  authUrl: string;
  userId: string;
  password: string;
  /** Seconds of clock skew to subtract from Keystone expiry. Default: 60s */
  clockSkewSec?: number;
  /** Optional extra headers for auth (e.g., proxies). */
  headers?: Record<string, string>;
  /** Optional fetch impl for testing. */
  fetchImpl?: typeof fetch;
}

type TokenState = {
  token: string;
  /** When we should treat the token as expired (already skew-adjusted) */
  expiresAt: Date;
};

enum AuthState {
  UNAUTHENTICATED = 0,
  AUTHENTICATING = 1,
  AUTHENTICATED = 2,
  FAILED = 3,
}

export class SwiftAuthenticator extends EventEmitter {
  static readonly AUTH_EVENT = 'authentication';

  private readonly projectId: string;
  private readonly authUrl: string;
  private readonly userId: string;
  private readonly password: string;
  private readonly clockSkewMs: number;
  private readonly headers: Record<string, string>;
  private readonly _fetch: typeof fetch;

  private state: AuthState = AuthState.UNAUTHENTICATED;
  private current?: TokenState | undefined;
  private inflight?: Promise<string> | undefined; // single-flight

  constructor(opts: SwiftAuthenticatorOptions) {
    super();
    this.projectId = opts.projectId;
    this.authUrl = opts.authUrl;
    this.userId = opts.userId;
    this.password = opts.password;
    this.clockSkewMs = (opts.clockSkewSec ?? 60) * 1000;
    this.headers = opts.headers ?? {};
    this._fetch = opts.fetchImpl ?? fetch;
  }

  /**
   * Get a valid token (refreshing only when needed).
   * Multiple concurrent callers share the same refresh promise.
   */
  public async getToken(): Promise<string> {
    if (this.isTokenValid()) {
      return this.current!.token;
    }
    return this.refreshTokenShared();
  }

  /** Call on 401/403 from Swift to force a single refresh before retrying. */
  public invalidate(): void {
    this.current = undefined;
    if (this.state === AuthState.AUTHENTICATED) {
      this.state = AuthState.UNAUTHENTICATED;
    }
  }

  private isTokenValid(): boolean {
    if (!this.current) return false;
    return Date.now() < this.current.expiresAt.getTime();
  }

  private async refreshTokenShared(): Promise<string> {
    if (this.inflight) return this.inflight;

    this.state = AuthState.AUTHENTICATING;
    this.inflight = this.refreshToken()
      .then((token) => {
        this.state = AuthState.AUTHENTICATED;
        this.emit(SwiftAuthenticator.AUTH_EVENT, {ok: true});
        return token;
      })
      .catch((err) => {
        this.state = AuthState.FAILED;
        this.emit(SwiftAuthenticator.AUTH_EVENT, {ok: false, error: err});
        throw err;
      })
      .finally(() => {
        this.inflight = undefined;
      });

    return this.inflight;
  }

  /**
   * Actually request a token from Keystone (Identity v3).
   * Reads X-Subject-Token and the JSON body to extract token.expires_at.
   */
  private async refreshToken(): Promise<string> {
    const res = await this._fetch(this.authUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...this.headers,
      },
      body: JSON.stringify({
        auth: {
          identity: {
            methods: ['password'],
            password: {user: {id: this.userId, password: this.password}},
          },
          scope: {project: {id: this.projectId}},
        },
      }),
    });

    if (res.status !== 201) {
      // Try to capture body text for diagnostics without assuming JSON
      const body = await safeReadBody(res);
      throw new Error(
        `Keystone auth failed: ${res.status} ${res.statusText} ${body ? `- ${body}` : ''}`.trim()
      );
    }

    const token = res.headers.get('x-subject-token');
    if (!token) {
      throw new Error('Keystone auth failed: missing X-Subject-Token header');
    }

    // Keystone v3 returns JSON with token.expires_at
    const payload = await res.json().catch(() => ({} as any));
    const expiresAtRaw: string | undefined = payload?.token?.expires_at;
    if (!expiresAtRaw) {
      // Fallback: if expires_at missing, use short TTL (10 min) to be safe
      const fallback = new Date(Date.now() + 10 * 60 * 1000 - this.clockSkewMs);
      this.current = {token, expiresAt: fallback};
      return token;
    }

    const expires = new Date(expiresAtRaw);
    // Apply skew (expire a little early to avoid edge races)
    const adjusted = new Date(expires.getTime() - this.clockSkewMs);
    this.current = {token, expiresAt: adjusted};

    return token;
  }
}

async function safeReadBody(res: Response): Promise<string | null> {
  try {
    const txt = await res.text();
    return txt?.slice(0, 500) ?? null;
  } catch {
    return null;
  }
}

export default SwiftAuthenticator;
