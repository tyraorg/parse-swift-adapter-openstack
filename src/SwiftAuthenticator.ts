import {EventEmitter} from 'events';

export interface SwiftAuthenticatorOptions {
  projectId: string;
  authUrl: string;
  baseUrl: string;
  userId: string;
  password: string;
}

enum AuthState {
  UNAUTHENTICATED = 0,
  AUTHENTICATED = 1,
  FAILED = 2,
}

export class SwiftAuthenticator extends EventEmitter {
  static readonly AUTH_EVENT = 'authentication';
  private readonly projectId: string;
  private readonly authUrl: string;
  private readonly baseUrl: string;
  private readonly userId: string;
  private readonly password: string;
  private authState = AuthState.UNAUTHENTICATED;
  private tokenId: string | null = null;
  private authError: unknown = null;
  private isAuthenticating = false;

  constructor(options: SwiftAuthenticatorOptions) {
    super();
    this.projectId = options.projectId;
    this.authUrl = options.authUrl;
    this.baseUrl = options.baseUrl;
    this.userId = options.userId;
    this.password = options.password;
  }

  /**
   * Returns a valid token, re-using or refreshing as needed.
   * Resolves to the token string or rejects with an error.
   */
  public async authenticate(): Promise<string> {
    const waitForAuth = (): Promise<string> =>
      new Promise((resolve, reject) => {
        const listener = () => {
          this.removeListener(SwiftAuthenticator.AUTH_EVENT, listener);
          if (this.authState === AuthState.AUTHENTICATED && this.tokenId) {
            resolve(this.tokenId);
          } else {
            reject(this.authError);
          }
        };
        this.on(SwiftAuthenticator.AUTH_EVENT, listener);
        this.authenticateRequest();
      });

    switch (this.authState) {
      case AuthState.AUTHENTICATED:
        if (await this.validateToken()) {
          return this.tokenId as string;
        }
        return waitForAuth();
      case AuthState.UNAUTHENTICATED:
        return waitForAuth();
      case AuthState.FAILED:
        return Promise.reject(this.authError);
      default:
        return waitForAuth();
    }
  }

  /**
   * Kick off a POST to the Keystone endpoint to get a new token.
   * Emits `AUTH_EVENT` on success or failure.
   */
  private async authenticateRequest(): Promise<void> {
    if (this.isAuthenticating) return;
    this.isAuthenticating = true;

    try {
      const res = await fetch(this.authUrl, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          auth: {
            identity: {
              methods: ['password'],
              password: {
                user: {id: this.userId, password: this.password},
              },
            },
            scope: {project: {id: this.projectId}},
          },
        }),
      });

      if (res.status === 201) {
        this.tokenId = res.headers.get('x-subject-token');
        this.authState = AuthState.AUTHENTICATED;
        this.authError = null;
      } else {
        this.tokenId = null;
        this.authState = AuthState.FAILED;
        this.authError = `${res.status} - ${res.statusText}`;
        console.error(`SwiftAuthenticator: auth failed ${res.status} ${res.statusText}`);
      }
    } catch (err) {
      this.tokenId = null;
      this.authState = AuthState.FAILED;
      this.authError = err;
      console.error('SwiftAuthenticator: authenticateRequest() error', err);
    } finally {
      this.isAuthenticating = false;
      this.emit(SwiftAuthenticator.AUTH_EVENT);
    }
  }

  /**
   * HEADs the container to verify the current token.
   * If it’s invalid, reset state so we re-auth next time.
   */
  private async validateToken(): Promise<boolean> {
    if (!this.tokenId) return false;
    const res = await fetch(this.baseUrl, {
      method: 'HEAD',
      headers: {'X-Auth-Token': this.tokenId},
    });
    if (res.status === 204) {
      return true;
    }
    console.error(`SwiftAuthenticator: token invalidated ${res.status} ${res.statusText}`);
    this.authState = AuthState.UNAUTHENTICATED;
    this.tokenId = null;
    return false;
  }
}

export default SwiftAuthenticator;
