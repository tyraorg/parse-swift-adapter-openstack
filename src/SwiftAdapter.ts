import SwiftAuthenticator from './SwiftAuthenticator.js';

export interface SwiftAdapterOptions {
  baseUrl: string;
  projectId: string;
  container: string;
  authUrl: string;
  userId: string;
  password: string;
  directAccess?: boolean;
}

export interface FileConfig {
  mount: string;
  applicationId: string;
}

export default class SwiftAdapter {
  private baseUrl: string;
  private directAccess: boolean;
  private authenticator: SwiftAuthenticator;

  constructor(options: SwiftAdapterOptions) {
    this.baseUrl = `${options.baseUrl}/AUTH_${options.projectId}/${options.container}`;
    this.directAccess = options.directAccess ?? false;

    this.authenticator = new SwiftAuthenticator({
      projectId: options.projectId,
      authUrl: options.authUrl,
      baseUrl: this.baseUrl,
      userId: options.userId,
      password: options.password,
    });
  }

  /**
   * Uploads a file to Swift.
   * @param filename   Name of the file (within the container)
   * @param data       Buffer or string content
   * @param contentType Optional MIME type, e.g. "image/png"
   */
  public async createFile(
    filename: string,
    data: Buffer | string,
    contentType?: string
  ): Promise<void> {
    const token = await this.authenticator.authenticate();
    const res = await fetch(`${this.baseUrl}/${filename}`, {
      method: 'PUT',
      headers: {
        'X-Auth-Token': token,
        ...(contentType && {'Content-Type': contentType}),
      },
      body: data,
    });
    if (res.status !== 201) {
      throw new Error(`Failed with status code ${res.status}`);
    }
  }

  /**
   * Deletes a file from Swift.
   * @param filename Name of the file to delete
   */
  public async deleteFile(filename: string): Promise<void> {
    try {
      const token = await this.authenticator.authenticate();
      const res = await fetch(`${this.baseUrl}/${filename}`, {
        method: 'DELETE',
        headers: {
          'X-Auth-Token': token,
        },
      });
      if (res.status !== 204) {
        throw new Error(`Failed with status code ${res.status}`);
      }
    } catch (err) {
      console.error('SwiftAdapter.deleteFile():', err);
      throw err;
    }
  }

  /**
   * Retrieves raw file data.
   * @param filename Name of the file to fetch
   * @returns Buffer containing file contents
   */
  public async getFileData(filename: string): Promise<Buffer> {
    try {
      const token = await this.authenticator.authenticate();
      const res = await fetch(`${this.baseUrl}/${filename}`, {
        method: 'GET',
        headers: {
          'X-Auth-Token': token,
        },
      });
      if (res.status !== 200) {
        throw new Error(`Failed with status code ${res.status}`);
      }
      const arrayBuffer = await res.arrayBuffer();
      return Buffer.from(arrayBuffer);
    } catch (err) {
      console.error('SwiftAdapter.getFileData():', err);
      throw err;
    }
  }

  /**
   * Computes a client‐facing URL for a stored file.
   * @param config   App config (mount point + app ID)
   * @param filename The file name
   * @returns URL where the file can be accessed
   */
  public getFileLocation(config: FileConfig, filename: string): string {
    const encoded = encodeURIComponent(filename);
    if (this.directAccess) {
      return `${this.baseUrl}/${encoded}`;
    }
    return `${config.mount}/files/${config.applicationId}/${encoded}`;
  }
}

