import { readFile } from "node:fs/promises";
import { Server, createServer } from "node:net";
import { Client } from "ssh2";
import type { ClientChannel } from "ssh2";
import type { ServerConfig } from "./types.js";

export class SshExecService {
  private client: Client | undefined;
  private connecting: Promise<void> | undefined;
  private hasConnected = false;

  constructor(private readonly config: ServerConfig) {}

  async exec(
    command: string,
    opts: { timeoutMs?: number } = {}
  ): Promise<{ stdout: string; stderr: string; code: number }> {
    const ssh = await this.connectedClient();
    const timeoutMs = opts.timeoutMs ?? this.config.frida?.commandTimeoutMs ?? 30_000;

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error(`SSH exec timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      ssh.exec(command, (err, stream: ClientChannel) => {
        if (err) {
          clearTimeout(timer);
          reject(err);
          return;
        }

        let stdout = "";
        let stderr = "";

        stream.on("data", (data: Buffer) => {
          stdout += data.toString();
        });
        stream.stderr.on("data", (data: Buffer) => {
          stderr += data.toString();
        });
        stream.on("close", (code: number | null) => {
          clearTimeout(timer);
          resolve({ stdout, stderr, code: code ?? 0 });
        });
        stream.on("error", (streamErr: Error) => {
          clearTimeout(timer);
          reject(streamErr);
        });
      });
    });
  }

  async execStream(
    command: string,
    onData: (line: string) => void,
    signal: AbortSignal
  ): Promise<{ code: number }> {
    const ssh = await this.connectedClient();

    return new Promise((resolve, reject) => {
      ssh.exec(command, (err, stream: ClientChannel) => {
        if (err) {
          reject(err);
          return;
        }

        let buf = "";

        const abort = () => {
          try {
            stream.signal("KILL");
          } catch {
            /* ignore */
          }
          try {
            stream.close();
          } catch {
            /* ignore */
          }
        };

        signal.addEventListener("abort", abort, { once: true });

        stream.on("data", (data: Buffer) => {
          buf += data.toString();
          const lines = buf.split("\n");
          buf = lines.pop() ?? "";
          for (const line of lines) {
            if (line.trim()) onData(line);
          }
        });

        stream.stderr.on("data", (_data: Buffer) => {
          /* absorb stderr into event buffer via caller */
        });

        stream.on("close", (code: number | null) => {
          signal.removeEventListener("abort", abort);
          if (buf.trim()) onData(buf.trim());
          resolve({ code: code ?? 0 });
        });

        stream.on("error", (streamErr: Error) => {
          signal.removeEventListener("abort", abort);
          reject(streamErr);
        });
      });
    });
  }

  async writeFile(remotePath: string, content: string): Promise<void> {
    const ssh = await this.connectedClient();

    return new Promise((resolve, reject) => {
      ssh.sftp((err, sftp) => {
        if (err) {
          reject(err);
          return;
        }
        const ws = sftp.createWriteStream(remotePath);
        ws.on("close", () => resolve());
        ws.on("error", (wsErr: Error) => reject(wsErr));
        ws.write(Buffer.from(content, "utf8"));
        ws.end();
      });
    });
  }

  async deleteFile(remotePath: string): Promise<void> {
    const ssh = await this.connectedClient();

    return new Promise((resolve, reject) => {
      ssh.sftp((err, sftp) => {
        if (err) {
          reject(err);
          return;
        }
        sftp.unlink(remotePath, (unlinkErr) => {
          if (unlinkErr) reject(unlinkErr);
          else resolve();
        });
      });
    });
  }

  private async connectedClient(): Promise<Client> {
    if (this.client) return this.client;

    if (this.connecting) {
      await this.connecting;
      return this.client!;
    }

    this.connecting = this.doConnect();

    try {
      await this.connecting;
      return this.client!;
    } finally {
      this.connecting = undefined;
    }
  }

  private doConnect(): Promise<void> {
    return new Promise((resolve, reject) => {
      const client = new Client();
      let settled = false;

      client.once("ready", () => {
        this.hasConnected = true;
        this.client = client;
        settled = true;
        resolve();
      });

      client.on("error", (err: Error) => {
        this.client = undefined;
        // During initial connect, surface a proper rejection.
        if (!settled && !this.hasConnected) {
          settled = true;
          reject(new Error(`SSH exec connection failed: ${err.message}`));
          return;
        }
        // After successful connect, avoid crashing the process on transport errors.
      });

      client.once("end", () => {
        this.client = undefined;
      });

      client.on("close", () => {
        this.client = undefined;
        this.hasConnected = false;
      });

      void this.buildConnectConfig().then((cfg) => {
        client.connect(cfg);
      }).catch(reject);
    });
  }

  private async buildConnectConfig() {
    const privateKey = this.config.privateKeyPath
      ? await readFile(this.config.privateKeyPath, "utf8")
      : undefined;

    return {
      host: this.config.host,
      port: this.config.port,
      username: this.config.username,
      password: this.config.password,
      privateKey,
      passphrase: this.config.passphrase,
      keepaliveInterval: 10_000,
      readyTimeout: this.config.readyTimeoutMs
    };
  }

  async createLocalPortForward(
    remoteHost: string,
    remotePort: number
  ): Promise<{ localPort: number; close: () => void }> {
    const ssh = await this.connectedClient();

    return new Promise((resolve, reject) => {
      const server: Server = createServer((localSocket) => {
        ssh.forwardOut(
          localSocket.remoteAddress || "127.0.0.1",
          localSocket.remotePort || 0,
          remoteHost,
          remotePort,
          (err, remoteStream) => {
            if (err) {
              localSocket.destroy();
              return;
            }
            remoteStream.on("error", () => {
              try {
                localSocket.destroy();
              } catch {
                /* ignore */
              }
            });
            localSocket.on("error", () => {
              try {
                remoteStream.destroy();
              } catch {
                /* ignore */
              }
            });
            localSocket.pipe(remoteStream);
            remoteStream.pipe(localSocket);
          }
        );
      });

      server.listen(0, "127.0.0.1", () => {
        const address = server.address();
        if (address && typeof address === "object") {
          resolve({
            localPort: address.port,
            close: () => server.close()
          });
        } else {
          server.close();
          reject(new Error("Failed to get local port"));
        }
      });

      server.on("error", (err) => {
        reject(err);
      });
    });
  }

  async close(): Promise<void> {
    if (this.client) {
      this.client.end();
      this.client = undefined;
    }
  }
}
