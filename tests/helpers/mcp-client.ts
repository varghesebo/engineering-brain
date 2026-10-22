import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { fileURLToPath } from "node:url";

const BIN = fileURLToPath(new URL("../../packages/cli/dist/bin.js", import.meta.url));

export interface RpcReply { jsonrpc: string; id: number | null; result?: any; error?: { code: number; message: string } }

/** A real child-process MCP client speaking newline-delimited JSON-RPC to `engbrain mcp` (no SDK, no mocks). */
export class McpClient {
  private readonly child: ChildProcessWithoutNullStreams;
  private buffer = "";
  private nextId = 1;
  private readonly waiting = new Map<number, (r: RpcReply) => void>();
  readonly stdoutLines: string[] = [];
  stderr = "";
  exited: Promise<number | null>;

  constructor(root: string, home: string, extraArgs: string[] = []) {
    this.child = spawn(process.execPath, [BIN, "mcp", "--root", root, ...extraArgs], { env: { ...process.env, ENGBRAIN_HOME: home }, stdio: ["pipe", "pipe", "pipe"] });
    this.child.stdout.setEncoding("utf8");
    this.child.stdout.on("data", (chunk: string) => {
      this.buffer += chunk;
      for (let i = this.buffer.indexOf("\n"); i !== -1; i = this.buffer.indexOf("\n")) {
        const line = this.buffer.slice(0, i);
        this.buffer = this.buffer.slice(i + 1);
        this.stdoutLines.push(line);
        const reply = JSON.parse(line) as RpcReply; // any non-JSON on stdout would throw here: stdout must be protocol only
        this.waiting.get(reply.id as number)?.(reply);
      }
    });
    this.child.stderr.setEncoding("utf8");
    this.child.stderr.on("data", (c: string) => void (this.stderr += c));
    this.exited = new Promise((resolve) => this.child.on("close", resolve));
  }

  request(method: string, params?: unknown): Promise<RpcReply> {
    const id = this.nextId++;
    return new Promise((resolve) => {
      this.waiting.set(id, resolve);
      this.child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, ...(params === undefined ? {} : { params }) })}\n`);
    });
  }

  notify(method: string, params?: unknown): void {
    this.child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method, ...(params === undefined ? {} : { params }) })}\n`);
  }

  sendRaw(text: string): void {
    this.child.stdin.write(text);
  }

  async initialize(version = "2025-06-18"): Promise<RpcReply> {
    const reply = await this.request("initialize", { protocolVersion: version, capabilities: {}, clientInfo: { name: "test", version: "0" } });
    this.notify("notifications/initialized");
    return reply;
  }

  /** Calls a tool and returns the parsed JSON payload plus the isError flag. */
  async tool(name: string, args: unknown = {}): Promise<{ payload: any; isError: boolean; raw: string }> {
    const reply = await this.request("tools/call", { name, arguments: args });
    const text = reply.result?.content?.[0]?.text as string | undefined;
    return { payload: text === undefined ? reply : JSON.parse(text), isError: reply.result?.isError === true, raw: text ?? JSON.stringify(reply) };
  }

  async close(): Promise<number | null> {
    this.child.stdin.end();
    return this.exited;
  }
}
