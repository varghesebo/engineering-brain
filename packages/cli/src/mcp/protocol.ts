import type { Readable } from "node:stream";

/** JSON-RPC 2.0 over newline-delimited stdio (the MCP stdio transport). stdout carries protocol messages ONLY. */
export const MAX_MESSAGE_BYTES = 1_048_576;

export interface JsonRpcRequest { jsonrpc: "2.0"; id?: string | number | null; method: string; params?: unknown }

export const RPC_ERROR = { parse: -32700, invalidRequest: -32600, methodNotFound: -32601, invalidParams: -32602, internal: -32603, notInitialized: -32002 } as const;

export const rpcResult = (id: string | number | null, result: unknown): string => `${JSON.stringify({ jsonrpc: "2.0", id, result })}\n`;
export const rpcError = (id: string | number | null, code: number, message: string): string => `${JSON.stringify({ jsonrpc: "2.0", id, error: { code, message } })}\n`;

/**
 * Splits a stream into lines, enforcing a hard per-message size: an oversized message is reported once (`onOversize`) and discarded up to its newline,
 * so a hostile or buggy client cannot make the server buffer without bound.
 */
export async function readLines(input: Readable, onLine: (line: string) => Promise<void>, onOversize: () => void): Promise<void> {
  let buffered = "";
  let discarding = false;
  input.setEncoding("utf8");
  for await (const chunk of input as AsyncIterable<string>) {
    let rest = chunk;
    for (;;) {
      const newline = rest.indexOf("\n");
      const piece = newline === -1 ? rest : rest.slice(0, newline);
      if (!discarding) {
        buffered += piece;
        if (Buffer.byteLength(buffered, "utf8") > MAX_MESSAGE_BYTES) {
          discarding = true;
          buffered = "";
          onOversize();
        }
      }
      if (newline === -1) {
        break;
      }
      if (!discarding && buffered.trim() !== "") {
        const line = buffered;
        buffered = "";
        await onLine(line);
      }
      discarding = false;
      buffered = "";
      rest = rest.slice(newline + 1);
    }
  }
  if (!discarding && buffered.trim() !== "") {
    await onLine(buffered);
  }
}
