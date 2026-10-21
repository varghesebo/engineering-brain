import dgram from "node:dgram";
import dns from "node:dns";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";

/**
 * TEST INSTRUMENT, NOT A SECURITY BOUNDARY. Records and blocks network use from JavaScript in this
 * process by patching Node built-ins. It cannot see native addons, child processes, or code that captured
 * the original functions earlier. It supports guarantee 1 (our own code makes no outbound calls) only.
 */
export interface NetworkAttempt {
  api: string;
  detail: string;
}

export interface NetworkGuard {
  readonly attempts: NetworkAttempt[];
  uninstall(): void;
}

type AnyFn = (...args: never[]) => unknown;

export function installNetworkGuard(): NetworkGuard {
  const attempts: NetworkAttempt[] = [];
  const restorers: Array<() => void> = [];

  const patch = (target: object, key: string, api: string): void => {
    const record = target as Record<string, unknown>;
    const original = record[key];
    if (typeof original !== "function") {
      return;
    }
    record[key] = function guarded(...args: unknown[]): never {
      attempts.push({ api, detail: String(args[0] ?? "").slice(0, 80) });
      throw new Error(`network access blocked by test guard: ${api}`);
    } as AnyFn;
    restorers.push(() => {
      record[key] = original;
    });
  };

  patch(net.Socket.prototype, "connect", "net.Socket.connect");
  patch(net, "connect", "net.connect");
  patch(net, "createConnection", "net.createConnection");
  patch(tls, "connect", "tls.connect");
  patch(dns, "lookup", "dns.lookup");
  patch(dns, "resolve", "dns.resolve");
  patch(dns.promises, "lookup", "dns.promises.lookup");
  patch(http, "request", "http.request");
  patch(http, "get", "http.get");
  patch(https, "request", "https.request");
  patch(https, "get", "https.get");
  patch(dgram.Socket.prototype, "send", "dgram.send");
  patch(globalThis, "fetch", "fetch");

  return {
    attempts,
    uninstall(): void {
      for (const restore of restorers.splice(0).reverse()) {
        restore();
      }
    }
  };
}
