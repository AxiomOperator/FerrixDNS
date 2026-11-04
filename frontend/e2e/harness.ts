/** Runs the real `ferrixdns` binary against a scripted upstream, for end-to-end tests. */

import { type ChildProcess, spawn } from "node:child_process";
import dgram from "node:dgram";
import { mkdtempSync, rmSync } from "node:fs";
import http from "node:http";
import { type AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

export const RCODE = { NOERROR: 0, SERVFAIL: 2, NXDOMAIN: 3 };

function encodeName(name: string): Buffer {
  const parts: Buffer[] = [];
  for (const label of name.split(".")) {
    parts.push(Buffer.from([label.length]), Buffer.from(label, "ascii"));
  }
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}

/** Answers every A query with 192.0.2.1, and names starting with "alias." with a CNAME too. */
function startUpstream(): Promise<dgram.Socket> {
  const socket = dgram.createSocket("udp4");
  socket.on("message", (query, peer) => {
    let end = 12;
    const labels: string[] = [];
    while (query[end] !== 0 && end < query.length) {
      const length = query[end] ?? 0;
      labels.push(query.subarray(end + 1, end + 1 + length).toString("ascii"));
      end += length + 1;
    }
    const questionEnd = end + 5;
    const question = query.subarray(12, questionEnd);
    const isAlias = labels[0] === "alias";

    const records: Buffer[] = [];
    let owner: Buffer = Buffer.from([0xc0, 0x0c]);
    if (isAlias) {
      const target = encodeName("ads-target.example");
      const length = Buffer.alloc(2);
      length.writeUInt16BE(target.length);
      records.push(owner, Buffer.from([0, 5, 0, 1, 0, 0, 0, 60]), length, target);
      owner = target;
    }
    records.push(owner, Buffer.from([0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1]));

    const header = Buffer.alloc(12);
    query.copy(header, 0, 0, 2);
    header.writeUInt16BE(0x8180, 2);
    header.writeUInt16BE(1, 4);
    header.writeUInt16BE(isAlias ? 2 : 1, 6);
    socket.send(Buffer.concat([header, question, ...records]), peer.port, peer.address);
  });
  return new Promise((resolve) => socket.bind(0, "127.0.0.1", () => resolve(socket)));
}

function startListServer(lists: Map<string, string>): Promise<http.Server> {
  const server = http.createServer((request, response) => {
    const body = lists.get(request.url ?? "");
    if (body === undefined) {
      response.writeHead(404).end();
      return;
    }
    response.writeHead(200, { "Content-Type": "text/plain" }).end(body);
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

export interface Node {
  webUrl: string;
  dnsPort: number;
  listBaseUrl: string;
  lists: Map<string, string>;
  setupToken: string;
  /** Sends an A query and returns the response code. */
  rcode(name: string): Promise<number>;
  stop(): Promise<void>;
}

export async function startNode(): Promise<Node> {
  const stateDir = mkdtempSync(path.join(tmpdir(), "ferrix-e2e-"));
  const upstream = await startUpstream();
  const lists = new Map<string, string>();
  const listServer = await startListServer(lists);
  const upstreamPort = (upstream.address() as AddressInfo).port;

  const ferrixdns: ChildProcess = spawn(
    path.join(REPO_ROOT, "target/debug/ferrixdns"),
    [
      "serve",
      "--listen", "127.0.0.1:0",
      "--upstream", `127.0.0.1:${upstreamPort}`,
      "--state-dir", stateDir,
      "--web-listen", "127.0.0.1:0",
      "--allow-private-list-urls",
    ],
    { stdio: ["ignore", "ignore", "pipe"], env: { ...process.env, NO_COLOR: "1", RUST_LOG: "info,hickory_server=warn" } },
  );

  const startup = new Promise<{ dnsPort: number; webUrl: string; setupToken: string }>(
    (resolve, reject) => {
      let dnsPort: number | undefined;
      let webUrl: string | undefined;
      let setupToken: string | undefined;
      ferrixdns.once("exit", (code) => reject(new Error(`ferrixdns exited early with code ${code}`)));
      if (!ferrixdns.stderr) throw new Error("ferrixdns has no stderr");
      createInterface({ input: ferrixdns.stderr }).on("line", (line) => {
        dnsPort ??= Number(/listening for DNS.* address=[\d.]+:(\d+)/.exec(line)?.[1]) || undefined;
        webUrl ??= /url=(http:\S+)/.exec(line)?.[1];
        setupToken ??= /setup_token=([0-9a-f]+)/.exec(line)?.[1];
        if (dnsPort && webUrl && setupToken) resolve({ dnsPort, webUrl, setupToken });
      });
    },
  );
  const { dnsPort, webUrl, setupToken } = await startup;
  ferrixdns.removeAllListeners("exit");

  return {
    webUrl,
    dnsPort,
    lists,
    setupToken,
    listBaseUrl: `http://127.0.0.1:${(listServer.address() as AddressInfo).port}`,
    rcode(name) {
      return new Promise((resolve, reject) => {
        const socket = dgram.createSocket("udp4");
        const header = Buffer.from([0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        const packet = Buffer.concat([header, encodeName(name), Buffer.from([0, 1, 0, 1])]);
        const timer = setTimeout(() => {
          socket.close();
          reject(new Error(`no DNS answer for ${name}`));
        }, 5000);
        socket.on("message", (reply) => {
          clearTimeout(timer);
          socket.close();
          resolve((reply[3] ?? 0) & 0x0f);
        });
        socket.send(packet, dnsPort, "127.0.0.1");
      });
    },
    async stop() {
      ferrixdns.kill("SIGTERM");
      upstream.close();
      listServer.close();
      await new Promise((resolve) => setTimeout(resolve, 200));
      rmSync(stateDir, { recursive: true, force: true });
    },
  };
}
