/** Finite trusted prelaunch controller; every product/probe child applies its first OS boundary. */
import assert from "node:assert/strict";
import { afterEach, test } from "bun:test";
import { Database } from "bun:sqlite";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { serialize } from "node:v8";
import { testNetworkArgv } from "../scripts/test-network.ts";

const SOURCE_SHA = "b".repeat(40);
const SENTINEL = "PRIVATE_CAPTURE_SENTINEL_NOT_STDOUT";
const ROOT = fileURLToPath(new URL("../", import.meta.url));
const OPERATOR = fileURLToPath(new URL("../tools/cloudflare/private-bun-copy.ts", import.meta.url));
const owned: string[] = [];
afterEach(() => {
  for (const path of owned.splice(0)) rmSync(path, { recursive: true, force: true });
});

function systemPythonRole(): string[] {
  const environment = { PATH: "/usr/bin:/bin" };
  const inspect = (argv: string[]): string => {
    const result = spawnSync(argv[0], argv.slice(1), { env: environment, encoding: "utf8", timeout: 10_000 });
    assert.equal(result.status, 0, "Fixed Python role metadata verification failed");
    return result.stdout + result.stderr;
  };
  const selected = inspect(["/usr/bin/xcrun", "--find", "python3"]).trim();
  assert(isAbsolute(selected) && !selected.includes("\n"));
  const canonical = realpathSync(selected);
  const identity: unknown = JSON.parse(
    inspect([
      "/usr/bin/python3",
      "-I",
      "-S",
      "-B",
      "-c",
      String.raw`
import ctypes, json, os, sys
buffer = ctypes.create_string_buffer(4096)
length = ctypes.CDLL("/usr/lib/libproc.dylib").proc_pidpath(os.getpid(), buffer, len(buffer))
if length <= 0:
    raise RuntimeError("Python executable identity unavailable")
print(json.dumps({"selected":sys.executable,"base":sys._base_executable,"terminal":os.fsdecode(buffer.value)}))
`,
    ])
  );
  assert(typeof identity === "object" && identity !== null && "selected" in identity && "base" in identity && "terminal" in identity);
  assert.equal(identity.selected, selected);
  assert.equal(identity.base, selected);
  assert(typeof identity.terminal === "string");
  const terminal = identity.terminal;
  assert(canonical.includes("/Library/Frameworks/Python3.framework/Versions/"));
  assert.equal(terminal, join(dirname(dirname(canonical)), "Resources/Python.app/Contents/MacOS/Python"));
  assert.equal(realpathSync(terminal), terminal);
  const roles = ["/usr/bin/python3", canonical, terminal];
  const facts = roles.map((path, index) => {
    const info = lstatSync(path);
    assert(info.isFile() && !info.isSymbolicLink() && info.uid === 0 && (info.mode & 0o777) === 0o755);
    inspect(["/usr/bin/codesign", "--verify", "--strict", path]);
    const identity = inspect(["/usr/bin/codesign", "--display", "--verbose=4", "-r-", path]);
    const expected = index === 0 ? "com.apple.dt.xcode_select.tool-shim-public" : "com.apple.python3";
    assert(identity.includes('identifier "' + expected + '" and anchor apple'));
    return { path, bytes: info.size, sha256: createHash("sha256").update(readFileSync(path)).digest("hex"), designated_identity: expected };
  });
  assert.equal(realpathSync(inspect(["/usr/bin/xcrun", "--find", "python3"]).trim()), canonical);
  console.log(JSON.stringify({ kind: "verified_private_copy_python_role", selected, canonical, terminal, files: facts }));
  return roles;
}

let pythonRole: string[] | undefined;

function fixture() {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), "uos-private-confinement-")));
  chmodSync(directory, 0o700);
  owned.push(directory);
  const source = join(directory, "source.sqlite3");
  const database = new Database(source, { create: true, strict: true, safeIntegers: true });
  // Closed synthetic schema3 fixture; deliberately no product module import.
  for (const ddl of [
    "CREATE TABLE data_version (k INTEGER PRIMARY KEY, version INTEGER NOT NULL, seq INTEGER NOT NULL DEFAULT 0)",
    "CREATE TABLE kv (k BLOB PRIMARY KEY, v BLOB NOT NULL, v_encoding INTEGER NOT NULL, version INTEGER NOT NULL, seq INTEGER NOT NULL DEFAULT 0, expiration_ms INTEGER NOT NULL DEFAULT -1) WITHOUT ROWID",
    "CREATE INDEX kv_expiration_ms_idx ON kv (expiration_ms)",
    "CREATE TABLE migration_state (k INTEGER NOT NULL PRIMARY KEY, version INTEGER NOT NULL)",
    "CREATE TABLE queue (ts INTEGER NOT NULL, id TEXT NOT NULL, data BLOB NOT NULL, backoff_schedule TEXT NOT NULL, keys_if_undelivered BLOB NOT NULL, PRIMARY KEY (ts, id))",
    "CREATE TABLE queue_running (deadline INTEGER NOT NULL, id TEXT NOT NULL, data BLOB NOT NULL, backoff_schedule TEXT NOT NULL, keys_if_undelivered BLOB NOT NULL, PRIMARY KEY (deadline, id))",
    "CREATE TABLE uos_kv_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID",
  ])
    database.run(ddl);
  database.run("INSERT INTO uos_kv_metadata VALUES('codec','bun-jsc-v1')");
  database.run("INSERT INTO migration_state VALUES(0,3)");
  database.run("INSERT INTO data_version VALUES(0,10,0)");
  const rawKey = new Uint8Array([2, ...Buffer.from("default"), 0, 2, ...Buffer.from("confinement"), 0]);
  database.run("INSERT INTO kv VALUES(?,?,?,?,?,?)", [rawKey, serialize({ text: SENTINEL }), 1n, 9n, 0n, -1n]);
  database.close(true);
  chmodSync(source, 0o600);
  return { directory, input: { v: 1, source, directory: join(directory, "run"), source_git_sha: SOURCE_SHA } };
}

type ChildResult = Readonly<{ code: number; stdout: string; stderr: string }>;
async function runChild(argv: readonly string[], input: unknown): Promise<ChildResult> {
  const child = Bun.spawn([...argv], {
    cwd: ROOT,
    env: { PATH: "/usr/bin:/bin", BUN_RUNTIME_TRANSPILER_CACHE_PATH: "0" },
    stdin: "pipe",
    stdout: "pipe",
    stderr: "pipe",
  });
  await child.stdin.write(JSON.stringify(input));
  await child.stdin.end();
  const [stdout, stderr, code] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
  return { code, stdout, stderr };
}

function confined(child: readonly string[], output: string, forbidden: string): string[] {
  assert.equal(process.platform, "darwin", "These operator containment cases require actual Darwin Seatbelt");
  const argv = testNetworkArgv(child);
  const encoded: unknown = JSON.parse(argv[5] ?? "null");
  assert(Array.isArray(encoded) && encoded.every((item: unknown) => typeof item === "string"));
  const inner: string[] = encoded;
  assert.equal(inner[0], "/usr/bin/sandbox-exec");
  assert.equal(inner[1], "-p");
  const profile = inner[2];
  assert(profile.includes("(deny network*)"));
  const removedClause = '(allow network-outbound (remote ip "localhost:*"))';
  assert.equal(profile.split(removedClause).length, 2, "The exact reviewed outbound clause must occur once");
  const stricterProfile = profile.replace(removedClause, "");
  const literal = (path: string): string => "(literal " + JSON.stringify(path) + ")";
  const subpath = (path: string): string => "(subpath " + JSON.stringify(path) + ")";
  pythonRole ??= systemPythonRole();
  inner[2] =
    stricterProfile +
    "\n(deny network-outbound)\n(deny file-write*)\n(allow file-write* " +
    subpath(output) +
    ")" +
    "\n(deny file-read* " +
    subpath(forbidden) +
    ")" +
    "\n(deny process-exec)\n(allow process-exec " +
    literal(realpathSync(process.execPath)) +
    " " +
    pythonRole.map(literal).join(" ") +
    ")";
  console.log(
    JSON.stringify({
      kind: "private_copy_stricter_profile",
      original_profile: profile,
      final_profile: inner[2],
      original_sha256: createHash("sha256").update(profile).digest("hex"),
      final_sha256: createHash("sha256").update(inner[2]).digest("hex"),
      removed_exact_clause: removedClause,
    })
  );
  return [...argv.slice(0, 5), JSON.stringify(inner)];
}

test("private stdin CLI publishes only success metadata under inherited Python write/read/process confinement", async () => {
  const f = fixture();
  try {
    const forbidden = join(f.directory, "forbidden");
    mkdirSync(forbidden, { mode: 0o700 });
    writeFileSync(join(forbidden, "auth.json"), SENTINEL, { mode: 0o600 });
    const command = [process.execPath, "--no-env-file", "--no-install", OPERATOR];
    const argv = confined(command, f.input.directory, forbidden);
    const result = await runChild(argv, f.input);
    assert.equal(result.code, 0, result.stderr);
    assert.equal(result.stderr, "");
    assert.equal(result.stdout.includes(SENTINEL), false);
    assert.equal(result.stdout.includes('"entries":['), false);
    const metadata: unknown = JSON.parse(result.stdout);
    assert(typeof metadata === "object" && metadata !== null && "kind" in metadata);
    assert.equal(metadata.kind, "private_bun_copy_capture");
    assert.equal(readFileSync(join(forbidden, "auth.json"), "utf8"), SENTINEL);
    const failed = await runChild(testNetworkArgv(command), { ...f.input, unexpected: SENTINEL });
    assert.equal(failed.code, 78);
    assert.equal(failed.stdout, "");
    assert.equal(failed.stderr.includes(SENTINEL), false);
  } finally {
    rmSync(f.directory, { recursive: true, force: true });
  }
});

test("actual Python descendants cannot write/read forbidden fixtures or exec another role inside the operator boundary", async () => {
  const f = fixture();
  try {
    mkdirSync(f.input.directory, { mode: 0o700 });
    const forbidden = join(f.directory, "forbidden");
    mkdirSync(forbidden, { mode: 0o700 });
    const hidden = join(forbidden, "auth.json");
    writeFileSync(hidden, SENTINEL, { mode: 0o600 });
    const program = String.raw`
import json, os, pathlib, sys
value = json.load(sys.stdin)
def denied(operation):
    try:
        operation()
    except PermissionError:
        return True
    return False
assert denied(lambda: pathlib.Path(value["hidden"]).read_bytes())
assert denied(lambda: pathlib.Path(value["outside"]).write_text("forbidden"))
assert denied(lambda: os.execv("/bin/sh", ["/bin/sh", "-c", "exit 99"]))
pathlib.Path(value["inside"]).write_text("allowed")
print("PYTHON_BOUNDARY_CONFIRMED")
`;
    const command = ["/usr/bin/python3", "-I", "-S", "-B", "-c", program];
    const result = await runChild(confined(command, f.input.directory, forbidden), {
      hidden,
      outside: join(forbidden, "new"),
      inside: join(f.input.directory, "allowed"),
    });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(result.stdout.trim(), "PYTHON_BOUNDARY_CONFIRMED");
    assert.equal(existsSync(join(forbidden, "new")), false);
    assert.equal(readFileSync(join(f.input.directory, "allowed"), "utf8"), "allowed");
  } finally {
    rmSync(f.directory, { recursive: true, force: true });
  }
});

test("actual Python outbound denial has matching outside-operator-boundary positive probes", async () => {
  const f = fixture();
  // The outer repository fixture boundary permits loopback. The stricter
  // operator boundary denies all outbound sockets, including this fixture.
  const { createServer } = await import("node:net");
  const address = "127.0.0.1";
  const server = createServer((socket) => socket.end());
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, address, resolve);
  });
  try {
    const bound = server.address();
    assert(bound && typeof bound === "object");
    const program = String.raw`
import errno, json, socket, sys
value = json.load(sys.stdin)
print("PYTHON_STARTED", flush=True)
try:
    connection = socket.create_connection((value["host"], value["port"]), 2)
except PermissionError as error:
    if error.errno != errno.EPERM:
        raise
    print("PYTHON_OUTBOUND_DENIED", flush=True)
    sys.exit(77)
connection.close()
print("CONNECTED", flush=True)
`;
    const command = ["/usr/bin/python3", "-I", "-S", "-B", "-c", program];
    const input = { host: address, port: bound.port };
    const before = await runChild(testNetworkArgv(command), input);
    assert.equal(before.code, 0, before.stderr);
    assert.equal(before.stdout, "PYTHON_STARTED\nCONNECTED\n");
    assert.equal(before.stderr, "");
    const forbidden = join(f.directory, "forbidden");
    mkdirSync(forbidden, { mode: 0o700 });
    const inside = await runChild(confined(command, f.input.directory, forbidden), input);
    assert.equal(inside.code, 77, inside.stderr);
    assert.equal(inside.stdout, "PYTHON_STARTED\nPYTHON_OUTBOUND_DENIED\n");
    assert.equal(inside.stderr, "");
    const after = await runChild(testNetworkArgv(command), input);
    assert.equal(after.code, 0, after.stderr);
    assert.equal(after.stdout, "PYTHON_STARTED\nCONNECTED\n");
    assert.equal(after.stderr, "");
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => {
        if (error) reject(error);
        else resolve();
      });
    });
    rmSync(f.directory, { recursive: true, force: true });
  }
});
