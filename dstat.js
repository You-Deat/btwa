const { spawn, exec, execSync } = require("child_process");
const http = require("http");
const axios = require("axios");
const crypto = require("crypto");
const winston = require("winston");
const WebSocket = require("ws");
const Redis = require("ioredis");
const client = require("prom-client");
const { CIDR } = require("ip-cidr");
const NodeCache = require("node-cache");
const { Worker } = require("worker_threads");
const maxmind = require("maxmind");
const fs = require("fs").promises;
const path = require("path");
const os = require("os");

function detectEnvironment() {
  if (process.env.TERMUX_VERSION || process.env.PREFIX === "/data/data/com.termux/files/usr") return "termux";
  if (process.env.CLOUD_SHELL === "true" || process.env.GOOGLE_CLOUD_PROJECT) return "cloudshell";
  return "other";
}
const ENV = detectEnvironment();
const IS_TERMUX = ENV === "termux";
const IS_CLOUD_SHELL = ENV === "cloudshell";

const SILENT_CONSOLE = true;
const LOG_DIR = "./logs";
(async () => { try { await fs.mkdir(LOG_DIR, { recursive: true }); } catch(e) {} })();

const logger = winston.createLogger({
  level: "info",
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: path.join(LOG_DIR, "error.log"), level: "error" }),
    new winston.transports.File({ filename: path.join(LOG_DIR, "combined.log") }),
  ],
});
if (!SILENT_CONSOLE) logger.add(new winston.transports.Console({ format: winston.format.simple() }));

const CONFIG = {
  BIND_ADDR: process.env.BIND_ADDR || (IS_TERMUX ? "0.0.0.0" : "127.0.0.1"),
  HTTP_PORT: parseInt(process.env.HTTP_PORT) || 9090,
  METRICS_PORT: parseInt(process.env.METRICS_PORT) || 9091,
  REDIS_MODE: process.env.REDIS_MODE || (IS_TERMUX ? "single" : "memory"),
  REDIS_SINGLE_HOST: process.env.REDIS_SINGLE_HOST || "127.0.0.1",
  REDIS_SINGLE_PORT: parseInt(process.env.REDIS_SINGLE_PORT) || 6379,
  REDIS_PASSWORD: process.env.REDIS_PASSWORD || "",
  REDIS_CLUSTER_NODES: process.env.REDIS_CLUSTER_NODES ? JSON.parse(process.env.REDIS_CLUSTER_NODES) : [
    { host: "127.0.0.1", port: 7000 }, { host: "127.0.0.1", port: 7001 },
    { host: "127.0.0.1", port: 7002 }, { host: "127.0.0.1", port: 7003 },
    { host: "127.0.0.1", port: 7004 }, { host: "127.0.0.1", port: 7005 }
  ],
  GLOBAL_RPS_LIMIT: 30,
  BASE_PER_IP_LIMIT: 5,
  RATE_LIMIT_WINDOW_SEC: 5,
  CHALLENGE_DIFFICULTY: 6,
  CHALLENGE_SECRET: process.env.CHALLENGE_SECRET || "dizflyze-seccurity-system",
  SESSION_TOKEN_TTL_SEC: 300,
  CHALLENGE_POW_TIMEOUT: 15000,
  MAX_CHALLENGE_FAILS: 5,
  WORKER_POOL_SIZE: parseInt(process.env.WORKER_POOL_SIZE) || Math.max(1, os.cpus().length - 1),
  WS_MAX_CONNECTIONS_PER_IP: 2,
  WS_MESSAGE_RATE_LIMIT: 5,
  WS_PING_INTERVAL: 30000,
  MAX_CONCURRENT_CONNECTIONS_PER_IP: 10,
  WHITELIST_IPS: new Set((process.env.WHITELIST_IPS || "127.0.0.1").split(",").map(s=>s.trim())),
  HONEYPOT_PATHS: ["/admin-panel", "/wp-login.php", "/.env", "/config.php", "/backup.zip"],
  ENABLE_GEO: !IS_CLOUD_SHELL && process.env.ENABLE_GEO !== "false",
  ENABLE_ASN_BLOCK: !IS_CLOUD_SHELL && process.env.ENABLE_ASN_BLOCK !== "false",
  GEO_ANOMALY_SCORE: 10,
  BLOCKED_ASN: new Set((process.env.BLOCKED_ASN || "16509,15169,20473,14061,24940,16276,13335").split(",").map(Number)),
  AUTO_SCALE: !IS_CLOUD_SHELL,
  DIFFICULTY_BASE: 6,
  DIFFICULTY_MAX: 12,
  HIGH_RPS_THRESHOLD: 2000,
  SLOWLORIS_TIMEOUT_MS: 5000,
  MAX_URL_LENGTH: 2048,
  MAX_HEADER_SIZE: 8192,
  GRAPHQL_DEPTH_LIMIT: 10,
  ALLOWED_ORIGINS: (process.env.ALLOWED_ORIGINS || "").split(",").filter(Boolean),
  BEHAVIOR_SCORE_BAN_THRESHOLD: 30,
  BAN_DURATIONS: [120, 300, 600, 1800, 3600, 7200],
  CACHE_TTL_MS: 60000,
  DSTAT_DURATION_MS: 200000,
  PREPARE_DURATION_MS: 60000,
  COOLDOWN_DURATION_MS: 60000,
  WS_PAYLOAD_LIMIT: 65536,
  RATE_LIMIT_PATHS: { "/login": 3, "/api": 5, "/": 20 },
  CHALLENGE_TTL_SEC: 30,
  MULTIPART_MAX_PARTS: 100,
  MULTIPART_MAX_SIZE: 2097152,
};

const SUSPICIOUS_UA_PATTERNS = [/^(python|curl|wget|go-http|zgrab|masscan|nikto|sqlmap|scanner|httpx|katana)/i];

let redisClient = null;
let isRedisReady = false;
let redisFailTimer = null;
let redisFailCount = 0;
const memoryCache = new NodeCache({ stdTTL: 60, checkperiod: 120, maxKeys: 5000 });
const regexResultCache = new NodeCache({ stdTTL: 60, maxKeys: 5000 });

async function initRedis() {
  if (CONFIG.REDIS_MODE === "memory") {
    console.log("[ REDIS ] MODE MEMORY");
    isRedisReady = false;
    return null;
  }

  try {
    if (CONFIG.REDIS_MODE === "single") {
      redisClient = new Redis({
        host: CONFIG.REDIS_SINGLE_HOST,
        port: CONFIG.REDIS_SINGLE_PORT,
        password: CONFIG.REDIS_PASSWORD || undefined,
        retryStrategy: (times) => Math.min(times * 100, 3000),
        maxRetriesPerRequest: 3,
      });
    } else {
      redisClient = new Redis.Cluster(
        CONFIG.REDIS_CLUSTER_NODES,
        {
          scaleReads: "slave",
          redisOptions: {
            password: CONFIG.REDIS_PASSWORD || undefined,
            retryStrategy: (times) => Math.min(times * 100, 3000),
          },
          clusterRetryStrategy: (times) =>
            Math.min(times * 100, 3000),
          maxRedirections: 16,
        }
      );
    }

    await redisClient.ping();

    console.log(
      `[ REDIS ] MODE ${CONFIG.REDIS_MODE.toUpperCase()}`
    );

    isRedisReady = true;

    redisClient.on("error", (err) => {
      logger.error("Redis error:", err.message);
      isRedisReady = false;
    });

    redisClient.on("ready", () => {
      isRedisReady = true;
    });

    return redisClient;
  } catch (err) {
    logger.error(err.message);
    isRedisReady = false;
    return null;
  }
}

async function lazyRedisCheck() {
  if (isRedisReady) return true;
  if (redisFailTimer) return false;
  const delay = Math.min(1000 * Math.pow(2, redisFailCount), 30000);
  redisFailTimer = setTimeout(async () => {
    try { if (redisClient) await redisClient.ping(); isRedisReady = true; redisFailCount = 0; } catch (e) { redisFailCount++; }
    finally { redisFailTimer = null; }
  }, delay);
  return false;
}
async function cacheGet(key) {
  if (isRedisReady && (await lazyRedisCheck())) { try { const v = await redisClient.get(key); if (v !== null) return v; } catch(e){ isRedisReady=false; } }
  return memoryCache.get(key);
}
async function cacheSet(key, value, ttlSeconds) {
  if (isRedisReady && (await lazyRedisCheck())) { try { await redisClient.setex(key, ttlSeconds, value); return; } catch(e){ isRedisReady=false; } }
  memoryCache.set(key, value, ttlSeconds);
}
async function cacheDel(key) {
  if (isRedisReady && (await lazyRedisCheck())) { try { await redisClient.del(key); } catch(e){ isRedisReady=false; } }
  memoryCache.del(key);
}

client.collectDefaultMetrics({ timeout: 5000 });
const httpRequestsTotal = new client.Counter({ name: "http_requests_total", help: "Total HTTP requests" });
const httpBlockedTotal = new client.Counter({ name: "http_blocked_total", help: "Total blocked requests" });
const wsConnectionsGauge = new client.Gauge({ name: "ws_connections", help: "Active WebSocket connections" });
const metricsServer = http.createServer(async (req, res) => {
  if (req.url === "/metrics") {
    const auth = req.headers.authorization || "";
    const expected = "Basic " + Buffer.from(process.env.METRICS_USER + ":" + process.env.METRICS_PASS).toString("base64");
    if (auth !== expected) { res.writeHead(401); res.end(); return; }
    res.writeHead(200, { "Content-Type": client.register.contentType });
    res.end(await client.register.metrics());
  } else res.writeHead(404).end();
});
metricsServer.listen(CONFIG.METRICS_PORT, "127.0.0.1", () => logger.info(`Metrics on :${CONFIG.METRICS_PORT}`));

class CircularBuffer {
  constructor(maxSize) { this.maxSize = maxSize; this.buffer = new Array(maxSize); this.index = 0; this.full = false; }
  push(value) { this.buffer[this.index] = value; this.index = (this.index + 1) % this.maxSize; if (this.index === 0) this.full = true; }
  getAll() { if (!this.full) return this.buffer.slice(0, this.index); return [...this.buffer.slice(this.index), ...this.buffer.slice(0, this.index)]; }
}
class LimitedMap extends Map {
  constructor(maxSize = 10000) { super(); this.maxSize = maxSize; }
  set(key, value) { if (this.size >= this.maxSize && !this.has(key)) { const firstKey = this.keys().next().value; this.delete(firstKey); } return super.set(key, value); }
}
function getTopN(map, n=3) { return Array.from(map.entries()).sort((a,b)=>b[1]-a[1]).slice(0,n).map(([k])=>k).join(" + "); }
function formatDuration(seconds) { const mins = Math.floor(seconds/60); const secs = seconds%60; return `${mins.toString().padStart(2,"0")}:${secs.toString().padStart(2,"0")}`; }
function safeDecode(str) { if (!str) return ""; try { return decodeURIComponent(str); } catch { return str; } }
function normalizeForRegex(str) { return str.replace(/\s+/g," ").replace(/\/\*.*?\*\//g,"").replace(/--.*$/gm,"").replace(/;/g,"").toLowerCase(); }
function readBody(req, maxBytes=1048576) { return new Promise((resolve,reject)=>{ let body=""; req.on("data",chunk=>{ if(Buffer.byteLength(body)+chunk.length>maxBytes){ req.destroy(); reject(new Error("Body too large")); return; } body+=chunk.toString(); }); req.on("end",()=>resolve(body)); req.on("error",reject); }); }

const WORKER_FILE = path.join(__dirname, "worker_detector.js");
const workerCode = `
const { parentPort } = require("worker_threads");
const REGEX = {
  SQLi: /select[\\s\\S]*?from|insert[\\s\\S]*?into|delete[\\s\\S]*?from|drop[\\s\\S]*?table|' or '1'='1|sleep\\(|benchmark\\(|information_schema|--\\s*$|;\\s*--|\\|\\|.*?(?:or|and).*?=.*?=/i,
  XSS: /<script|javascript:|onerror=|onload=|alert\\(|prompt\\(|confirm\\(|<img.*?src=|onmouseover=|onclick=|onkeyup=|eval\\(|expression\\(/i,
  PathTraversal: /\\.\\.\\/|\\.\\.\\\\|%2e%2e%2f|%2e%2e%5c|\\.\\.%2f|\\.\\.%5c/i,
  CmdInjection: /;\\s*(rm|curl|wget|bash|sh|nc|nslookup|ping|python|perl|ruby)|\\|\\s*(sh|bash|nc|nslookup|ping)/i,
  SensitiveFile: /\\/etc\\/|\\/proc\\/|\\/\\.env|\\/wp-config|\\/config\\.php|\\/\\.git\\/|\\/\\.aws\\/|\\/\\.ssh\\/|\\/\\.bash_history/i,
  Scanner: /sqlmap|nmap|nikto|burp|dirbuster|gobuster|wpscan|masscan|zgrab|python-requests|curl|wget|scanner|httpx|katana/i,
};
parentPort.on("message", ({ id, full }) => {
  const attacks = [];
  for (const [type, regex] of Object.entries(REGEX)) { if (regex.test(full)) attacks.push(type); }
  parentPort.postMessage({ id, attacks });
});
`;
(async () => { try { await fs.access(WORKER_FILE); } catch { await fs.writeFile(WORKER_FILE, workerCode); } })();
function createWorkerPool(size = CONFIG.WORKER_POOL_SIZE) {
  const workers = []; const queue = []; const MAX_QUEUE = 500;
  for (let i=0;i<size;i++) {
    const worker = new Worker(WORKER_FILE);
    worker.on("message", (result) => { const task = worker._task; if (task && task.id === result.id) { task.resolve(result.attacks); worker._task = null; if (queue.length) runWorker(worker, queue.shift()); } });
    worker.on("error", (err) => { logger.error("Worker error", err); const task = worker._task; if (task) { task.resolve(["Suspicious"]); worker._task = null; } if (queue.length) { const freeWorker = workers.find(w => !w._task); if (freeWorker) runWorker(freeWorker, queue.shift()); } });
    workers.push(worker);
  }
  function runWorker(worker, task) { worker._task = task; worker.postMessage({ id: task.id, full: task.full }); }
  return function detectAttackInWorker(full) { return new Promise((resolve) => { if (queue.length > MAX_QUEUE) { resolve(["Suspicious"]); return; } const id = Math.random().toString(36).substr(2); const task = { id, full, resolve }; const freeWorker = workers.find(w => !w._task); if (freeWorker) runWorker(freeWorker, task); else queue.push(task); }); };
}
const detectWithWorker = createWorkerPool();

async function getBanDuration(violationCount, reason) {
  let idx = Math.min(violationCount, CONFIG.BAN_DURATIONS.length-1);
  let duration = CONFIG.BAN_DURATIONS[idx]*1000;
  if (reason.includes("attack")) duration *= 2;
  if (reason.includes("scanner") || reason.includes("honeypot")) duration *= 3;
  return Math.min(duration, 7*86400000);
}
async function banIp(ip, reason, score = 0, wsConns = null) {
  const banKey = `ban:${ip}`;
  let violations = 1;
  const existing = await cacheGet(banKey);
  if (existing) violations = JSON.parse(existing).level + 1;
  const duration = await getBanDuration(violations, reason);
  const banData = { until: Date.now()+duration, level: violations, reason, score };
  await cacheSet(banKey, JSON.stringify(banData), Math.ceil(duration/1000));
  await cacheDel(`rl:${ip}`); await cacheDel(`session:${ip}`); await cacheDel(`challenge_count:${ip}`);
  await updateReputation(ip, -30);
  if (wsConns && wsConns.has(ip)) { for (const ws of wsConns.get(ip)) try { ws.close(1008, "Banned"); } catch(e) {} wsConns.delete(ip); }
  httpBlockedTotal.inc();
}
async function isBanned(ip) {
  const ban = await cacheGet(`ban:${ip}`);
  if (ban) { const data = JSON.parse(ban); if (Date.now() < data.until) return data; await cacheDel(`ban:${ip}`); }
  return null;
}
async function updateReputation(ip, delta) {
  const key = `rep:${ip}`;
  let rep = 50;
  const val = await cacheGet(key);
  if (val) rep = parseInt(val);
  rep = Math.min(100, Math.max(0, rep + delta));
  await cacheSet(key, rep.toString(), 7200);
  return rep;
}
async function getEffectiveRateLimit(ip) {
  const rep = parseInt(await cacheGet(`rep:${ip}`) || "50");
  return Math.max(1, Math.floor(CONFIG.BASE_PER_IP_LIMIT * (rep/100)));
}
async function addBehaviorScore(ip, delta, trusted = false, wsConns = null) {
  if (trusted) delta = Math.floor(delta / 2);
  if (delta <= 0) return false;
  const key = `score:${ip}`;
  let current = 0;
  const val = await cacheGet(key);
  if (val) current = parseInt(val);
  const newScore = current + delta;
  await cacheSet(key, newScore.toString(), 3600);
  await updateReputation(ip, -Math.floor(delta/2));
  if (newScore >= CONFIG.BEHAVIOR_SCORE_BAN_THRESHOLD) { await banIp(ip, `behavior_score_${newScore}`, newScore, wsConns); await cacheDel(key); return true; }
  return false;
}
let globalRpsCounter = 0;
const globalRpsKey = "global_rps_counter";
async function checkGlobalRpsAtomic() {
  if (isRedisReady && (await lazyRedisCheck())) { try { const current = await redisClient.incr(globalRpsKey); if (current === 1) await redisClient.expire(globalRpsKey, 1); return current <= CONFIG.GLOBAL_RPS_LIMIT; } catch(e){ isRedisReady=false; } }
  globalRpsCounter++; return globalRpsCounter <= CONFIG.GLOBAL_RPS_LIMIT;
}
setInterval(() => { globalRpsCounter = 0; }, 1000);
const ipLocks = new Map();
async function withLock(ip, fn) {
  while (ipLocks.get(ip)) await new Promise(r => setTimeout(r, 5));
  ipLocks.set(ip, true);
  try { return await fn(); } finally { ipLocks.delete(ip); }
}
async function checkRateLimitAtomic(ip, path = null, trusted = false, wsConns = null) {
  const effectiveIpLimit = trusted ? await getEffectiveRateLimit(ip)*2 : await getEffectiveRateLimit(ip);
  if (!(await checkGlobalRpsAtomic())) return false;
  const windowSec = CONFIG.RATE_LIMIT_WINDOW_SEC;
  const nowSec = Math.floor(Date.now() / 1000);
  const ipKey = `rl:${ip}`;
  if (isRedisReady && (await lazyRedisCheck())) {
    try {
      const currentBucket = await redisClient.get(`${ipKey}:${nowSec}`);
      let current = currentBucket ? parseInt(currentBucket) : 0;
      if (current < effectiveIpLimit) {
        await redisClient.incr(`${ipKey}:${nowSec}`);
        await redisClient.expire(`${ipKey}:${nowSec}`, windowSec + 1);
        let total = current + 1;
        for (let i = 1; i <= windowSec; i++) { const pastVal = await redisClient.get(`${ipKey}:${nowSec - i}`); if (pastVal) total += parseInt(pastVal); }
        if (total > effectiveIpLimit) { await redisClient.decr(`${ipKey}:${nowSec}`); if (!trusted) await banIp(ip, "rate_limit", 0, wsConns); return false; }
      } else { if (!trusted) await banIp(ip, "rate_limit", 0, wsConns); return false; }
      if (path && CONFIG.RATE_LIMIT_PATHS[path]) {
        const pathKey = `rlpath:${ip}:${path}`;
        const pathNowSec = nowSec;
        const pathCurrentBucket = await redisClient.get(`${pathKey}:${pathNowSec}`);
        let pathCurrent = pathCurrentBucket ? parseInt(pathCurrentBucket) : 0;
        if (pathCurrent < CONFIG.RATE_LIMIT_PATHS[path]) { await redisClient.incr(`${pathKey}:${pathNowSec}`); await redisClient.expire(`${pathKey}:${pathNowSec}`, windowSec + 1); } else { if (!trusted) await banIp(ip, `path_rate_${path}`, 0, wsConns); return false; }
      }
      return true;
    } catch(e) { logger.error("Rate limit redis error", e); isRedisReady = false; }
  }
  return withLock(ip, async () => {
    const memBucket = await cacheGet(`${ipKey}:${nowSec}`);
    let memCurrent = memBucket ? parseInt(memBucket) : 0;
    if (memCurrent < effectiveIpLimit) {
      await cacheSet(`${ipKey}:${nowSec}`, (memCurrent+1).toString(), windowSec+1);
      let total = memCurrent + 1;
      for (let i = 1; i <= windowSec; i++) { const past = await cacheGet(`${ipKey}:${nowSec - i}`); if (past) total += parseInt(past); }
      if (total > effectiveIpLimit) { await cacheSet(`${ipKey}:${nowSec}`, memCurrent.toString(), windowSec+1); if (!trusted) await banIp(ip, "rate_limit_fallback", 0, wsConns); return false; }
    } else { if (!trusted) await banIp(ip, "rate_limit_fallback", 0, wsConns); return false; }
    if (path && CONFIG.RATE_LIMIT_PATHS[path]) {
      const pathKey = `rlpath:${ip}:${path}`;
      const pathNowSec = nowSec;
      const pathMemBucket = await cacheGet(`${pathKey}:${pathNowSec}`);
      let pathMemCurrent = pathMemBucket ? parseInt(pathMemBucket) : 0;
      if (pathMemCurrent < CONFIG.RATE_LIMIT_PATHS[path]) { await cacheSet(`${pathKey}:${pathNowSec}`, (pathMemCurrent+1).toString(), windowSec+1); } else { if (!trusted) await banIp(ip, `path_rate_fallback_${path}`, 0, wsConns); return false; }
    }
    return true;
  });
}
async function generateSessionToken(ip) {
  const rawToken = crypto.randomBytes(32).toString("hex");
  const signature = crypto.createHmac("sha256", CONFIG.CHALLENGE_SECRET).update(rawToken).digest("hex");
  const token = `${rawToken}.${signature}`;
  await cacheSet(`session:${rawToken}`, ip, CONFIG.SESSION_TOKEN_TTL_SEC);
  return token;
}
async function verifySessionToken(token, ip) {
  if (!token || !token.includes(".")) return false;
  const [rawToken, signature] = token.split(".");
  const expectedSig = crypto.createHmac("sha256", CONFIG.CHALLENGE_SECRET).update(rawToken).digest("hex");
  if (signature !== expectedSig) return false;
  const storedIp = await cacheGet(`session:${rawToken}`);
  if (storedIp === ip) { await cacheSet(`session:${rawToken}`, ip, CONFIG.SESSION_TOKEN_TTL_SEC); await updateReputation(ip, 1); return true; }
  return false;
}
async function isTrusted(req, ip) {
  if (CONFIG.WHITELIST_IPS.has(ip)) return true;
  const token = req.headers["x-security-token"] || (()=>{ const match = req.headers.cookie?.match(/__Secure-token=([^;]+)/); return match ? match[1] : null; })();
  if (token && (await verifySessionToken(token, ip))) return true;
  return false;
}
async function createPowChallenge(ip) {
  const challengeId = crypto.randomBytes(16).toString('hex');
  const prefix = crypto.randomBytes(16).toString('hex');
  await cacheSet(`pow:${challengeId}`, JSON.stringify({ prefix, ip, createdAt: Date.now() }), CONFIG.CHALLENGE_POW_TIMEOUT/1000);
  return { challengeId, prefix };
}
async function verifyProofOfWork(challengeId, nonce, hash) {
  const challengeData = await cacheGet(`pow:${challengeId}`);
  if (!challengeData) return false;
  const { prefix, ip } = JSON.parse(challengeData);
  const computedHash = crypto.createHash('sha256').update(prefix + nonce).digest('hex');
  if (computedHash !== hash) return false;
  const requiredLeadingZeros = Math.ceil(CONFIG.CHALLENGE_DIFFICULTY / 4);
  if (!hash.startsWith('0'.repeat(requiredLeadingZeros))) return false;
  await cacheDel(`pow:${challengeId}`);
  return true;
}
async function handleSolveChallenge(req, res, ip) {
  let body = '';
  try { body = await readBody(req); } catch { res.writeHead(400); res.end('Bad request'); return; }
  let data;
  try { data = JSON.parse(body); } catch { res.writeHead(400); res.end('Invalid JSON'); return; }
  const { challengeId, nonce, hash } = data;
  if (!challengeId || typeof nonce !== 'string' || typeof hash !== 'string') { res.writeHead(400); res.end('Missing parameters'); return; }
  const isValid = await verifyProofOfWork(challengeId, nonce, hash);
  if (!isValid) { res.writeHead(403); res.end('Invalid proof of work'); return; }
  const token = await generateSessionToken(ip);
  res.setHeader("Set-Cookie", `__Secure-token=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${CONFIG.SESSION_TOKEN_TTL_SEC}`);
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ status: "ok" }));
}
function sendJSChallenge(res, ip) {
  createPowChallenge(ip).then(({ challengeId, prefix }) => {
    const nonce = crypto.randomBytes(32).toString("base64");
    setSecurityHeaders(res, nonce);
    res.setHeader("X-Protected-By", "Dizflyze");
    res.setHeader("Protection", "Dizflzye-Security");
    res.setHeader("X-Challenge-Type", "JS-PoW");
    res.setHeader("Dz-Security-Costum", "Combo");
    res.writeHead(404, { "Content-Type": "text/html" });
    res.end(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="author" content="DizFlyze">
<meta name="protection" content="JS Challenge And Dizflyze Security System">
<meta name="challenge-type" content="JS-Challenge">
<meta name="security-version" content="4.0">
<meta name="x-protected-by" content="Dizflyze">
<meta name="description" content="Keamanan tingkat tinggi yang di kembangkan langsung oleh gua DIZ FLYZE">
<title>𝐃𝐢𝐳 𝐅𝐥𝐲𝐳𝐞 𝐒𝐞𝐜𝐮𝐫𝐢𝐭𝐲</title>
  <style nonce="${nonce}">
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }
    body {
      background: #030712;
      font-family: 'Consolas', 'Courier New', monospace;
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
      width: 100%;
      overflow: hidden;
      padding: 1.5rem;
      color: #00ffcc;
      position: relative;
    }
    body::before {
      content: '';
      position: absolute;
      top: 0; left: 0; width: 100%; height: 100%;
      background: 
        linear-gradient(rgba(0, 255, 204, 0.015) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0, 255, 204, 0.015) 1px, transparent 1px);
      background-size: 20px 20px;
      z-index: 1;
    }
    .scanlines {
      position: absolute;
      top: 0; left: 0; width: 100%; height: 100%;
      background: linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.25) 50%);
      background-size: 100% 4px;
      z-index: 4;
      pointer-events: none;
    }
    .glow-aura {
      position: absolute;
      width: 350px;
      height: 350px;
      background: radial-gradient(circle, rgba(0, 255, 204, 0.15) 0%, transparent 70%);
      z-index: 2;
      animation: floatAura 6s ease-in-out infinite alternate;
    }
    @keyframes floatAura {
      0% { transform: translate(-10px, -10px); }
      100% { transform: translate(10px, 10px); }
    }
    .container {
      position: relative;
      background: rgba(6, 11, 25, 0.8);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border-radius: 16px;
      padding: 3.5rem 2.5rem;
      width: 100%;
      max-width: 500px;
      text-align: center;
      border: 1px solid #00ffcc;
      box-shadow: 0 0 30px rgba(0, 255, 204, 0.2), inset 0 0 15px rgba(0, 255, 204, 0.1);
      z-index: 3;
      clip-path: polygon(0 0, 93% 0, 100% 7%, 100% 100%, 7% 100%, 0 93%);
      animation: glitchedIn 0.6s cubic-bezier(0.19, 1, 0.22, 1);
    }
    @keyframes glitchedIn {
      0% { opacity: 0; transform: scale(0.9) cubic-bezier(0.19, 1, 0.22, 1); filter: hue-rotate(90deg); }
      100% { opacity: 1; transform: scale(1); filter: hue-rotate(0deg); }
    }
    .cyber-bracket {
      position: absolute;
      width: 20px;
      height: 20px;
      border: 2px solid #00ffcc;
    }
    .cb-tl { top: 15px; left: 15px; border-right: none; border-bottom: none; }
    .cb-br { bottom: 15px; right: 15px; border-left: none; border-top: none; }
    .loading-hex {
      position: relative;
      width: 80px;
      height: 80px;
      margin: 0 auto 2rem;
    }
    .circle-outer {
      position: absolute;
      width: 100%;
      height: 100%;
      border: 2px dashed rgba(0, 255, 204, 0.3);
      border-radius: 50%;
      animation: spinR 15s linear infinite;
    }
    .circle-inner {
      position: absolute;
      top: 10px; left: 10px; right: 10px; bottom: 10px;
      border: 3px solid transparent;
      border-top-color: #00ffcc;
      border-bottom-color: #00ffcc;
      border-radius: 50%;
      animation: spinL 1.5s cubic-bezier(0.68, -0.55, 0.265, 1.55) infinite;
      filter: drop-shadow(0 0 8px #00ffcc);
    }
    @keyframes spinR { to { transform: rotate(360deg); } }
    @keyframes spinL { to { transform: rotate(-360deg); } }
    h2 {
      font-size: 1.6rem;
      font-weight: 900;
      letter-spacing: 2px;
      text-transform: uppercase;
      margin-bottom: 0.5rem;
      color: #ffffff;
      text-shadow: 0 0 10px rgba(0, 255, 204, 0.5);
    }
    .status {
      font-size: 0.7rem;
      text-transform: uppercase;
      letter-spacing: 2px;
      margin-bottom: 2.5rem;
      color: #6b7280;
      font-weight: bold;
    }
    .success {
      color: #00ffcc !important;
      text-shadow: 0 0 12px rgba(0, 255, 204, 0.8);
    }
    .progress-box {
      position: relative;
      background: rgba(0, 0, 0, 0.6);
      border: 1px solid rgba(0, 255, 204, 0.2);
      padding: 4px;
      border-radius: 4px;
      margin-bottom: 1.5rem;
    }
    .progress {
      width: 100%;
      height: 10px;
      background: transparent;
      overflow: hidden;
    }
    .progress-fill {
      width: 0%;
      height: 100%;
      background: repeating-linear-gradient(
        -45deg,
        #00ffcc,
        #00ffcc 6px,
        #00b38f 6px,
        #00b38f 12px
      );
      box-shadow: 0 0 10px rgba(0, 255, 204, 0.7);
      transition: width 0.15s ease-out;
    }
    .info-note {
      font-size: 0.75rem;
      color: #4b5563;
      letter-spacing: 1px;
      text-transform: uppercase;
    }
    .system-tag {
      font-size: 0.7rem;
      color: rgba(0, 255, 204, 0.4);
      margin-bottom: 1.5rem;
      letter-spacing: 2px;
    }
    @media (max-width: 480px) {
      .container { padding: 2.5rem 1.5rem; }
      h2 { font-size: 1.3rem; }
    }
  </style>
</head>
<body>
<div class="scanlines"></div>
<div class="glow-aura"></div>

<div class="container">
  <div class="cyber-bracket cb-tl"></div>
  <div class="cyber-bracket cb-br"></div>
  
  <div class="system-tag">𝗦𝗘𝗖𝗨𝗥𝗜𝗧𝗬 𝗔𝗖𝗧𝗜𝗩𝗔𝗧𝗘𝗗</div>

  <div class="loading-hex">
    <div class="circle-outer"></div>
    <div class="circle-inner" id="loaderIcon"></div>
  </div>

  <h2>𝗧𝗨𝗡𝗚𝗚𝗨 𝗕𝗘𝗡𝗧𝗔𝗥</h2>
  <p class="status" id="statusMsg">𝗦𝗘𝗗𝗔𝗡𝗚-𝗥𝗘𝗦𝗢𝗟𝗩𝗘</p>
  
  <div class="progress-box">
    <div class="progress">
      <div class="progress-fill" id="progressFill"></div>
    </div>
  </div>
  
  <p class="info-note">
    𝗗𝗢 𝗡𝗢𝗧 𝗖𝗟𝗢𝗦𝗘 𝗧𝗛𝗜𝗦 𝗪𝗘𝗕𝗦𝗜𝗧𝗘
  </p>
</div>

<script nonce="${nonce}">
const challengeId = "${challengeId}";
const prefix = "${prefix}";
const targetZeros = ${Math.ceil(CONFIG.CHALLENGE_DIFFICULTY/4)};
const maxAttempts = 50000;
let nonceVal = 0;
let found = false;
const statusDiv = document.getElementById('statusMsg');
const progressFill = document.getElementById('progressFill');
const loaderIcon = document.getElementById('loaderIcon');

function updateProgress(attempt) {
  let percent = (attempt / maxAttempts) * 100;
  progressFill.style.width = Math.min(100, percent) + '%';
}

async function sha256(s) {
  const buffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

(async () => {
  for (let i = 0; i < maxAttempts; i++) {
    if (found) break;
    nonceVal = i;
    const hash = await sha256(prefix + nonceVal);
    if (hash.startsWith('0'.repeat(targetZeros))) {
      found = true;
      statusDiv.className = 'status success';
      try {
        const res = await fetch('/api/challenge/solve', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ challengeId, nonce: nonceVal.toString(), hash })
        });
        if (res.ok) {
          loaderIcon.style.borderTopColor = '#00ffcc';
          loaderIcon.style.animationDuration = '3s';
          await new Promise(r => setTimeout(r, 4500));
          statusDiv.innerHTML = '𝗩𝗘𝗥𝗜𝗙𝗜𝗞𝗔𝗦𝗜 𝗦𝗨𝗞𝗦𝗘𝗦';
          await new Promise(r => setTimeout(r, 2500));
          statusDiv.innerHTML = '𝗦𝗜𝗟𝗔𝗛𝗞𝗔𝗡 𝗠𝗔𝗦𝗨𝗞';
          setTimeout(() => location.reload(), 1500);
        } else {
          statusDiv.innerHTML = '𝗚𝗔𝗚𝗔𝗟 𝗖𝗛𝗔𝗟𝗟𝗘𝗡𝗚𝗘';
          setTimeout(() => location.reload(), 2000);
        }
      } catch (e) {
        statusDiv.innerHTML = '𝗝𝗔𝗥𝗜𝗡𝗚𝗔𝗡 𝗝𝗘𝗟𝗘𝗞';
        setTimeout(() => location.reload(), 2000);
      }
      break;
    }
    if (i % 100 === 0) updateProgress(i);
  }
  if (!found) {
    statusDiv.innerHTML = '𝗥𝗘𝗦𝗢𝗟𝗩𝗘 𝗧𝗜𝗠𝗘𝗢𝗨𝗧';
    setTimeout(() => location.reload(), 2000);
  }
})();
</script>

<noscript>
  <div style="text-align:center; margin-top:1rem; color:#ff3b3b; font-weight:bold;">JAVASCRIPT REQUIRED</div>
</noscript>
</body>
</html>`);
  }).catch((err) => logger.error("Challenge error", err));
}
function setSecurityHeaders(res, nonce = "") {
  const csp = `default-src 'none'; script-src 'nonce-${nonce}' 'strict-dynamic'; style-src 'self' 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self' ws: wss:;`;
  res.setHeader("Content-Security-Policy", csp);
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
  res.setHeader("Server", "DIZFLYZE SECURITY");
}
async function detectAttackPattern(path, headers, queryString, body = "", trusted = false) {
  const bodyLen = Buffer.byteLength(body);
  if (bodyLen<10 && !queryString.includes("%") && !queryString.includes("'") && !path.includes("%")) return ["Normal"];
  const decodedPath = safeDecode(path);
  const decodedQuery = safeDecode(queryString);
  const headerString = Object.entries(headers).map(([k,v])=>`${k}:${v}`).join(" ");
  let full = `${decodedPath} ${decodedQuery} ${headerString} ${body}`.slice(0,2000).toLowerCase();
  full = normalizeForRegex(full);
  const cacheKey = `regex:${full}`;
  const cached = regexResultCache.get(cacheKey);
  if (cached) return cached;
  try {
    const attacks = await detectWithWorker(full);
    regexResultCache.set(cacheKey, attacks);
    return attacks.length ? [...new Set(attacks)] : ["Normal"];
  } catch(e) { return ["Normal"]; }
}
function fastPreCheckRegex(full) {
  const lower = full.toLowerCase();
  return !lower.includes("<script") && !lower.includes("select") && !lower.includes("../") &&
    !lower.includes("' or '") && !lower.includes("sleep(") && !lower.includes("benchmark(") &&
    !lower.includes("../../") && !lower.includes(";wget") && !lower.includes("|sh") && !lower.includes("cmd=");
}
function isUASuspicious(ua) { return SUSPICIOUS_UA_PATTERNS.some(p=>p.test(ua)); }
function totalHeaderSize(headers) { let size=0; for(const [k,v] of Object.entries(headers)) if(typeof v==="string") size+=k.length+v.length+4; return size; }
async function checkFingerprintAnomaly(ip, fp, trusted=false, wsConns=null) {
  if (trusted) return false;
  const key = `fp:${ip}`;
  const now = Date.now();
  const windowMs = 300000;
  let data = await cacheGet(key);
  if (!data) { await cacheSet(key, JSON.stringify({ fp, count:1, windowStart:now }), Math.ceil(windowMs/1000)); return false; }
  const parsed = JSON.parse(data);
  if (now-parsed.windowStart > windowMs) { await cacheSet(key, JSON.stringify({ fp, count:1, windowStart:now }), Math.ceil(windowMs/1000)); return false; }
  if (parsed.fp !== fp) { parsed.count++; if (parsed.count>5) { await addBehaviorScore(ip,5,trusted,wsConns); await cacheDel(key); return false; } parsed.fp=fp; await cacheSet(key, JSON.stringify(parsed), Math.ceil((parsed.windowStart+windowMs-now)/1000)); }
  return false;
}
function fastPreFilterLocal(req, trusted) {
  const url = req.url || "";
  if (url.length > CONFIG.MAX_URL_LENGTH) return "url_too_long";
  if (url.includes("\x00")) return "null_byte";
  const ua = req.headers["user-agent"] || "";
  if (ua.length===0 && !trusted) return "missing_ua";
  if (ua.length>500) return "ua_too_long";
  if (!["GET","POST","HEAD"].includes(req.method)) return "invalid_method";
  if (totalHeaderSize(req.headers) > CONFIG.MAX_HEADER_SIZE) return "header_too_large";
  return null;
}
function detectHTTPDesync(headers) {
  let cl = null, te = null;
  for (const [k,v] of Object.entries(headers)) {
    const key = k.toLowerCase();
    if (key === "content-length") cl = parseInt(v);
    if (key === "transfer-encoding") te = v.toLowerCase();
  }
  if (cl !== null && te !== null) return true;
  if (te && te.includes("chunked") && cl !== null) return true;
  return false;
}
function detectGraphQLDepth(body) {
  if (!body.includes("query") && !body.includes("mutation")) return 0;
  let depth = 0, maxDepth = 0, inString = false, stringChar = null;
  for (let i = 0; i < body.length; i++) {
    const ch = body[i];
    if (inString) { if (ch === stringChar && body[i-1] !== '\\') inString = false; continue; }
    if (ch === '"' || ch === "'") { inString = true; stringChar = ch; continue; }
    if (ch === '{') { depth++; if (depth > maxDepth) maxDepth = depth; }
    else if (ch === '}') depth--;
  }
  return maxDepth;
}
let asnReader = null;
async function loadASN() {
  if (!CONFIG.ENABLE_ASN_BLOCK) return;
  try {
    const asnPath = path.join(__dirname, "GeoLite2-ASN.mmdb");
    const exists = await fs.access(asnPath).then(() => true).catch(() => false);
    if (exists) asnReader = await maxmind.open(asnPath);
    else logger.warn("GeoLite2-ASN.mmdb not found");
  } catch (e) { logger.error("Failed to load ASN db", e); }
}
loadASN();
setInterval(loadASN, 86400000);
function getASN(ip) { if (!asnReader) return null; try { const record = asnReader.get(ip); return record?.autonomous_system_number || null; } catch { return null; } }
async function checkASNBlock(ip, trusted, wsConns) {
  if (!CONFIG.ENABLE_ASN_BLOCK || trusted) return false;
  const asn = getASN(ip);
  if (asn && CONFIG.BLOCKED_ASN.has(asn)) { await banIp(ip, `asn_${asn}`, 0, wsConns); return true; }
  return false;
}
async function checkGeoAnomaly(ip, country, trusted, wsConns=null) {
  if (!CONFIG.ENABLE_GEO || trusted) return false;
  const key = `geo:${ip}`;
  const last = await cacheGet(key);
  if (last && last !== country) { await addBehaviorScore(ip, CONFIG.GEO_ANOMALY_SCORE, trusted, wsConns); await cacheDel(key); return true; }
  await cacheSet(key, country, 300);
  return false;
}
let cloudflareCidrs = [];
const ipIsCfCache = new NodeCache({ stdTTL: 3600, checkperiod: 600 });
async function fetchCloudflareIPs() {
  try {
    const v4 = await axios.get("https://www.cloudflare.com/ips-v4", { timeout: 5000 });
    const v6 = await axios.get("https://www.cloudflare.com/ips-v6", { timeout: 5000 });
    const ips = [...v4.data.split("\n"), ...v6.data.split("\n")].filter(l => l.trim());
    cloudflareCidrs = ips.map(cidr => new CIDR(cidr.trim()));
    await fs.writeFile(path.join(__dirname, "cloudflare-cache.json"), JSON.stringify(ips));
  } catch (e) {
    try { const data = await fs.readFile(path.join(__dirname, "cloudflare-cache.json"), "utf8"); const ips = JSON.parse(data); cloudflareCidrs = ips.map(cidr => new CIDR(cidr)); } catch (err) {}
  }
}
setInterval(fetchCloudflareIPs, 24 * 3600 * 1000);
fetchCloudflareIPs();
function isCloudflareIP(ip) {
  let cached = ipIsCfCache.get(ip);
  if (cached !== undefined) return cached;
  let result = false;
  for (const cidr of cloudflareCidrs) { try { if (cidr.contains(ip)) { result = true; break; } } catch(e) {} }
  ipIsCfCache.set(ip, result);
  return result;
}
function getClientIp(req) {
  if (req.headers["cf-connecting-ip"]) return req.headers["cf-connecting-ip"];
  let remote = req.socket.remoteAddress;
  if (isCloudflareIP(remote) && req.headers["x-forwarded-for"]) return req.headers["x-forwarded-for"].split(",")[0].trim();
  if (req.headers["x-forwarded-for"]) return req.headers["x-forwarded-for"].split(",")[0].trim();
  return remote;
}

const GLOBAL_LEADERBOARD_FILE = path.join(__dirname, "../Log/leaderboard.json");
async function loadGlobalLeaderboard() {
  try { const data = await fs.readFile(GLOBAL_LEADERBOARD_FILE, "utf-8"); return JSON.parse(data); } catch(e) { return {}; }
}
async function saveGlobalLeaderboard(data) {
  const dir = path.dirname(GLOBAL_LEADERBOARD_FILE);
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(GLOBAL_LEADERBOARD_FILE, JSON.stringify(data, null, 2));
}
async function updateGlobalLeaderboard(userJid, newRequests) {
  const leaderboard = await loadGlobalLeaderboard();
  const currentBest = leaderboard[userJid] || 0;
  if (newRequests > currentBest) {
    leaderboard[userJid] = newRequests;
    await saveGlobalLeaderboard(leaderboard);
    await cacheSet(`leaderboard_${userJid}`, newRequests.toString(), 86400);
    if (isRedisReady && (await lazyRedisCheck())) { try { await redisClient.zadd("leaderboard_best", newRequests, userJid); } catch(e) {} }
    logger.info(`New record for ${userJid}: ${newRequests}`);
  }
  if (Object.keys(leaderboard).length > 1000) {
    const sorted = Object.entries(leaderboard).sort((a,b)=>b[1]-a[1]);
    await saveGlobalLeaderboard(Object.fromEntries(sorted.slice(0,1000)));
  }
}
async function getTopGlobalLeaderboard(limit = 10) {
  if (isRedisReady && (await lazyRedisCheck())) {
    try {
      const res = await redisClient.zrevrange("leaderboard_best", 0, limit-1, "WITHSCORES");
      if (res?.length) {
        const entries = [];
        for (let i=0;i<res.length;i+=2) entries.push({ number: res[i].split("@")[0], total: parseInt(res[i+1]) });
        return entries;
      }
    } catch(e) {}
  }
  const leaderboard = await loadGlobalLeaderboard();
  return Object.entries(leaderboard).sort((a,b)=>b[1]-a[1]).slice(0,limit).map(([jid,total])=>({ number: jid.split("@")[0], total }));
}
function formatDateOnly() {
  const now = new Date();
  return `${now.getDate().toString().padStart(2,"0")}-${(now.getMonth()+1).toString().padStart(2,"0")}-${now.getFullYear()}`;
}
async function generateChart(rpsHistory) {
  const labels = Array.from({ length: rpsHistory.length }, (_, i) => `${i}s`);
  const allowedData = rpsHistory.map(r => r.allowed);
  const blockedData = rpsHistory.map(r => r.blocked);
  const bypassData = rpsHistory.map(r => r.bypass || 0);
  const challengeData = rpsHistory.map(r => r.challenge || 0);
  function smoothData(data) {
    const result = [];
    for (let i=0;i<data.length;i++) {
      const prev = data[i-1] ?? data[i];
      const curr = data[i];
      const next = data[i+1] ?? data[i];
      result.push(Math.round((prev+curr*2+next)/4));
    }
    return result;
  }
  const chartConfig = {
    type: 'line',
    data: {
      labels: labels,
      datasets: [
        { label: '𝗔𝗟𝗟𝗢𝗪𝗘𝗗', data: smoothData(allowedData), borderColor: '#00ffcc', borderWidth: 4, tension: 100, cubicInterpolationMode: 'monotone', pointRadius: 0, fill: true, backgroundColor: (ctx) => { const chart = ctx.chart; const { ctx: c, chartArea } = chart; if (!chartArea) return null; const gradient = c.createLinearGradient(0, chartArea.top, 0, chartArea.bottom); gradient.addColorStop(0, 'rgba(0,255,204,0.45)'); gradient.addColorStop(1, 'rgba(0,255,204,0)'); return gradient; } },
        { label: '𝗕𝗟𝗢𝗖𝗞𝗘𝗗', data: smoothData(blockedData), borderColor: '#ff3b3b', borderWidth: 4, tension: 100, cubicInterpolationMode: 'monotone', pointRadius: 0, fill: true, backgroundColor: (ctx) => { const chart = ctx.chart; const { ctx: c, chartArea } = chart; if (!chartArea) return null; const gradient = c.createLinearGradient(0, chartArea.top, 0, chartArea.bottom); gradient.addColorStop(0, 'rgba(255,59,59,0.45)'); gradient.addColorStop(1, 'rgba(255,59,59,0)'); return gradient; } },
        { label: '𝗕𝗬𝗣𝗔𝗦𝗦', data: smoothData(bypassData), borderColor: '#f1c40f', borderWidth: 4, tension: 100, cubicInterpolationMode: 'monotone', pointRadius: 0, fill: true, backgroundColor: (ctx) => { const chart = ctx.chart; const { ctx: c, chartArea } = chart; if (!chartArea) return null; const gradient = c.createLinearGradient(0, chartArea.top, 0, chartArea.bottom); gradient.addColorStop(0, 'rgba(241,196,15,0.45)'); gradient.addColorStop(1, 'rgba(241,196,15,0)'); return gradient; } },
        { label: '𝗖𝗛𝗔𝗟𝗟𝗘𝗡𝗚𝗘', data: smoothData(challengeData), borderColor: '#3498db', borderWidth: 4, tension: 100, cubicInterpolationMode: 'monotone', pointRadius: 0, fill: true, backgroundColor: (ctx) => { const chart = ctx.chart; const { ctx: c, chartArea } = chart; if (!chartArea) return null; const gradient = c.createLinearGradient(0, chartArea.top, 0, chartArea.bottom); gradient.addColorStop(0, 'rgba(52,152,219,0.45)'); gradient.addColorStop(1, 'rgba(52,152,219,0)'); return gradient; } }
      ]
    },
    options: { responsive: true, maintainAspectRatio: true, interaction: { mode: 'index', intersect: false }, plugins: { legend: { labels: { color: '#e5e7eb' } } }, scales: { x: { grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { color: '#9ca3af' } }, y: { grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { color: '#9ca3af' } } } }
  };
  const chartUrl = `https://quickchart.io/chart?c=${encodeURIComponent(JSON.stringify(chartConfig))}&_t=${Date.now()}`;
  const response = await axios.get(chartUrl, { responseType: "arraybuffer" });
  return Buffer.from(response.data, "binary");
}
async function startLeaderboardServerAndTunnel() {
  return new Promise((resolve, reject) => {
    const port = 1000 + Math.floor(Math.random() * 8001);
    getTopGlobalLeaderboard(10).then(async (topList) => {
      let htmlRows = "";
      if (topList.length === 0) htmlRows = '<div class="card"><div class="rank">Belum ada data</div><div class="name">-</div><div class="request">Jalankan .dstat</div></div>';
      else topList.forEach((item, idx) => {
        let rankClass = idx === 0 ? "top1" : idx === 1 ? "top2" : idx === 2 ? "top3" : "";
        htmlRows += `<div class="card ${rankClass}"><div class="rank">#${idx + 1}</div><div class="name">ID: ${item.number}</div><div class="request">TOTAL : ${item.total}</div></div>`;
      });
      const html = `<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rank Top 10 DSTAT</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;700&family=Space+Grotesk:wght@500;700&display=swap');
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: radial-gradient(circle at 50% 0%, #0f172a, #020617);
            font-family: 'Plus Jakarta Sans', sans-serif;
            padding: 1rem 0.5rem; 
            color: #f8fafc;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: flex-start;
        }
        .leaderboard-container {
            width: 100%;
            max-width: 700px; 
            background: rgba(15, 23, 42, 0.6);
            backdrop-filter: blur(12px);
            border-radius: 20px;
            padding: 1.25rem;
            border: 1px solid rgba(0, 234, 255, 0.15);
            box-shadow: 0 20px 40px -15px rgba(0, 0, 0, 0.5);
            margin: 0 auto;
        }
        .header-section {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 1.5rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.08);
            padding-bottom: 1rem;
            gap: 0.5rem;
        }
        h1 {
            font-family: 'Space Grotesk', sans-serif;
            font-size: 1.4rem; 
            font-weight: 700;
            letter-spacing: -0.03em;
            background: linear-gradient(135deg, #ffffff, #7dd3fc, #00eaff);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .badge {
            background: rgba(0, 234, 255, 0.1);
            padding: 0.4rem 0.8rem;
            border-radius: 10px;
            font-size: 0.65rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: #00eaff;
            border: 1px solid rgba(0, 234, 255, 0.25);
            white-space: nowrap; 
        }
        .rank-list { display: flex; flex-direction: column; gap: 0.75rem; }
        .card {
            background: rgba(30, 41, 59, 0.4);
            border-radius: 14px;
            padding: 1rem;
            border: 1px solid rgba(255, 255, 255, 0.05);
            display: flex;
            align-items: center;
            gap: 1rem;
            position: relative;
            overflow: hidden;
            transition: transform 0.2s ease;
        }
        .card::before {
            content: '';
            position: absolute;
            left: 0;
            top: 0;
            height: 100%;
            width: 4px;
            background: #475569;
        }
        .card.top1::before { background: #fbbf24; }
        .card.top1 { background: linear-gradient(90deg, rgba(251, 191, 36, 0.05), rgba(30, 41, 59, 0.4)); border-color: rgba(251, 191, 36, 0.2); }
        .card.top2::before { background: #cbd5e1; }
        .card.top2 { background: linear-gradient(90deg, rgba(203, 213, 225, 0.05), rgba(30, 41, 59, 0.4)); border-color: rgba(203, 213, 225, 0.2); }
        .card.top3::before { background: #cd7f32; }
        .card.top3 { background: linear-gradient(90deg, rgba(205, 127, 50, 0.05), rgba(30, 41, 59, 0.4)); border-color: rgba(205, 127, 50, 0.2); }
        .rank {
            font-family: 'Space Grotesk', sans-serif;
            font-weight: 700;
            font-size: 1.2rem;
            color: #64748b;
            min-width: 35px;
        }
        .top1 .rank { color: #fbbf24; }
        .top2 .rank { color: #cbd5e1; }
        .top3 .rank { color: #f59e0b; }
        .main-content {
            display: flex;
            flex-direction: row;
            justify-content: space-between;
            align-items: center;
            flex: 1;
            gap: 0.5rem;
        }
        .info-wrapper {
            display: flex;
            flex-direction: column;
            gap: 0.25rem;
            min-width: 0; 
        }
        .name {
            font-size: 1rem;
            font-weight: 600;
            color: #e2e8f0;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis; 
        }
        .stat-bar-bg {
            width: 80px;
            height: 3px;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 2px;
            overflow: hidden;
        }
        .stat-bar-fill {
            height: 100%;
            background: #00eaff;
        }
        .top1 .stat-bar-fill { background: #fbbf24; }
        .request-wrapper {
            text-align: right;
            flex-shrink: 0;
        }
        .request {
            font-family: 'Space Grotesk', sans-serif;
            font-weight: 700;
            font-size: 1.1rem;
            color: #00eaff;
        }
        .top1 .request { color: #fbbf24; }
        .unit {
            font-size: 0.65rem;
            color: #64748b;
            font-weight: 600;
        }
        @media (max-width: 480px) {
            body { padding: 0.5rem; }
            .leaderboard-container { padding: 1rem; border-radius: 16px; }
            h1 { font-size: 1.2rem; }
            .main-content { flex-direction: column; align-items: flex-start; gap: 0.4rem; }
            .request-wrapper { text-align: left; display: flex; align-items: baseline; gap: 0.25rem; }
            .unit { font-size: 0.6rem; }
            .stat-bar-bg { width: 120px; }
        }
    </style>
</head>
<body>
    <div class="leaderboard-container">
        <div class="header-section">
            <h1><span>⚡</span> RANK TOP DSTAT</h1>
            <div class="badge">LIVE</div>
        </div>
        <div class="rank-list">
            ${htmlRows}
        </div>
    </div>
</body>
</html>`;
      const server = http.createServer((req, res) => { res.writeHead(200, { "Content-Type": "text/html" }); res.end(html); });
      const tunnel = spawn("zrok", ["share", "public", `http://127.0.0.1:${port}`, "--backend-mode", "proxy", "--headless", "--insecure"]);
      let tunnelUrl = null;
      const onData = (data) => {
        const text = data.toString();
        const match = text.match(/https:\/\/[a-z0-9-]+\.shares\.zrok\.io/i);
        if (match && !tunnelUrl) {
          tunnelUrl = match[0];
          resolve({ url: tunnelUrl, server, tunnel });
        }
      };
      tunnel.stdout.on("data", onData);
      tunnel.stderr.on("data", onData);
      tunnel.on("error", reject);
      setTimeout(() => { if (!tunnelUrl) reject(new Error("Tunnel timeout")); }, 30000);
      server.listen(port, "127.0.0.1");
    }).catch(reject);
  });
}
let currentDifficulty = CONFIG.CHALLENGE_DIFFICULTY;
function updateDifficulty(rps) {
  if (!CONFIG.AUTO_SCALE) return;
  if (rps > CONFIG.HIGH_RPS_THRESHOLD) currentDifficulty = Math.min(CONFIG.DIFFICULTY_MAX, currentDifficulty + 1);
  else currentDifficulty = Math.max(CONFIG.DIFFICULTY_BASE, currentDifficulty - 1);
  CONFIG.CHALLENGE_DIFFICULTY = currentDifficulty;
}
async function cleanupRedisKeys(activeIps) {
  if (!isRedisReady) return;
  const patterns = ['rl:*','ban:*','score:*','fp:*','ws_count:*','wsrate:*','challenge_count:*','rlpath:*','geo:*','session:*','pow:*','challenge_ts:*','rep:*'];
  try {
    const masters = redisClient.nodes ? redisClient.nodes("master") : [redisClient];
    for (const master of masters) {
      for (const pattern of patterns) {
        let cursor = '0';
        do {
          const reply = await master.scan(cursor, 'MATCH', pattern, 'COUNT', 100);
          cursor = reply[0];
          if (reply[1].length) for (const key of reply[1]) await master.del(key).catch(e => {});
        } while (cursor !== '0');
      }
    }
  } catch(e) {}
  for (const [ip] of activeIps) {
    await cacheDel(`rl:${ip}`); await cacheDel(`ban:${ip}`); await cacheDel(`session:${ip}`); await cacheDel(`score:${ip}`); await cacheDel(`fp:${ip}`); await cacheDel(`ws_count:${ip}`); await cacheDel(`wsrate:${ip}`); await cacheDel(`challenge_count:${ip}`); await cacheDel(`geo:${ip}`); await cacheDel(`rep:${ip}`);
    for (const p in CONFIG.RATE_LIMIT_PATHS) await cacheDel(`rlpath:${ip}:${p}`);
  }
}
module.exports.startDstat = async function startDstat(chatId, sock, sendMessageFunc, LOGO_URL, dstatTimers, callerJid) {
  process.env.GODEBUG = "netdns=go";
  if (!(dstatTimers instanceof Map)) dstatTimers = new Map();
  if (dstatTimers.has(chatId)) { const old = dstatTimers.get(chatId); if (old.cleanup) await old.cleanup(); dstatTimers.delete(chatId); }
  await initRedis();
  const PORT = 1000 + Math.floor(Math.random() * 8001);
  const PREPARE_DURATION = 60000, ACTIVE_DURATION = 200000, COOLDOWN_DURATION = 60000;
  let state = 'IDLE', timers = { prepare: null, active: null, cooldown: null, updateInterval: null, rpsInterval: null }, tunnels = [], tunnelUrl = null, msgKey = null, prepareStart = 0, activeStart = 0, cooldownStart = 0, server = null, wss = null;
  const wsConns = new Map(), ipConnCount = new LimitedMap(10000), activeIps = new LimitedMap(10000);
  const stats = { totalRequests: 0, allowed: 0, blocked: 0, bypass: 0, challenge: 0, uniqueIPs: new LimitedMap(5000), uniqueUAs: new LimitedMap(2000), methods: new LimitedMap(100), paths: new LimitedMap(1000), countries: new LimitedMap(100), tlsVersions: new LimitedMap(50), connectionTypes: new LimitedMap(50), httpVersions: new LimitedMap(50), reqTimesBuffer: new CircularBuffer(10000), allowedTimes: [], startTime: Date.now(), attackDetails: new CircularBuffer(1000), wsConnections: 0, wsMessagesReceived: 0, rpsSecondCounter: 0, bypassSecondCounter: 0, challengeSecondCounter: 0, lastBlocked: 0, lastChallenge: 0 };
  let rpsHistory = [];
  function cleanupTimers() { for (const key of ['prepare','active','cooldown','updateInterval','rpsInterval']) if (timers[key]) { clearTimeout(timers[key]); timers[key] = null; } }
  async function cleanupResources() { for (const [ip, conns] of wsConns.entries()) for (const ws of conns) try { ws.close(1000, "Server shutdown"); } catch(e) {} wsConns.clear(); if (wss) wss.close(); if (server) server.close(); tunnels.forEach(t => t.kill()); await cleanupRedisKeys(activeIps); ipConnCount.clear(); activeIps.clear(); }
  async function finishAndSendReport() {
    if (state === 'DONE') return;
    state = 'DONE'; cleanupTimers(); await cleanupResources(); await updateGlobalLeaderboard(callerJid, stats.totalRequests);
    const topLeaderboard = await startLeaderboardServerAndTunnel();
    const waktuSelesai = formatDateOnly();
    const peakRps = rpsHistory.length ? Math.max(...rpsHistory.map(r => r.allowed + r.blocked + r.bypass + r.challenge), 0) : 0;
    let chartBuffer = null;
    if (rpsHistory.length) try { chartBuffer = await generateChart(rpsHistory); } catch(e) { logger.error("Chart error", e); }
    const callerNumber = callerJid.split("@")[0];
    const captionAkhir = `┌────[『 𝐃𝐬𝐭𝐚𝐭 𝐒𝐞𝐥𝐞𝐬𝐚𝐢 』\n│⎋.𝐓𝐨𝐭𝐚𝐥 : ${stats.totalRequests}\n│⎋.𝐑𝐩𝐬   : ${peakRps}\n│⎋.𝐀𝐥𝐥𝐨𝐰𝐞𝐝 : ${stats.allowed}\n│⎋.𝐁𝐥𝐨𝐜𝐤𝐞𝐝 : ${stats.blocked}\n│⎋.𝐁𝐲𝐩𝐚𝐬𝐬 : ${stats.bypass}\n│⎋.𝐂𝐡𝐚𝐥𝐥𝐞𝐧𝐠𝐞 : ${stats.challenge}\n└───────\n│⎋.𝐃𝐚𝐭𝐚 𝐁𝐲 : @${callerNumber}\n│⎋.𝐓𝐢𝐦𝐞 : 200s\n│⎋.𝐖𝐚𝐤𝐭𝐮 : ${waktuSelesai}\n└───[『 𝐑𝐚𝐧𝐤 𝐏𝐞𝐫 𝐃𝐚𝐲 』\n│⎋.𝐋𝐢𝐧𝐤 : ${topLeaderboard.url}\n└──────────────────>`;
    if (chartBuffer) await sock.sendMessage(chatId, { image: chartBuffer, caption: captionAkhir, mentions: [callerJid], contextInfo: { forwardingScore: 9999, isForwarded: true } });
    else await sock.sendMessage(chatId, { text: captionAkhir, mentions: [callerJid], contextInfo: { forwardingScore: 9999, isForwarded: true } });
    setTimeout(() => { try { topLeaderboard.server.close(); topLeaderboard.tunnel.kill(); } catch(e) {} }, 100000);
    dstatTimers.delete(chatId);
  }
  async function updateCaption() {
    if (!msgKey || !tunnelUrl) return;
    let durationSec = 0, caption = "";
    const allowed = stats.allowed, uniqueIP = stats.uniqueIPs.size, uniqueUA = stats.uniqueUAs.size, methodsList = Array.from(stats.methods.keys()).join(" + ") || "-", connList = Array.from(stats.connectionTypes.keys()).join(" + ") || "-", topIP = getTopN(stats.uniqueIPs, 3), topPath = getTopN(stats.paths, 3), topCountry = getTopN(stats.countries, 3);
    if (state === 'PREPARING') { durationSec = Math.max(0, Math.floor((PREPARE_DURATION - (Date.now() - prepareStart)) / 1000)); caption = `┌────[『 𝐃𝐬𝐭𝐚𝐭 𝐁𝐨𝐭 』\n│⎋.𝐋𝐢𝐧𝐤 : ${tunnelUrl}\n└───────\n│⎋.𝐓𝐞𝐫𝐬𝐢𝐬𝐚 : ${formatDuration(durationSec)}\n│⎋.𝐌𝐞𝐧𝐮𝐧𝐠𝐠𝐮 𝐓𝐫𝐚𝐟𝐢𝐤!\n└──────────────────>`; }
    else if (state === 'ACTIVE') { durationSec = Math.max(0, Math.floor((ACTIVE_DURATION - (Date.now() - activeStart)) / 1000)); caption = `┌────[『 𝐃𝐬𝐭𝐚𝐭 𝐁𝐨𝐭 』\n│⎋.𝐋𝐢𝐧𝐤 : ${tunnelUrl}\n└───────\n│⎋.𝐀𝐥𝐥𝐨𝐰𝐞𝐝 : ${allowed}\n│⎋.𝐁𝐥𝐨𝐜𝐤𝐞𝐝 : ${stats.blocked}\n│⎋.𝐁𝐲𝐩𝐚𝐬𝐬 : ${stats.bypass}\n│⎋.𝐂𝐡𝐚𝐥𝐥𝐞𝐧𝐠𝐞 : ${stats.challenge}\n└───────\n│⎋.𝐓𝐨𝐭𝐚𝐥 𝐈𝐏 : ${uniqueIP}\n│⎋.𝐓𝐨𝐭𝐚𝐥 𝐔𝐀 : ${uniqueUA}\n│⎋.𝐓𝐞𝐫𝐬𝐢𝐬𝐚 : ${formatDuration(durationSec)}\n│⎋.𝐌𝐞𝐭𝐡𝐨𝐝 : ${methodsList}\n└───────\n│⎋.𝐏𝐚𝐭𝐡 : ${topPath || "-"}\n│⎋.𝐓𝐨𝐩 3 𝐈𝐏 : ${topIP || "-"}\n└──────────────────>\n • 𝐋𝐢𝐯𝐞`; }
    else if (state === 'COOLDOWN') { durationSec = Math.max(0, Math.floor((COOLDOWN_DURATION - (Date.now() - cooldownStart)) / 1000)); caption = `┌────[『 𝐃𝐬𝐭𝐚𝐭 𝐁𝐨𝐭 』\n│⎋.𝐋𝐢𝐧𝐤 : ${tunnelUrl}\n└───────\n│⎋.𝐓𝐮𝐧𝐠𝐠𝐮 : ${formatDuration(durationSec)}\n│⎋.𝐌𝐞𝐧𝐲𝐢𝐚𝐩𝐤𝐚𝐧 𝐃𝐚𝐭𝐚!\n└──────────────────>`; }
    else return;
    try { await sock.sendMessage(chatId, { image: { url: LOGO_URL }, caption: caption, edit: msgKey, contextInfo: { forwardingScore: 9999, isForwarded: true } }); } catch(e) { logger.error("Update caption error:", e); }
  }
  function startRpsInterval() { if (timers.rpsInterval) clearInterval(timers.rpsInterval); timers.rpsInterval = setInterval(() => { const recentAllowed = stats.rpsSecondCounter, recentBlocked = stats.blocked - stats.lastBlocked, recentBypass = stats.bypassSecondCounter, recentChallenge = stats.challengeSecondCounter; updateDifficulty(recentAllowed + recentBlocked + recentBypass + recentChallenge); rpsHistory.push({ allowed: recentAllowed, blocked: recentBlocked, bypass: recentBypass, challenge: recentChallenge }); if (rpsHistory.length > 300) rpsHistory.shift(); stats.lastBlocked = stats.blocked; stats.lastChallenge = stats.challenge; stats.rpsSecondCounter = 0; stats.bypassSecondCounter = 0; stats.challengeSecondCounter = 0; }, 1000); }
  function startUpdateCaptionInterval() { if (timers.updateInterval) clearInterval(timers.updateInterval); timers.updateInterval = setInterval(() => updateCaption(), 10000); }
  async function transitionTo(newState) { if (state === newState) return; state = newState; if (newState === 'PREPARING') { prepareStart = Date.now(); startUpdateCaptionInterval(); timers.prepare = setTimeout(async () => { if (state === 'PREPARING') await transitionTo('ACTIVE'); }, PREPARE_DURATION); } else if (newState === 'ACTIVE') { activeStart = Date.now(); startRpsInterval(); startUpdateCaptionInterval(); timers.active = setTimeout(async () => { if (state === 'ACTIVE') await transitionTo('COOLDOWN'); }, ACTIVE_DURATION); await updateCaption(); } else if (newState === 'COOLDOWN') { cooldownStart = Date.now(); if (timers.active) clearTimeout(timers.active); if (timers.rpsInterval) clearInterval(timers.rpsInterval); timers.cooldown = setTimeout(async () => { if (state === 'COOLDOWN') await finishAndSendReport(); }, COOLDOWN_DURATION); await updateCaption(); } }
  function autoStartIfNeeded() { if (state === 'PREPARING' && timers.prepare) { clearTimeout(timers.prepare); transitionTo('ACTIVE'); } }
  server = http.createServer(async (req, res) => {
    httpRequestsTotal.inc();
    let ip = getClientIp(req);
    let cleanIp = ip === "::1" ? "127.0.0.1" : ip.replace(/^::ffff:/, "");
    activeIps.set(cleanIp, true);
    autoStartIfNeeded();
    let aborted = false; req.on("close", () => { aborted = true; });
    const pathOnly = req.url?.split("?")[0] || "/", queryString = req.url?.split("?")[1] || "", country = req.headers["cf-ipcountry"] || "XX", method = req.method;
    if (pathOnly === "/api/challenge/solve" && method === "POST") { await handleSolveChallenge(req, res, cleanIp); return; }
    stats.totalRequests++;
    const banned = await isBanned(cleanIp);
    if (aborted) return;
        if (banned) {
      stats.blocked++;
      httpBlockedTotal.inc();
      const nonce = crypto.randomBytes(16).toString('base64');
      setSecurityHeaders(res, nonce);
      res.setHeader("Connection", "close");
      res.writeHead(403, { "Content-Type": "text/html; charset=utf-8" });
      res.end(`<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="author" content="DizFlyze">
  <meta name="protection" content="Dizflyze Security System">
  <title>𝐃𝐢𝐳 𝐅𝐥𝐲𝐳𝐞 𝐒𝐞𝐜𝐮𝐫𝐢𝐭𝐲 - Access Denied</title>
  <style nonce="${nonce}">
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }
    body {
      background: radial-gradient(circle at center, #0f172a 0%, #020617 100%);
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
      width: 100%;
      overflow: hidden;
      padding: 1.5rem;
      color: #f1f5f9;
    }
    body::before {
      content: '';
      position: absolute;
      width: 100%;
      height: 100%;
      background-image: linear-gradient(rgba(0, 255, 204, 0.03) 1px, transparent 1px),
                        linear-gradient(90deg, rgba(0, 255, 204, 0.03) 1px, transparent 1px);
      background-size: 30px 30px;
      z-index: 1;
    }
    .w-card {
      position: relative;
      background: rgba(15, 23, 42, 0.65);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      border-radius: 24px;
      padding: 3rem 2rem;
      width: 100%;
      max-width: 480px;
      text-align: center;
      border: 1px solid rgba(255, 59, 59, 0.25);
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5),
                  0 0 40px rgba(255, 59, 59, 0.1);
      z-index: 2;
      animation: wave 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
    }
    @keyframes wave {
      from { transform: scale(0.9) translateY(20px); opacity: 0; }
      to { transform: scale(1) translateY(0); opacity: 1; }
    }
    .icon-box {
      width: 84px;
      height: 84px;
      background: rgba(255, 59, 59, 0.1);
      border: 2px solid #ff3b3b;
      border-radius: 50%;
      display: flex;
      justify-content: center;
      align-items: center;
      margin: 0 auto 1.5rem;
      box-shadow: 0 0 20px rgba(255, 59, 59, 0.3);
      animation: pulse 2s infinite;
    }
    @keyframes pulse {
      0% { box-shadow: 0 0 0 0 rgba(255, 59, 59, 0.4); }
      70% { box-shadow: 0 0 0 15px rgba(255, 59, 59, 0); }
      100% { box-shadow: 0 0 0 0 rgba(255, 59, 59, 0); }
    }
    .icon-box svg {
      width: 40px;
      height: 40px;
      fill: #ff3b3b;
    }
    h2 {
      font-size: 1.5rem;
      font-weight: 800;
      letter-spacing: 1.5px;
      margin-bottom: 0.5rem;
      background: linear-gradient(135deg, #ff3b3b, #ff7676);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    .subtitle {
      font-size: 0.85rem;
      text-transform: uppercase;
      letter-spacing: 3px;
      color: #94a3b8;
      font-weight: 600;
      margin-bottom: 2rem;
    }
    .divider {
      height: 1px;
      background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.1), transparent);
      margin: 1.5rem 0;
    }
    .meta-container {
      background: rgba(0, 0, 0, 0.3);
      border-radius: 12px;
      padding: 1rem;
      border: 1px solid rgba(255, 255, 255, 0.05);
    }
    .meta-item {
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 0.9rem;
      color: #cbd5e1;
    }
    .meta-value {
      font-family: 'Courier New', monospace;
      font-weight: 600;
      color: #ff7676;
      background: rgba(255, 59, 59, 0.1);
      padding: 2px 8px;
      border-radius: 6px;
    }
    .footer-text {
      margin-top: 2rem;
      font-size: 0.75rem;
      color: #64748b;
      letter-spacing: 1px;
    }
    .brand {
      color: #00ffcc;
      text-decoration: none;
      font-weight: bold;
    }
  </style>
</head>
<body>
  <div class="w-card">
    <div class="icon-box">
      <svg viewBox="0 0 24 24">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10zm-1-15h2v6h-2V7zm0 8h2v2h-2v-2z"/>
      </svg>
    </div>
    <h2>𝗔𝗖𝗖𝗘𝗦𝗦 𝗗𝗘𝗡𝗜𝗘𝗗</h2>
    <div class="subtitle">403</div>
    <p style="color: #94a3b8; font-size: 0.95rem; line-height: 1.6;">
      𝗔𝗸𝘀𝗲𝘀 𝗮𝗻𝗱𝗮 𝘁𝗲𝗿𝗽𝗮𝗸𝘀𝗮 𝗱𝗶 𝗯𝗹𝗼𝗰𝗸𝗶𝗿 𝗱𝗲𝗺𝗶 𝗮𝗹𝗮𝘀𝗮𝗻 𝗸𝗲𝗮𝗺𝗮𝗻𝗮𝗻.
    </p>
    <div class="divider"></div>
    <div class="meta-container">
      <div class="meta-item">
        <span>𝗜𝗣 𝗞𝗔𝗠𝗨 :</span>
        <span class="meta-value">${cleanIp}</span>
      </div>
    </div>
    <div class="footer-text">
      𝗥𝗨𝗟𝗘𝗦 <a class="brand" href="#">𝗥𝗔𝗧𝗘 𝗟𝗜𝗠𝗜𝗧</a>
    </div>
  </div>
</body>
</html>`);
      return;
    }
    const trusted = await isTrusted(req, cleanIp);
    if (aborted) return;
    stats.uniqueIPs.set(cleanIp, (stats.uniqueIPs.get(cleanIp) || 0) + 1);
    stats.methods.set(method, (stats.methods.get(method) || 0) + 1);
    stats.paths.set(pathOnly, (stats.paths.get(pathOnly) || 0) + 1);
    stats.countries.set(country, (stats.countries.get(country) || 0) + 1);
    stats.uniqueUAs.set(req.headers["user-agent"] || "unknown", (stats.uniqueUAs.get(req.headers["user-agent"]) || 0) + 1);
    if (CONFIG.WHITELIST_IPS.has(cleanIp)) { stats.allowed++; stats.rpsSecondCounter++; setSecurityHeaders(res); res.setHeader("Connection","close"); res.writeHead(200); res.end("OK"); return; }
    if (!trusted && (!req.headers["user-agent"] || req.headers["user-agent"].trim() === "")) { stats.blocked++; httpBlockedTotal.inc(); setSecurityHeaders(res); res.setHeader("Connection","close"); res.writeHead(403); res.end("Blocked: Empty User-Agent"); return; }
    if (!trusted && isUASuspicious(req.headers["user-agent"] || "")) { stats.blocked++; httpBlockedTotal.inc(); setSecurityHeaders(res); res.setHeader("Connection","close"); res.writeHead(403); res.end("Blocked: Suspicious User-Agent"); return; }
    if (await checkASNBlock(cleanIp, trusted, wsConns)) { if (aborted) return; stats.blocked++; httpBlockedTotal.inc(); setSecurityHeaders(res); res.setHeader("Connection","close"); res.writeHead(403); res.end("Blocked: ASN blacklist"); return; }
    if (await checkGeoAnomaly(cleanIp, country, trusted, wsConns)) { if (aborted) return; stats.blocked++; httpBlockedTotal.inc(); setSecurityHeaders(res); res.setHeader("Connection","close"); res.writeHead(403); res.end("Blocked: Geo anomaly"); return; }
    const currentConns = ipConnCount.get(cleanIp) || 0;
    if (currentConns >= CONFIG.MAX_CONCURRENT_CONNECTIONS_PER_IP) { stats.blocked++; httpBlockedTotal.inc(); setSecurityHeaders(res); res.setHeader("Connection","close"); res.writeHead(429); res.end("Too many concurrent connections"); return; }
    ipConnCount.set(cleanIp, currentConns + 1);
    let connectionCleanedUp = false;
    const cleanupConnection = () => { if (connectionCleanedUp) return; connectionCleanedUp = true; const c = ipConnCount.get(cleanIp); if (c === 1) ipConnCount.delete(cleanIp); else if (c) ipConnCount.set(cleanIp, c - 1); };
    req.on("end", cleanupConnection); req.on("close", cleanupConnection); req.on("error", cleanupConnection);
    req.setTimeout(CONFIG.SLOWLORIS_TIMEOUT_MS, () => { if (!res.headersSent) { stats.blocked++; httpBlockedTotal.inc(); res.setHeader("Connection","close"); res.writeHead(408); res.end("Request Timeout"); } req.destroy(); });
    if (!(await checkRateLimitAtomic(cleanIp, pathOnly, trusted, wsConns))) { if (aborted) { cleanupConnection(); return; } stats.blocked++; httpBlockedTotal.inc(); setSecurityHeaders(res); res.setHeader("Connection","close"); res.writeHead(429); res.end("Rate Limit"); cleanupConnection(); return; }
    if (aborted) { cleanupConnection(); return; }
    if (detectHTTPDesync(req.headers)) { stats.blocked++; httpBlockedTotal.inc(); await banIp(cleanIp, "http_desync", 0, wsConns); setSecurityHeaders(res); res.setHeader("Connection","close"); res.writeHead(400); res.end("HTTP Desync detected"); cleanupConnection(); return; }
    if (aborted) { cleanupConnection(); return; }
    const pre = fastPreFilterLocal(req, trusted);
    if (pre) { stats.blocked++; httpBlockedTotal.inc(); setSecurityHeaders(res); res.setHeader("Connection","close"); res.writeHead(400); res.end(`Bad request: ${pre}`); cleanupConnection(); return; }
    if (aborted) { cleanupConnection(); return; }
    const fp = crypto.createHash("md5").update(`${req.headers["user-agent"] || ""}|${req.headers["accept"] || ""}|${req.headers["accept-language"] || ""}`).digest("hex");
    if (await checkFingerprintAnomaly(cleanIp, fp, trusted, wsConns)) { if (aborted) { cleanupConnection(); return; } stats.blocked++; httpBlockedTotal.inc(); setSecurityHeaders(res); res.setHeader("Connection","close"); res.writeHead(403); res.end("Fingerprint Anomaly"); cleanupConnection(); return; }
    if (!trusted && method !== "GET" && method !== "HEAD") { stats.blocked++; httpBlockedTotal.inc(); setSecurityHeaders(res); res.setHeader("Connection","close"); res.writeHead(403); res.end("Untrusted method not allowed"); cleanupConnection(); return; }
    if (!trusted && (method === "GET" || method === "HEAD")) {
      const lastChallenge = await cacheGet(`challenge_ts:${cleanIp}`);
      if (aborted) { cleanupConnection(); return; }
      if (lastChallenge && Date.now() - parseInt(lastChallenge) < 1000) { stats.blocked++; setSecurityHeaders(res); res.setHeader("Connection","close"); res.writeHead(429); res.end("𝐓𝐮𝐧𝐠𝐠𝐮 𝐒𝐞𝐛𝐞𝐧𝐭𝐚𝐫!"); cleanupConnection(); return; }
      await cacheSet(`challenge_ts:${cleanIp}`, Date.now().toString(), 5);
      stats.challenge++; stats.challengeSecondCounter++;
      const challengeKey = `challenge_count:${cleanIp}`;
      let failCount = parseInt(await cacheGet(challengeKey) || "0");
      failCount++; await cacheSet(challengeKey, failCount.toString(), 120);
      if (failCount > CONFIG.MAX_CHALLENGE_FAILS) { stats.blocked++; stats.challenge--; stats.challengeSecondCounter--; httpBlockedTotal.inc(); await banIp(cleanIp, "challenge_flood", 0, wsConns); setSecurityHeaders(res); res.setHeader("Connection","close"); res.writeHead(403); res.end("Too many failed challenges"); cleanupConnection(); return; }
      sendJSChallenge(res, cleanIp); cleanupConnection(); return;
    }
    let body = "";
    if (method !== "GET" && method !== "HEAD") { try { body = await readBody(req); } catch (e) { stats.blocked++; httpBlockedTotal.inc(); setSecurityHeaders(res); res.setHeader("Connection","close"); res.writeHead(413); res.end("Body too large"); cleanupConnection(); return; } }
    if (aborted) { cleanupConnection(); return; }
    const gqlDepth = detectGraphQLDepth(body);
    if (gqlDepth > CONFIG.GRAPHQL_DEPTH_LIMIT) { stats.blocked++; httpBlockedTotal.inc(); await banIp(cleanIp, "graphql_depth", 0, wsConns); setSecurityHeaders(res); res.setHeader("Connection","close"); res.writeHead(403); res.end("GraphQL depth limit exceeded"); cleanupConnection(); return; }
    if (aborted) { cleanupConnection(); return; }
    let behaviorScore = 0;
    if (body.length > 10000) behaviorScore += 5;
    if (!req.headers["user-agent"]) behaviorScore += 10;
    if (!req.headers["accept-language"]) behaviorScore += 3;
    if (queryString.length > 500) behaviorScore += 4;
    if (method === "POST" && body.length === 0) behaviorScore += 5;
    if (req.headers["referer"] === undefined) behaviorScore += 1;
    if (Object.keys(req.headers).length < 5) behaviorScore += 2;
    if (req.headers["accept"] && !req.headers["accept"].includes("text/html") && method === "GET") behaviorScore += 3;
    if (req.url.includes("%00") || req.url.includes("%0a") || req.url.includes("%0d")) behaviorScore += 8;
    if (req.url.match(/\.\.%5c/i) || req.url.match(/\.\.%2f/i)) behaviorScore += 10;
    if (req.headers["cache-control"] === "no-cache" && !req.headers["pragma"]) behaviorScore += 2;
    if (behaviorScore > 0) {
      const bannedNow = await addBehaviorScore(cleanIp, behaviorScore, trusted, wsConns);
      if (aborted) { cleanupConnection(); return; }
      if (bannedNow) { stats.blocked++; stats.attackDetails.push({ ip: cleanIp, attacks: ["behavior"], time: Date.now(), path: pathOnly, score: behaviorScore }); httpBlockedTotal.inc(); setSecurityHeaders(res); res.setHeader("Connection","close"); res.writeHead(403); res.end(`Blocked (score ${behaviorScore})`); cleanupConnection(); return; }
      if (trusted) { stats.bypass++; stats.bypassSecondCounter++; logger.warn(`Bypass detected: ${cleanIp} attacks=behavior score=${behaviorScore}`); await banIp(cleanIp, "bypass_behavior", 0, wsConns); stats.blocked++; httpBlockedTotal.inc(); setSecurityHeaders(res); res.setHeader("Connection","close"); res.writeHead(403); res.end("Bypass Blocked!"); cleanupConnection(); return; }
    }
    if (aborted) { cleanupConnection(); return; }
    const fullAttacks = await detectAttackPattern(pathOnly, req.headers, queryString, body, trusted);
    if (aborted) { cleanupConnection(); return; }
    if (fullAttacks[0] !== "Normal") { stats.blocked++; stats.attackDetails.push({ ip: cleanIp, attacks: fullAttacks, time: Date.now(), path: pathOnly }); httpBlockedTotal.inc(); if (!trusted) await banIp(cleanIp, `attack: ${fullAttacks.join(",")}`, 0, wsConns); setSecurityHeaders(res); res.setHeader("Connection","close"); res.writeHead(403); res.end("Blocked: " + fullAttacks.join(", ")); cleanupConnection(); return; }
    if (CONFIG.HONEYPOT_PATHS.includes(pathOnly)) { stats.blocked++; httpBlockedTotal.inc(); if (!trusted) await banIp(cleanIp, "honeypot", 0, wsConns); setSecurityHeaders(res); res.setHeader("Connection","close"); res.writeHead(403); res.end("Honeypot Triggered"); cleanupConnection(); return; }
    stats.allowed++; stats.rpsSecondCounter++; setSecurityHeaders(res); res.setHeader("Connection","close"); res.writeHead(200); res.end("OK"); cleanupConnection();
  });
  server.keepAliveTimeout = 5000; server.headersTimeout = 6000;
  wss = new WebSocket.Server({ noServer: true });
  async function checkWsRateLimit(ip) {
    const key = `wsrate:${ip}`, now = Date.now(), windowMs = 1000;
    if (isRedisReady && (await lazyRedisCheck())) {
      try {
        const slidingWindowSingleKey = `local key=KEYS[1] local limit=tonumber(ARGV[1]) local window=tonumber(ARGV[2]) local now=tonumber(ARGV[3]) redis.call('ZREMRANGEBYSCORE',key,0,now-window) local current=redis.call('ZCARD',key) if current<limit then local timeArray=redis.call('TIME') local micro=timeArray[2] local member=now..':'..micro..':'..math.random(1000000) redis.call('ZADD',key,now,member) redis.call('EXPIRE',key,math.ceil(window/1000)) return 1 end return 0`;
        const allowed = await redisClient.eval(slidingWindowSingleKey, 1, key, CONFIG.WS_MESSAGE_RATE_LIMIT, windowMs, now);
        return allowed === 1;
      } catch (e) { logger.error("WS rate limit eval error", e); }
    }
    const memData = (await cacheGet(key)) || [];
    let filtered = Array.isArray(memData) ? memData.filter(ts => ts > now - windowMs) : [];
    if (filtered.length >= CONFIG.WS_MESSAGE_RATE_LIMIT) return false;
    filtered.push(now); await cacheSet(key, JSON.stringify(filtered), Math.ceil(windowMs/1000)); return true;
  }
  server.on("upgrade", async (req, socket, head) => {
    autoStartIfNeeded();
    let ip = getClientIp(req);
    let cleanIp = ip === "::1" ? "127.0.0.1" : ip.replace(/^::ffff:/, "");
    activeIps.set(cleanIp, true);
    if (await isBanned(cleanIp)) { socket.write("HTTP/1.1 403 Forbidden\r\n\r\n"); socket.destroy(); stats.blocked++; httpBlockedTotal.inc(); return; }
    const trusted = await isTrusted(req, cleanIp);
    if (!(await checkRateLimitAtomic(cleanIp, null, trusted, wsConns))) { socket.write("HTTP/1.1 429 Too Many Requests\r\n\r\n"); socket.destroy(); stats.blocked++; httpBlockedTotal.inc(); return; }
    const origin = req.headers.origin;
    const allowedOrigins = CONFIG.ALLOWED_ORIGINS.length ? CONFIG.ALLOWED_ORIGINS : ["http://127.0.0.1", "https://*.trycloudflare.com"];
    let originOk = false;
    for (let allowed of allowedOrigins) {
      if (allowed.includes("*")) { const regex = new RegExp("^" + allowed.replace(/\./g, "\\.").replace(/\*/g, ".*") + "$"); if (regex.test(origin)) { originOk = true; break; } }
      else if (origin === allowed) originOk = true;
    }
    if (!originOk) { socket.write("HTTP/1.1 403 Forbidden\r\n\r\n"); socket.destroy(); stats.blocked++; httpBlockedTotal.inc(); return; }
    const wsCountKey = `ws_count:${cleanIp}`;
    let currentCount = parseInt(await cacheGet(wsCountKey) || "0");
    currentCount++; await cacheSet(wsCountKey, currentCount.toString(), 300);
    if (currentCount > CONFIG.WS_MAX_CONNECTIONS_PER_IP) { await cacheSet(wsCountKey, (currentCount-1).toString(), 300); socket.write("HTTP/1.1 429 Too Many WebSocket Connections\r\n\r\n"); socket.destroy(); stats.blocked++; httpBlockedTotal.inc(); return; }
    const token = req.headers["x-security-token"] || (() => { const match = req.headers.cookie?.match(/__Secure-token=([^;]+)/); return match ? match[1] : null; })();
    let wsTrusted = false;
    if (token && (await verifySessionToken(token, cleanIp))) wsTrusted = true;
    if (!wsTrusted) { await cacheSet(wsCountKey, (currentCount-1).toString(), 300); socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n"); socket.destroy(); stats.blocked++; httpBlockedTotal.inc(); return; }
    wss.handleUpgrade(req, socket, head, (ws) => {
      if (!wsConns.has(cleanIp)) wsConns.set(cleanIp, new Set());
      wsConns.get(cleanIp).add(ws);
      stats.wsConnections++; wsConnectionsGauge.inc();
      stats.uniqueIPs.set(cleanIp, (stats.uniqueIPs.get(cleanIp) || 0) + 1);
      ws.send(JSON.stringify({ type: "welcome", message: "WebSocket connected securely" }));
      const pingInterval = setInterval(() => { if (ws.readyState === WebSocket.OPEN) ws.ping(); else clearInterval(pingInterval); }, CONFIG.WS_PING_INTERVAL);
      ws.on("message", async (data) => {
        stats.wsMessagesReceived++;
        if (data.length > CONFIG.WS_PAYLOAD_LIMIT) { ws.close(1009, "Payload too large"); return; }
        if (!(await checkWsRateLimit(cleanIp))) { if (!trusted) await banIp(cleanIp, "ws_flood", 0, wsConns); ws.close(1008, "Rate limit exceeded"); return; }
        const messageStr = data.toString();
        const attacks = await detectAttackPattern("/websocket", req.headers, "", messageStr, trusted);
        if (attacks[0] !== "Normal") { if (!trusted) await banIp(cleanIp, `ws_attack: ${attacks.join(",")}`, 0, wsConns); ws.close(1008, "Attack detected"); stats.blocked++; httpBlockedTotal.inc(); return; }
        ws.send(JSON.stringify({ received: true, timestamp: Date.now() }));
      });
      ws.on("close", async () => { clearInterval(pingInterval); const conns = wsConns.get(cleanIp); if (conns) { conns.delete(ws); if (conns.size === 0) wsConns.delete(cleanIp); } stats.wsConnections--; wsConnectionsGauge.dec(); let cur = parseInt(await cacheGet(wsCountKey) || "0"); if (cur > 0) await cacheSet(wsCountKey, (cur-1).toString(), 300); });
      ws.on("error", (err) => logger.error(`WebSocket error from ${cleanIp}: ${err.message}`));
    });
  });
  const startTunnel = () => {
    const cloudflaredPath = path.join(process.env.HOME || "~", "cloudflared");
    const t = spawn(cloudflaredPath, ["tunnel", "--url", `http://127.0.0.1:${PORT}`]);
    console.log(`[DEBUG] Starting cloudflared tunnel on port ${PORT} using ${cloudflaredPath}`);
    t.on("error", (err) => {
      console.error(`[DEBUG] cloudflared error: ${err.message}`);
      logger.error(`Tunnel spawn error: ${err.message}`);
      if (!initialSent) {
        sock.sendMessage(chatId, { text: "❌ Gagal membuat tunnel cloudflared. Pastikan binary ada." }).catch(e => logger.error(e));
        initialSent = true;
      }
    });
    t.stdout.on("data", (data) => {
      const text = data.toString();
      console.log(`[DEBUG] cloudflared stdout: ${text.trim()}`);
      const match = text.match(/https:\/\/[a-z0-9.-]+\.trycloudflare\.com/i);
      if (match && !tunnelUrlSet && !initialSent) {
        console.log(`[DEBUG] URL detected: ${match[0]}`);
        tunnelUrlSet = true;
        tunnelUrl = match[0];
        sendInitialMessage(tunnelUrl).catch(err => logger.error(err));
      }
    });
    t.stderr.on("data", (data) => {
      const text = data.toString();
      console.error(`[DEBUG] cloudflared stderr: ${text.trim()}`);
      const match = text.match(/https:\/\/[a-z0-9.-]+\.trycloudflare\.com/i);
      if (match && !tunnelUrlSet && !initialSent) {
        console.log(`[DEBUG] URL detected from stderr: ${match[0]}`);
        tunnelUrlSet = true;
        tunnelUrl = match[0];
        sendInitialMessage(tunnelUrl).catch(err => logger.error(err));
      }
    });
    return t;
  };
  server.listen(PORT, "127.0.0.1", () => {
    logger.info(`[DSTAT] Server on ${PORT}`);
    console.log(`[DEBUG] HTTP server listening on 127.0.0.1:${PORT}`);
    tunnels.push(startTunnel());
  });
  let initialSent = false, tunnelUrlSet = false;
  async function sendInitialMessage(url) {
    if (initialSent) return;
    initialSent = true;
    try {
      const sent = await Promise.race([ sock.sendMessage(chatId, { image: { url: LOGO_URL }, caption: `🚀 𝐃𝐈𝐙 𝐅𝐋𝐘𝐙𝐄 𝐃𝐒𝐓𝐀𝐓 🌐`, contextInfo: { forwardingScore: 9999, isForwarded: true } }), new Promise((_, reject) => setTimeout(() => reject(new Error("Image send timeout")), 15000)) ]);
      msgKey = sent.key; await new Promise(resolve => setTimeout(resolve, 2000)); await transitionTo('PREPARING');
    } catch (err) {
      logger.error("Gagal kirim pesan awal (gambar): " + err.message);
      try { const sent = await sock.sendMessage(chatId, { text: `🚀 DSTAT ACTIVE\nTunnel URL: ${url}\nMemulai dalam ${Math.floor(PREPARE_DURATION / 1000)} detik.` }); msgKey = sent.key; await transitionTo('PREPARING'); } catch (e2) { logger.error("Gagal kirim pesan teks juga:", e2); }
    }
  }
  dstatTimers.set(chatId, { cleanup: finishAndSendReport });
};
