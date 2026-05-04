import { EventEmitter } from 'events';
import { Request, Response, NextFunction, RequestHandler } from 'express';

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

export interface APIMonitorOptions {
  /** MongoDB connection URI. Required when saveRecords is true. */
  mongoURI?: string;
  /** Redis connection URL. Required when saveRecords is true. */
  redisURL?: string;
  /** Maximum requests allowed per time window. Default: 10 */
  maxRequests?: number;
  /** Time window in seconds. Default: 60 */
  timeWindow?: number;
  /** Maximum unique endpoints allowed per time window before path-scan block. Default: 5 */
  scanThreshold?: number;
  /**
   * Enable persistent logging to MongoDB and distributed tracking via Redis.
   * When false (default) tracking is kept in process memory.
   */
  saveRecords?: boolean;
  /**
   * Local-mode only. How often (in ms) the cleanup timer runs to evict expired
   * blocked IPs and stale tracking data from the in-memory Maps. Default: 60000 (1 min).
   */
  cleanupInterval?: number;
  /**
   * Local-mode only. Absolute path to an NDJSON file used for lightweight block persistence.
   * Each line is a JSON object with fields: timestamp, ip, action, reason, route, expiresAt.
   *
   * On startup, non-expired blocks are restored from the file so bans survive restarts.
   * Compatible with jq, grep, tail -f, fail2ban, Filebeat, Logstash, and most SIEM tools.
   *
   * @example
   * blockLogPath: '/var/log/api-monitor/blocked.ndjson'
   */
  blockLogPath?: string;
}

// ---------------------------------------------------------------------------
// Shapes returned / emitted by the library
// ---------------------------------------------------------------------------

export interface BlockInfo {
  /** Human-readable denial message */
  error: string;
  /** Attack type that triggered the block */
  reason: string;
  /** Remaining block duration as a human-readable string, e.g. "295 seconds" */
  blockedFor: string;
  /** ISO-8601 timestamp when the block expires */
  blockedUntil: string;
}

export interface AttackEvent {
  /** Client IP address */
  ip: string;
  /** Attack category detected */
  type: 'DDoS (Excessive Requests)' | 'Path Scanning' | string;
  /** When the attack was detected */
  timestamp: Date;
}

/** Internal record stored per blocked IP in local (non-Redis) mode */
export interface LocalBlockRecord {
  /** Unix-ms timestamp when the block expires */
  expiresAt: number;
  /** Attack type that caused the block */
  reason: string;
  /** Request path that triggered the block. null if not available. */
  route: string | null;
}

/**
 * Common log entry shape returned by getLogs and getAttackLogs.
 * In local mode (saveRecords: false), only ip, timestamp, attackType and route
 * are populated — the rest are null.
 * In advanced mode (saveRecords: true) all fields come from MongoDB.
 */
export interface LogEntry {
  ip: string;
  /** HTTP method. null in local mode. */
  method: string | null;
  /** Request path. Available in both modes. */
  route: string | null;
  timestamp: string | Date;
  /** Response time in ms. null in local mode. */
  responseTime: number | null;
  /** HTTP status code. null in local mode. */
  statusCode: number | null;
  /** User-Agent header. null in local mode. */
  userAgent: string | null;
  /** Attack category that triggered the block, or null for normal requests. */
  attackType: string | null;
}

/** Query options accepted by getLogs. All fields are optional. */
export interface LogQuery {
  /** Filter by exact IP address. */
  ip?: string;
  /** Filter by attack type, e.g. "DDoS (Excessive Requests)" or "Path Scanning". */
  attackType?: string;
  /** ISO-8601 or parseable date string. Returns entries on or after this date. */
  startDate?: string;
  /** ISO-8601 or parseable date string. Returns entries on or before this date. */
  endDate?: string;
  /** Maximum number of entries to return. Default: 10. */
  limit?: number;
}

/**
 * Per-IP statistics entry returned by getStats.
 * In local mode totalRequests and avgResponseTime are null (requests are not individually logged).
 */
export interface StatEntry {
  /** IP address */
  _id: string;
  /** Total requests from this IP. null in local mode. */
  totalRequests: number | null;
  /** Average response time in ms. null in local mode. */
  avgResponseTime: number | null;
  /** Number of attack events detected for this IP. */
  attackCount: number;
  /** Unique routes accessed. Empty array in local mode. */
  routes: string[];
}

/** Single entry in the blocked list returned by getBlockedIPs. */
export interface BlockedIPEntry {
  ip: string;
  /** Attack type that caused the block. */
  reason: string;
  /** Request path that triggered the block. null if not recorded. */
  route: string | null;
  /** Seconds remaining until the block expires. */
  remainingSec: number;
  /** ISO-8601 timestamp when the block expires. */
  blockedUntil: string;
}

/** Result shape returned by getBlockedIPs. */
export interface BlockedIPsResult {
  /** Total number of currently blocked IPs. */
  count: number;
  blocked: BlockedIPEntry[];
}

// ---------------------------------------------------------------------------
// Factory return value
// ---------------------------------------------------------------------------

export interface APIMonitorResult {
  /**
   * Express middleware that tracks every request and automatically blocks
   * IPs that exceed rate or path-scan thresholds.
   */
  middleware: RequestHandler;
  /**
   * Express middleware that rejects already-blocked IPs with HTTP 403.
   * Shares the same APIMonitor instance as `middleware` — mount it **before**
   * `middleware` so blocked IPs are short-circuited early.
   *
   * @example
   * app.use(blockIPs);   // ← reject blocked IPs here
   * app.use(middleware); // ← track & detect here
   */
  blockIPs: RequestHandler;
  /** The underlying APIMonitor instance — use to subscribe to events or inspect state. */
  monitor: APIMonitorInstance;
}

// ---------------------------------------------------------------------------
// APIMonitor instance shape
// ---------------------------------------------------------------------------

export declare class APIMonitorInstance extends EventEmitter {
  readonly maxRequests: number;
  readonly timeWindow: number;
  readonly scanThreshold: number;
  readonly saveRecords: boolean;

  /** Blocked IPs and their expiry info. Only populated in local mode (saveRecords: false). */
  localBlockedIPs: Map<string, LocalBlockRecord>;
  /** Per-IP timestamp arrays used for sliding-window rate limiting. Local mode only. */
  localRequestCounts: Map<string, number[]>;
  /** Per-IP sets of unique routes accessed. Local mode only. */
  localRouteScans: Map<string, Set<string>>;

  // Typed event emitter overloads
  on(event: 'attack-detected', listener: (event: AttackEvent) => void): this;
  on(event: string, listener: (...args: unknown[]) => void): this;
  once(event: 'attack-detected', listener: (event: AttackEvent) => void): this;
  once(event: string, listener: (...args: unknown[]) => void): this;
  emit(event: 'attack-detected', data: AttackEvent): boolean;
  emit(event: string, ...args: unknown[]): boolean;

  /** Extracts the real client IP, handling proxies and IPv6-mapped addresses. */
  getClientIP(req: Request): string;

  /** Returns true if the given IP is currently blocked. */
  isIPBlocked(ip: string): Promise<boolean>;

  /** Returns a BlockInfo object describing why and how long the IP is blocked. */
  getBlockInfo(ip: string): Promise<BlockInfo>;

  /** Express-compatible middleware that rejects blocked IPs with HTTP 403. */
  blockIPsMiddleware(req: Request, res: Response, next: NextFunction): Promise<void>;

  /** Express-compatible middleware that monitors and tracks the request. */
  monitorMiddleware(req: Request, res: Response, next: NextFunction): Promise<void>;

  // ---------------------------------------------------------------------------
  // Query methods — work in both local and advanced (Redis + MongoDB) modes
  // ---------------------------------------------------------------------------

  /**
   * Returns filtered log entries, most recent first.
   *
   * - Advanced mode: queries MongoDB.
   * - Local mode: reads the NDJSON block log.
   *
   * @example
   * const logs = await monitor.getLogs({ ip: '1.2.3.4', limit: 20 });
   */
  getLogs(opts?: LogQuery): Promise<LogEntry[]>;

  /**
   * Returns attack-only log entries (attackType != null), most recent first.
   *
   * - Advanced mode: queries MongoDB filtered by attackType.
   * - Local mode: reads block entries from the NDJSON log.
   *
   * @example
   * const attacks = await monitor.getAttackLogs({ limit: 50 });
   */
  getAttackLogs(opts?: { limit?: number }): Promise<LogEntry[]>;

  /**
   * Returns per-IP attack statistics sorted by attackCount descending.
   *
   * - Advanced mode: MongoDB aggregation (totalRequests and avgResponseTime populated).
   * - Local mode: counts block events per IP from the NDJSON log (totalRequests and
   *   avgResponseTime are null).
   *
   * @example
   * const stats = await monitor.getStats();
   */
  getStats(): Promise<StatEntry[]>;

  /**
   * Returns all currently blocked IPs with their remaining TTL.
   *
   * - Advanced mode: scans Redis for blocked:* keys.
   * - Local mode: reads localBlockedIPs, filtering out expired entries.
   *
   * @example
   * const { count, blocked } = await monitor.getBlockedIPs();
   */
  getBlockedIPs(): Promise<BlockedIPsResult>;
}

// ---------------------------------------------------------------------------
// Factory function + namespace (for module.exports.blockIPs)
// ---------------------------------------------------------------------------

/**
 * Creates an APIMonitor instance and returns three objects that all share the same
 * underlying monitor — so blocks detected by `middleware` are immediately visible
 * to `blockIPs`, and vice-versa.
 *
 * @example
 * const { middleware, blockIPs, monitor } = APIMonitor({ maxRequests: 100 });
 *
 * app.use(blockIPs);   // reject blocked IPs early
 * app.use(middleware); // track requests and detect attacks
 *
 * monitor.on('attack-detected', ({ ip, type, timestamp }) => {
 *   console.warn(`Attack from ${ip}: ${type} at ${timestamp}`);
 * });
 */
declare function APIMonitor(options?: APIMonitorOptions): APIMonitorResult;

declare namespace APIMonitor {
  /**
   * Creates a **standalone** IP-blocking middleware backed by its own independent
   * APIMonitor instance.
   *
   * Because it owns a separate instance its blocked-IP list is not shared with any
   * factory instance. Use the `blockIPs` property from the factory for shared state.
   *
   * @example
   * // Useful when you want a zero-config guard at the top of your app:
   * app.use(APIMonitor.blockIPs({ maxRequests: 200 }));
   */
  function blockIPs(options?: APIMonitorOptions): RequestHandler;
}

export = APIMonitor;
