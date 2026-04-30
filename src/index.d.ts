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
   * Each line is a JSON object with fields: timestamp, ip, action, reason, expiresAt.
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
