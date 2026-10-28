/**
 * 会话记录(transcript)持久化。
 *
 * 与"操作台账"是两份数据、两种职责(31 文档 §2):
 *   · 台账(ledger):每笔业务的能力/金额/对象/流水号/业务态 → 给列表页与"那笔成了吗"用;
 *   · 会话记录(本文件):每轮 user/agent 的原话、卡片标题、traceId → 给**回放**用。
 * 不合并的理由很实际:台账要快(列表一次拉几十条),回放要全(一句话都不能少)。
 *
 * ★ 三条硬约束(客户确认过的):
 *   ① **只读**:历史可查看,跨会话确认/撤销一律禁止(这条由编排器的会话隔离保证);
 *   ② **不留明文**:密码 / 验证码 / 完整卡号永远不进会话记录(redactText);
 *   ③ **会丢但不会坏**:每客户只留最近 50 个会话 / 30 天,超出滚动丢弃 ——
 *      丢的是回放,不影响审计链。
 *
 * ★ 为什么落盘而不是放内存:这条功能的验收标准就是"重启进程后会话还在"。
 *   内存实现会在演示中途换一次端口就穿帮 —— 而这恰恰是客户最先试的一次。
 */

import { createHmac, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

import type { Channel } from "../../core/src/types.ts";
import { OPERATION_STATUS_PRIORITY, type OperationStatus } from "../../core/src/agent/operationStatus.ts";

/** 与 core 的会话级优先级保持同一份定义 —— 口径只有一处 */
const OPERATION_STATUS_ORDER = OPERATION_STATUS_PRIORITY;

/** 一轮对话(仅存回放需要的字段;文本已脱敏) */
export interface SessionTurn {
  ts: number;
  role: "user" | "agent";
  /** 已脱敏;密码/验证码/完整卡号永不写入 */
  text: string;
  /** 这一轮展示的卡片标题(如「请确认转账信息」) */
  cardTitle?: string;
  /** 这一轮的追问类型(confirm / strong_auth / clarify / none) */
  promptKind?: string;
  /** 关联审计 traceId —— 详情页据此"跳到审计"而不复制审计内容 */
  traceId: string;
}

/** 某个能力在会话内的最新业务态(用于会话级状态聚合) */
export interface SessionOpState {
  status: OperationStatus;
  statusLabel: string;
  /** 该状态的时间(同一能力取最新一条) */
  at: number;
}

/** 一个会话 */
export interface SessionRecord {
  sessionId: string;
  customerId: string;
  channel: Channel;
  startedAt: number;
  lastAt: number;
  /** 列表标题,如「转账 · 王秀兰」「挂失冻结 · 尾号 8888」 */
  title: string;
  /** 会话级状态 = 该会话内最需关注的一个(31 文档 §4.3) */
  status: OperationStatus;
  statusLabel: string;
  turns: SessionTurn[];
  /** 指向台账的 opId */
  operationIds: string[];
  /**
   * ★ 会话内"每个能力的最新业务态"。
   *
   *   为什么要存在会话记录里,而不是每次去翻台账:
   *   台账在另一个文件里(甚至可能被清掉/换目录),而会话状态是会话的属性 ——
   *   重启、换库、台账被裁掉,都不该让"已转账成功"的会话变成"仅查询"。
   *   同一能力只留最新一条(转账会先 pending 再 done),不同能力之间才比优先级。
   */
  ops?: Record<string, SessionOpState>;
}

interface CustomerSessionFile {
  version: 1;
  customerId: string;
  sessions: SessionRecord[];
}

/** 每客户保留的会话数上限(31 文档 §3.1) */
export const MAX_SESSIONS_PER_CUSTOMER = 50;
/** 每客户保留的会话天数 */
export const SESSION_RETENTION_MS = 30 * 24 * 3600 * 1000;
/** 单个会话最多保留的轮次(防止一次长对话把文件撑大) */
export const MAX_TURNS_PER_SESSION = 200;

/**
 * 会话文本脱敏。
 *
 * ★ 为什么必须在**入库前**做,而不是展示时做:
 *   一旦明文落盘,它就已经在磁盘上了 —— 之后再怎么在界面上打码,
 *   都不改变"密码被存下来了"这个事实。审计与日志同理。
 *
 * 规则(与 31 文档 §2.4 一致):
 *   ① 密码/交易密码/登录密码 + 冒号后的值;
 *   ② 验证码 + 可选冒号 + 数字;
 *   ③ 任何 6 位以上连续数字(完整卡号/账号/手机号段)。
 */
export function redactText(text: string): string {
  return text
    .replace(/((?:交易|登录|查询)?密码)\s*[:：]\s*\S+/g, "$1:***")
    .replace(/(验证码)\s*[:：]?\s*\d+/g, "$1:***")
    // ★ 6 位以上连续数字一律打码:完整卡号/账号/手机号都不该被回放出来
    .replace(/\d{6,}/g, "******");
}

/** 台账条目里与会话聚合有关的最小形状(避免 server 内部文件互相依赖) */
export interface LedgerLike {
  capability: string;
  status?: OperationStatus;
  statusLabel?: string;
  createdAt?: number;
  ts: number;
}

/**
 * 会话级状态:从该会话的台账条目推出"最需要关注"的那一个。
 *
 * ★ 关键细节:**同一个能力只保留最新一条**再比优先级。
 *   一条转账会在台账里留下两行 —— "待你确认"和"已转账成功"。
 *   若直接按 §4.3 的优先级取最高,`pending` 会压住 `done`,
 *   于是已经办完的会话永远显示"待你确认"(P3 的 S5 会直接失败)。
 *   同一件事只认它的**最新状态**,不同的事之间才比严重程度。
 */
export function summarizeSession(rows: LedgerLike[]): { status: OperationStatus; statusLabel: string } {
  const latest = new Map<string, LedgerLike>();
  for (const row of rows) {
    const prev = latest.get(row.capability);
    if (!prev || (row.createdAt ?? row.ts) >= (prev.createdAt ?? prev.ts)) latest.set(row.capability, row);
  }
  let status: OperationStatus = "inquiry";
  let statusLabel = "仅查询";
  for (const candidate of OPERATION_STATUS_ORDER) {
    const hit = [...latest.values()].find((r) => r.status === candidate);
    if (hit) {
      status = candidate;
      statusLabel = hit.statusLabel ?? candidate;
      break;
    }
  }
  return { status, statusLabel };
}

/** upsertSession 的入参:会话字段 + 可选的"本轮操作" */
export interface SessionUpsert extends Partial<SessionRecord> {
  sessionId: string;
  /** 本轮发生的操作:用于滚动更新会话级状态(同一能力取最新一条) */
  op?: { capability: string; status: OperationStatus; statusLabel: string; at: number };
}

export class SessionJournal {  private readonly dir: string;
  private readonly cache = new Map<string, CustomerSessionFile>();
  /** 串行化写盘:同一客户的并发写入按顺序落盘(与 PersonalizationStore 一致) */
  private writeQueue: Promise<unknown> = Promise.resolve();
  /** 进程内的"已加载"标记:load() 只需成功一次 */
  private readonly loaded = new Set<string>();

  constructor(dir: string) {
    this.dir = dir;
  }

  private pathFor(customerId: string): string {
    // 客户 ID 来自请求,只允许安全字符,避免路径穿越
    const safe = customerId.replace(/[^a-zA-Z0-9_-]/g, "_");
    return join(this.dir, `${safe}.json`);
  }

  /** 懒加载:首次访问某客户时读盘;读不到就从空开始(不阻塞业务) */
  async load(customerId: string): Promise<void> {
    if (this.loaded.has(customerId)) return;
    let file: CustomerSessionFile = { version: 1, customerId, sessions: [] };
    try {
      const raw = await readFile(this.pathFor(customerId), "utf8");
      const parsed = JSON.parse(raw) as Partial<CustomerSessionFile>;
      file = {
        version: 1,
        customerId,
        sessions: Array.isArray(parsed.sessions) ? parsed.sessions : [],
      };
    } catch {
      // 文件不存在或损坏:从空开始。★ 不覆盖损坏的旧文件,除非再次写入
    }
    this.cache.set(customerId, file);
    this.loaded.add(customerId);
  }

  private async fileFor(customerId: string): Promise<CustomerSessionFile> {
    await this.load(customerId);
    const file = this.cache.get(customerId);
    if (file) return file;
    // 理论上不可达;兜底给一个空文件,避免把 "undefined" 写进磁盘
    const empty: CustomerSessionFile = { version: 1, customerId, sessions: [] };
    this.cache.set(customerId, empty);
    return empty;
  }

  /** 原子落盘:先写临时文件再重命名(写一半被杀也不会留下半个 JSON) */
  private persist(customerId: string, file: CustomerSessionFile): Promise<void> {
    const run = async (): Promise<void> => {
      const target = this.pathFor(customerId);
      await mkdir(dirname(target), { recursive: true });
      const tmp = `${target}.tmp-${process.pid}`;
      await writeFile(tmp, JSON.stringify(file, null, 2), "utf8");
      await rename(tmp, target);
    };
    const next = this.writeQueue.then(run, run);
    this.writeQueue = next.catch(() => undefined);
    return next;
  }

  /** 追加一轮。文本在这里**再脱敏一次**(调用方漏了也不会把明文写进去) */
  async appendTurn(
    customerId: string,
    turn: SessionTurn & { sessionId: string; channel: Channel },
    /** 裁剪基准时间(默认取这一轮的时间;宿主有注入时钟时传同一个时钟) */
    now: number = turn.ts,
  ): Promise<void> {
    const file = await this.fileFor(customerId);
    const existing = file.sessions.find((s) => s.sessionId === turn.sessionId);
    const safeTurn: SessionTurn = {
      ts: turn.ts,
      role: turn.role,
      text: redactText(turn.text),
      ...(turn.cardTitle ? { cardTitle: turn.cardTitle } : {}),
      ...(turn.promptKind ? { promptKind: turn.promptKind } : {}),
      traceId: turn.traceId,
    };

    if (!existing) {
      file.sessions.push({
        sessionId: turn.sessionId,
        customerId,
        channel: turn.channel,
        startedAt: turn.ts,
        lastAt: turn.ts,
        title: "新会话",
        status: "inquiry",
        statusLabel: "仅查询",
        turns: [safeTurn],
        operationIds: [],
      });
    } else {
      existing.turns.push(safeTurn);
      if (existing.turns.length > MAX_TURNS_PER_SESSION) {
        existing.turns = existing.turns.slice(-MAX_TURNS_PER_SESSION);
      }
      existing.lastAt = Math.max(existing.lastAt, turn.ts);
    }

    this.trim(file, now);
    await this.persist(customerId, file);
  }

  /** 更新会话的元信息(标题 / 状态 / 关联的台账条目) */
  async upsertSession(
    customerId: string,
    patch: SessionUpsert,
    /** 裁剪基准时间(默认取当前时间) */
    now: number = Date.now(),
  ): Promise<void> {
    const file = await this.fileFor(customerId);
    const { op, ...fields } = patch;
    let session = file.sessions.find((s) => s.sessionId === patch.sessionId);
    if (!session) {
      const at = fields.lastAt ?? fields.startedAt ?? now;
      session = {
        sessionId: patch.sessionId,
        customerId,
        channel: fields.channel ?? "app",
        startedAt: fields.startedAt ?? at,
        lastAt: fields.lastAt ?? at,
        title: fields.title ?? "新会话",
        status: fields.status ?? "inquiry",
        statusLabel: fields.statusLabel ?? "仅查询",
        turns: [],
        operationIds: [],
      };
      file.sessions.push(session);
    } else {
      /**
       * ★ 标题一旦有了意义就不再覆盖。
       *
       *   否则一个会话里最后一句是查余额,标题就变成「账户与账单查询」——
       *   客户在历史列表里找那笔转账时,看到的却是"查询"。
       *   标题代表"这个会话是干什么的",取第一次真正办了事的那一类。
       */
      if (fields.title && (session.title === "新会话" || session.title.length === 0)) session.title = fields.title;
      if (fields.status) session.status = fields.status;
      if (fields.statusLabel) session.statusLabel = fields.statusLabel;
      if (fields.lastAt) session.lastAt = Math.max(session.lastAt, fields.lastAt);
      if (fields.channel) session.channel = fields.channel;
    }
    if (fields.operationIds) {
      // 去重并保持顺序:同一笔操作可能被多次上报
      const merged = new Set([...session.operationIds, ...fields.operationIds]);
      session.operationIds = [...merged];
    }

    // ★ 会话级状态由"每个能力的最新状态"聚合而来,不依赖台账文件还在不在
    if (op) {
      session.ops = session.ops ?? {};
      const prev = session.ops[op.capability];
      if (!prev || op.at >= prev.at) {
        session.ops[op.capability] = { status: op.status, statusLabel: op.statusLabel, at: op.at };
      }
      const summary = summarizeSession(
        Object.entries(session.ops).map(([capability, state]) => ({
          capability,
          status: state.status,
          statusLabel: state.statusLabel,
          ts: state.at,
          createdAt: state.at,
        })),
      );
      session.status = summary.status;
      session.statusLabel = summary.statusLabel;
    }

    /**
     * ★ 裁剪基准必须是"现在",不是这条会话自己的时间。
     *
     *   用 patch.lastAt 当过基准踩过一次:补录一条 31 天前的会话时,
     *   基准也跟着退到 31 天前,于是"超过 30 天该清理"永远不成立 ——
     *   过期会话被原封不动地留了下来。保留期是墙钟概念,只能拿当前时间来比。
     */
    this.trim(file, now);
    await this.persist(customerId, file);
  }

  /** 会话列表(lastAt 倒序) */
  async list(customerId: string): Promise<SessionRecord[]> {
    const file = await this.fileFor(customerId);
    return [...file.sessions].sort((a, b) => b.lastAt - a.lastAt);
  }

  /** 单个会话(不存在返回 null —— 调用方据此返回 404,而不是给一个空壳) */
  async get(customerId: string, sessionId: string): Promise<SessionRecord | null> {
    const file = await this.fileFor(customerId);
    return file.sessions.find((s) => s.sessionId === sessionId) ?? null;
  }

  /**
   * 容量裁剪:每客户最多 50 个会话 / 30 天。
   *
   * ★ 先按时间丢,再按数量丢:时间淘汰是"合规口径"(超过一个月不该再留),
   *   数量淘汰是"容量口径"(防单客户把文件写爆)。两条都执行,顺序不影响结果,
   *   但写反了会先砍掉新会话却留着过期会话 —— 那是明显的错。
   */
  private trim(file: CustomerSessionFile, now: number): void {
    const cutoff = now - SESSION_RETENTION_MS;
    let kept = file.sessions.filter((s) => s.lastAt >= cutoff);
    if (kept.length > MAX_SESSIONS_PER_CUSTOMER) {
      kept = kept.sort((a, b) => a.lastAt - b.lastAt).slice(-MAX_SESSIONS_PER_CUSTOMER);
    }
    file.sessions = kept;
  }
}

// ============================================================================
// 上机会话(身份的唯一来源)
// ============================================================================

/**
 * ★ 为什么"身份"要落在 sessions.ts,而不是写一层 HTTP 中间件:
 *
 *   网关上的 `customerId` 曾经直接来自**请求体**（`{ customerId: "..." }`）,
 *   于是客户端传谁的 ID 就能看谁的账单、动谁的钱 —— 这是横向越权,不是"没登录"。
 *   修法只有一条:**身份必须由服务端签发、服务端保管**。
 *   本文件已经是"每次上机的状态都在哪里"的家(会话记录 transcript),
 *   上机会话(identity session)与它同源同生命周期,所以扩展在这里,
 *   而不是新起一个平行的安全组件。
 *
 * ★ 令牌与"会话记录"是两件事,别混:
 *   · SessionRecord  = 客户**说过什么、系统答过什么**(回放用,按客户按会话落盘);
 *   · AuthSession    = 这次上机**是谁、什么时候签发的、还能不能用**(鉴权用)。
 *   前者是内容,后者是身份;把身份塞进回放文件会让"清回放"顺带清掉鉴权状态。
 *
 * ★ 两道校验,缺一不可:
 *   ① 签名(无密钥签不出来)—— 拦"自己编一个 customerId";
 *   ② 服务端会话记录(可撤销、可过期)—— 拦"令牌没过期但已经登出/被吊销"。
 *   只做签名不做记录,登出就只能是"客户端自觉";只做记录不做签名,
 *   每次请求都要查库(且实现里很容易退化成"信任客户端报的 ID")。
 */

/** 登录成功后签发的上机会话 */
export interface AuthSession {
  sid: string;
  /** ★ 身份的唯一事实来源:后续所有接口的 customerId 都从这里取 */
  customerId: string;
  channel: Channel;
  /**
   * 上机方式:
   *   · login           —— 凭据登录(唯一能让客户成为"别人"的入口);
   *   · demo_bootstrap  —— 本机演示默认身份(见 AuthSessionStore.bootstrap)。
   */
  kind: "login" | "demo_bootstrap";
  issuedAt: number;
  expiresAt: number;
  lastSeenAt: number;
  /** 写操作的 CSRF 双提交令牌（前端可选携带;强制层是 Origin 校验 + SameSite） */
  csrfToken: string;
  revokedAt?: number;
  /** 签发时的客户端标识(便于审计"这个令牌是给谁签的") */
  userAgent?: string;
}

interface AuthSessionFile {
  version: 1;
  sessions: AuthSession[];
}

/** 会话 Cookie 名 —— HttpOnly,前端 JS 读不到;前端不需要知道它的存在 */
export const AUTH_COOKIE = "ba_session";
/** CSRF 双提交 Cookie(非 HttpOnly,供前端读取后回填请求头;可选增强) */
export const AUTH_CSRF_COOKIE = "ba_csrf";

/** 上机会话默认有效期(8 小时,与"上班一天"对齐) */
export const AUTH_SESSION_TTL_MS = 8 * 3600 * 1000;
/** 每客户最多保留的上机会话数(防止登录接口被刷出无数条记录) */
export const MAX_AUTH_SESSIONS = 50;

interface AuthTokenPayload {
  sid: string;
  cid: string;
  ch: string;
  iat: number;
  exp: number;
}

function b64url(input: Buffer | string): string {
  return (typeof input === "string" ? Buffer.from(input, "utf8") : input)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function unb64url(input: string): string {
  const padded = input.replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(padded, "base64").toString("utf8");
}

/**
 * 凭据登录的"冷静期"参数。
 *
 * ★ 为什么失败计数要放在**会话存储**里,而不是网关的某个 Map 里:
 *   它与登录是同一件事的两半(失败几次 → 锁多久 → 什么时候解锁),
 *   分家之后就会出现"网关锁了、另一个入口没锁"这种两套账。
 *   这里只做**内存**计数(重启即清零),这是有意的:
 *   上机尝试的节流是"当下的滥用防护",不是需要永久留痕的事实 ——
 *   需要永久留痕的是每一次拒绝,它们已经进了审计哈希链。
 */
export const LOGIN_MAX_FAILURES = 5;
export const LOGIN_FAILURE_WINDOW_MS = 5 * 60 * 1000;
export const LOGIN_LOCK_MS = 5 * 60 * 1000;

/** 登录失败计数(仅内存;见上面为什么不需要持久化) */
interface LoginFailureState {
  count: number;
  firstAt: number;
  lockedUntil: number;
}

export class AuthSessionStore {
  private readonly dir: string;
  private readonly secret: string;
  private readonly ttl: number;
  private readonly clock: () => number;
  private readonly ephemeralSecret: boolean;
  private loaded = false;
  private readonly cache = new Map<string, AuthSession>();
  private writeQueue: Promise<unknown> = Promise.resolve();
  /** 客户号 → 失败计数(★ 客户号不存在也照样计数:否则"锁不存在的人"就成了账号枚举信号) */
  private readonly loginFailures = new Map<string, LoginFailureState>();

  constructor(options: {
    dir: string;
    /** 签名密钥。生产环境必须来自密钥管理;不传则本进程随机(重启即失效) */
    secret?: string;
    ttlMs?: number;
    now?: () => number;
  }) {
    this.dir = options.dir;
    const configured = options.secret ?? process.env["AUTH_SESSION_SECRET"];
    this.ephemeralSecret = !configured;
    this.secret = configured ?? randomBytes(32).toString("hex");
    this.ttl = options.ttlMs ?? AUTH_SESSION_TTL_MS;
    this.clock = options.now ?? (() => Date.now());
  }

  /** 是否使用"进程内随机密钥"(重启后所有令牌失效)—— 启动时提示用 */
  get usingEphemeralSecret(): boolean {
    return this.ephemeralSecret;
  }

  /** 会话有效期(网关据此设置 Cookie 的 Max-Age,两侧必须同一个值) */
  get ttlMs(): number {
    return this.ttl;
  }

  private path(): string {
    return join(this.dir, "auth-sessions.json");
  }

  private async load(): Promise<void> {
    if (this.loaded) return;
    try {
      const raw = await readFile(this.path(), "utf8");
      const parsed = JSON.parse(raw) as Partial<AuthSessionFile>;
      for (const session of Array.isArray(parsed.sessions) ? parsed.sessions : []) {
        if (session?.sid) this.cache.set(session.sid, session);
      }
    } catch {
      // 文件不存在或损坏:从空开始(空 = 必须重新登录,这是安全方向)
    }
    this.loaded = true;
  }

  private persist(): Promise<void> {
    const run = async (): Promise<void> => {
      const target = this.path();
      await mkdir(dirname(target), { recursive: true });
      const file: AuthSessionFile = { version: 1, sessions: [...this.cache.values()] };
      const tmp = `${target}.tmp-${process.pid}`;
      await writeFile(tmp, JSON.stringify(file, null, 2), "utf8");
      await rename(tmp, target);
    };
    const next = this.writeQueue.then(run, run);
    this.writeQueue = next.catch(() => undefined);
    return next;
  }

  /** 清理过期/已吊销太久的上机会话,避免文件无限增长 */
  private trim(now: number): void {
    for (const [sid, session] of this.cache) {
      if (session.expiresAt < now - 24 * 3600 * 1000) this.cache.delete(sid);
    }
    const byCustomer = new Map<string, AuthSession[]>();
    for (const session of this.cache.values()) {
      const list = byCustomer.get(session.customerId) ?? [];
      list.push(session);
      byCustomer.set(session.customerId, list);
    }
    for (const list of byCustomer.values()) {
      if (list.length <= MAX_AUTH_SESSIONS) continue;
      for (const stale of list.sort((a, b) => a.lastSeenAt - b.lastSeenAt).slice(0, list.length - MAX_AUTH_SESSIONS)) {
        this.cache.delete(stale.sid);
      }
    }
  }

  /**
   * 签发一次上机会话。**这是身份诞生的唯一入口**。
   *
   * ★ 调用方必须已经把"上机的人确实是 customerId 这个人"验完(凭据登录或本机演示引导)。
   *   本方法只负责"把身份固定下来并签名",不负责判断该不该给。
   */
  async issue(input: {
    customerId: string;
    channel: Channel;
    kind: AuthSession["kind"];
    userAgent?: string;
    now?: number;
  }): Promise<{ session: AuthSession; token: string }> {
    await this.load();
    const now = input.now ?? this.clock();
    const session: AuthSession = {
      sid: `auth_${randomUUID()}`,
      customerId: input.customerId,
      channel: input.channel,
      kind: input.kind,
      issuedAt: now,
      expiresAt: now + this.ttl,
      lastSeenAt: now,
      csrfToken: randomBytes(16).toString("hex"),
      ...(input.userAgent ? { userAgent: input.userAgent.slice(0, 120) } : {}),
    };
    this.cache.set(session.sid, session);
    this.trim(now);
    await this.persist();
    return { session, token: this.sign(session) };
  }

  /**
   * 本机演示引导:为**默认演示身份**签发一次上机会话。
   *
   * ★ 为什么需要它,以及它的边界(如实说明):
   *   手机银行 App 这个渠道的前端在启动时没有任何"登录页",它直接开始对话。
   *   要满足"前端零改动也能跑通",服务端必须在首次请求时给一个身份 ——
   *   给的就是**这一个默认演示客户**,而不是"请求里说的那个客户"。
   *   跨客户访问(看别人的账单、动别人的钱)在这套设计里依然是不可能:
   *   要成为别的客户,只能走 login 并用那个客户的凭据。
   *   需要"连默认身份也要登录"的场景,把 AUTH_REQUIRE_LOGIN=1 打开,
   *   本方法就不会被网关调用(严格模式)。
   */
  async bootstrap(input: {
    customerId: string;
    channel: Channel;
    userAgent?: string;
    now?: number;
  }): Promise<{ session: AuthSession; token: string }> {
    return this.issue({ ...input, kind: "demo_bootstrap" });
  }

  /**
   * 凭据登录:签发一次 `kind: "login"` 的上机会话。
   *
   * ★ 与 bootstrap 的区别只有一处,但这一处就是全部:**凭据必须已经被验过**。
   *   调用方(index.ts 的 /api/auth/login)负责校验口令,本方法只负责签发 ——
   *   这样"谁能成为谁"的判定与"身份怎么固定下来"各自只有一处实现。
   */
  async login(input: {
    customerId: string;
    channel: Channel;
    userAgent?: string;
    now?: number;
  }): Promise<{ session: AuthSession; token: string }> {
    return this.issue({ ...input, kind: "login" });
  }

  /**
   * 该客户此刻是否还在登录冷静期内;返回剩余毫秒(0 = 可以尝试)。
   *
   * ★ 冷静期**必须先于凭据校验**判断:否则每一轮爆破都还会走一次口令比对,
   *   锁定就只是"少回一句话",没有真正降低尝试速率。
   */
  loginLockRemaining(customerId: string, now?: number): number {
    const at = now ?? this.clock();
    const state = this.loginFailures.get(customerId);
    if (!state) return 0;
    if (state.lockedUntil > at) return state.lockedUntil - at;
    // 冷静期已过,或失败窗口已过期 → 清计数,允许重新尝试
    if (state.lockedUntil > 0 || at - state.firstAt > LOGIN_FAILURE_WINDOW_MS) {
      this.loginFailures.delete(customerId);
    }
    return 0;
  }

  /**
   * 记一次登录失败;达到阈值即进入冷静期。
   *
   * ★ 阈值是"窗口内累计",不是"连续":攻击者穿插一次成功并不能清空计数
   *   (成功登录才会 clearLoginFailures)—— 这是防"打一下、登一下、再打"的节奏。
   */
  noteLoginFailure(customerId: string, now?: number): void {
    const at = now ?? this.clock();
    const state = this.loginFailures.get(customerId);
    if (!state || at - state.firstAt > LOGIN_FAILURE_WINDOW_MS) {
      this.loginFailures.set(customerId, { count: 1, firstAt: at, lockedUntil: 0 });
      this.trimLoginFailures();
      return;
    }
    state.count += 1;
    if (state.count >= LOGIN_MAX_FAILURES) {
      state.lockedUntil = at + LOGIN_LOCK_MS;
    }
  }

  /** 登录成功:清空该客户的失败计数(一次成功即恢复) */
  clearLoginFailures(customerId: string): void {
    this.loginFailures.delete(customerId);
  }

  /** 失败计数的内存上界(避免被海量随机客户号刷爆内存) */
  private trimLoginFailures(): void {
    if (this.loginFailures.size <= 500) return;
    for (const [key, state] of this.loginFailures) {
      if (this.loginFailures.size <= 250) break;
      if (state.lockedUntil === 0) this.loginFailures.delete(key);
    }
  }

  private sign(session: AuthSession): string {
    const payload: AuthTokenPayload = {
      sid: session.sid,
      cid: session.customerId,
      ch: session.channel,
      iat: session.issuedAt,
      exp: session.expiresAt,
    };
    const body = b64url(JSON.stringify(payload));
    const sig = createHmac("sha256", this.secret).update(`b1.${body}`).digest("hex");
    return `b1.${body}.${sig}`;
  }

  /**
   * 校验令牌 → 上机会话。
   *
   * 返回 null 的每一种情况都有明确含义(调用方据此落不同的审计事件):
   *   格式不合法 / 签名不符 → 伪造或损坏;过期 → 需要重新上机;
   *   记录不存在或已吊销 → 已登出或已被服务端撤销。
   */
  async verify(token: string | undefined, now?: number): Promise<AuthSession | null> {
    if (!token) return null;
    const parts = token.split(".");
    if (parts.length !== 3 || parts[0] !== "b1") return null;
    const [, body, sig] = parts;
    const expected = createHmac("sha256", this.secret).update(`b1.${body}`).digest("hex");
    if (!safeEqualHex(expected, sig!)) return null;

    let payload: AuthTokenPayload;
    try {
      payload = JSON.parse(unb64url(body!)) as AuthTokenPayload;
    } catch {
      return null;
    }
    if (!payload?.sid) return null;

    await this.load();
    const session = this.cache.get(payload.sid);
    if (!session) return null;
    // ★ 令牌里的 customerId 只用于交叉核对,身份以**服务端记录**为准
    if (session.customerId !== payload.cid) return null;
    const at = now ?? this.clock();
    if (session.revokedAt != null) return null;
    if (session.expiresAt <= at) return null;
    if (payload.exp !== session.expiresAt) return null;

    const previous = session.lastSeenAt;
    session.lastSeenAt = Math.max(previous, at);
    // 落盘节流:同一会话 60 秒内不重复写盘(lastSeenAt 只是活跃度统计)
    if (session.lastSeenAt - previous > 60_000) await this.persist();
    return session;
  }

  /** 登出:服务端撤销(不是"让客户端自己把 Cookie 删掉") */
  async revoke(sid: string, now?: number): Promise<boolean> {
    await this.load();
    const session = this.cache.get(sid);
    if (!session) return false;
    session.revokedAt = now ?? this.clock();
    await this.persist();
    return true;
  }

  /** 某客户当前有效的上机会话(审计与"在哪些设备上登录着"用) */
  async list(customerId: string, now?: number): Promise<AuthSession[]> {
    await this.load();
    const at = now ?? this.clock();
    return [...this.cache.values()]
      .filter((s) => s.customerId === customerId && s.revokedAt == null && s.expiresAt > at)
      .sort((a, b) => b.issuedAt - a.issuedAt);
  }

  /** 测试/演示辅助:清空全部上机会话(等价于"所有人都要重新上机") */
  async clearAll(): Promise<number> {
    await this.load();
    const count = this.cache.size;
    this.cache.clear();
    await this.persist();
    return count;
  }
}

function safeEqualHex(a: string, b: string): boolean {
  const left = Buffer.from(a, "utf8");
  const right = Buffer.from(b, "utf8");
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

/** 解析 Cookie 头(split 语义与浏览器一致:同名取第一个) */
export function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    const name = part.slice(0, eq).trim();
    if (!name || out[name] != null) continue;
    out[name] = decodeURIComponent(part.slice(eq + 1).trim());
  }
  return out;
}

/**
 * 组装会话 Cookie。
 *
 * ★ 三个属性各有明确职责,不是抄模板:
 *   · HttpOnly  —— JS 读不到,于是 XSS 也偷不走令牌;
 *   · SameSite=Strict —— 跨站请求根本不会带上它(CSRF 的第一层);
 *   · Path=/    —— 全站可用,但只在回环/本域。
 *   CSRF 的第二层是网关对 Origin 的白名单校验(见 index.ts)—— 因为
 *   "同站不同端口"(localhost:3000 → 127.0.0.1:8787)不算跨站,SameSite 管不到。
 */
export function buildCookie(
  name: string,
  value: string,
  options: { maxAgeMs?: number; httpOnly?: boolean; clear?: boolean } = {},
): string {
  const parts = [`${name}=${encodeURIComponent(value)}`, "Path=/", "SameSite=Strict"];
  if (options.httpOnly !== false) parts.push("HttpOnly");
  if (options.clear) {
    parts.push("Max-Age=0");
  } else if (options.maxAgeMs != null) {
    parts.push(`Max-Age=${Math.floor(options.maxAgeMs / 1000)}`);
  }
  return parts.join("; ");
}
