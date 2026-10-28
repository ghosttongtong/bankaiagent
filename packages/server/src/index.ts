/**
 * 渠道网关(Channel Gateway)
 *
 * ★ 设计要点:这是**所有渠道的唯一入口**。
 *   APP、IM、Web、语音都通过同一套消息信封进入,共享同一个 Agent 核心。
 *   核心逻辑里没有一行 `if (channel === 'im')` —— 渠道差异只体现在
 *   ChannelCapabilities 这张**数据表**里(见 app.ts 的 CHANNEL_CAPABILITIES)。
 *
 *   这就是"多渠道同源":新增一个渠道 = 新增一个适配器 + 一行能力表配置,
 *   而不是复制一遍业务逻辑。
 *
 * ★ 移动端 App 入口(`GET /`):
 *   public/ 下那个页面走的就是同一个 `app` 渠道 —— 它不是一个"为演示特制"的通道,
 *   而是**手机银行 App 这个渠道的真实前端**。这一点很重要:
 *   演示界面里看到的每一条裁决、每一张卡、每一次确认,
 *   与 IM/语音渠道进来的同一条消息走的是**同一段代码**。
 *
 * ★ 身份边界(本次修补的核心):
 *   网关是"谁在调用"的唯一判定处。**身份一律取自服务端签发的会话令牌**,
 *   请求体/查询串里的 `customerId` 只用于**交叉核对** —— 不一致即拒绝并落审计。
 *   这条边界放在网关而不是中间件里,因为"客户是谁"必须只有一个出处:
 *   一旦某个路由还能从 body 里取 customerId,横向越权就在那条路由上复活。
 *
 * 端点:
 *   GET  /                                 移动端 App 入口(模拟手机银行聊天界面)
 *   POST /api/auth/login                   凭据登录 → 签发会话令牌(HttpOnly Cookie)
 *   POST /api/auth/logout                  登出(服务端撤销会话)
 *   GET  /api/auth/whoami                  当前会话身份(客户可自查"我是谁")
 *   POST /api/channels/:channel/messages   入站消息(文本)
 *   POST /api/channels/:channel/actions    入站结构化动作(确认/取消/选择)
 *   GET  /api/audit/recent                 审计事件(按当前身份过滤)
 *   GET  /api/audit/verify                 哈希链完整性校验
 *   GET  /api/demo/profile                 客户、账户与卡片概况
 *   GET  /api/demo/pending                 当前待确认动作
 *   POST /api/demo/sign-auth-proof         签发强验证回执(仅演示;只签本会话身份名下未执行的待办)
 *   GET  /api/health                       健康检查(唯一免鉴权端点)
 */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { extname, join, normalize, resolve as resolvePath } from "node:path";
import { fileURLToPath } from "node:url";

import type { AuditEvent, CancellationState, Channel, MessageEnvelope } from "../../core/src/index.ts";
import { toPendingActionView } from "../../core/src/agent/orchestrator.ts";
import { flowFamilyOf } from "../../core/src/agent/flowTrace.ts";
import { OPERATION_STATUS_TONE } from "../../core/src/agent/operationStatus.ts";
import { fmtYuan } from "../../core/src/util/format.ts";
import { createApp, CHANNEL_CAPABILITIES, type App } from "./app.ts";
import { collapseBusinesses, type HistoryRecord } from "./personalization.ts";
import {
  AUTH_COOKIE,
  AUTH_CSRF_COOKIE,
  buildCookie,
  parseCookies,
  type AuthSession,
} from "./sessions.ts";

const VALID_CHANNELS: Channel[] = ["app", "im", "web", "voice"];

/**
 * ★ 网关的入口策略(在 startServer 里装配,按请求生效)。
 *
 * 为什么要把"谁能来、谁算谁"做成一张显式的表,而不是散在路由里:
 *   过去这两件事都是隐式的 —— CORS 是 `*`(谁都能来)、
 *   customerId 取自请求体(来的人说自己是就算是谁)。
 *   隐式的东西没法复核;写成表之后,"允许的来源"与"身份从哪来"都能被逐条读出来。
 */
interface GatewayPolicy {
  /** CORS 白名单(精确匹配 `scheme://host:port`)—— **不再有 `*`** */
  allowedOrigins: Set<string>;
  /**
   * 是否强制登录。
   *
   * ★ 默认 false 的理由:手机银行 App 渠道的前端在启动时没有登录页,
   *   它直接开始对话 —— 要满足"前端零改动也能跑通",首次请求必须能拿到
   *   **默认演示身份**的会话。默认身份只有一个(primaryCustomerId),
   *   想成为别的客户只能走 /api/auth/login 并用那个客户的凭据。
   *   设 AUTH_REQUIRE_LOGIN=1 即进入严格模式(连默认身份也要登录)。
   */
  requireLogin: boolean;
  /** 令牌 Cookie 的有效期(与 AuthSessionStore 的 ttl 一致,用于 Max-Age) */
  sessionTtlMs: number;
}

/** 已解析出来的"这次请求是谁" */
interface RequestIdentity {
  session: AuthSession;
  /** ★ 身份的唯一出处:下面所有路由用的都是它,不再看请求体 */
  customerId: string;
}

/** 身份解析失败的原因(每一种都对应一条可解释的审计事件) */
type IdentityFailure = { identity: null; reason: "no_session" | "invalid_session"; detail: string };

/**
 * 台账里的业务族名 —— 面向**客户**的那一个。
 *
 * ★ 为什么要在这里兜一次:台账里存的 `family` 可能是**内部能力名** ——
 *   要么这条记录写在补上族名之前,要么这个能力压根没登记族名
 *   (实测数据里 `human.handoff` 就是这样,历史列表整行显示成「human.handoff」)。
 *   本项目的底线是"界面上的每个字都应该是人话",所以读的时候就纠正,
 *   而不是等客户在历史列表里看到内部标识再来改。
 *
 * ★ 判据是"family 为空或等于能力名",不是"白名单已知族名":
 *   前者只会纠正坏值,不会覆盖上游将来新增的、更好的族名。
 */
function businessFamily(row: HistoryRecord): string {
  if (row.family && row.family !== row.capability) return row.family;
  return flowFamilyOf(row.capability).label;
}

/** 台账条目 → 面向界面的只读视图(★ 永不包含 pendingId:历史能看不能办) */
function toOperationView(row: HistoryRecord & { sessionId?: string }) {
  return {
    opId: row.opId ?? null,
    capability: row.capability,
    family: businessFamily(row),
    status: row.status ?? "inquiry",
    statusLabel: row.statusLabel ?? "仅查询",
    tone: OPERATION_STATUS_TONE[row.status ?? "inquiry"],
    ...(row.amount != null ? { amount: row.amount } : {}),
    ...(row.subject ? { subject: row.subject } : {}),
    ...(row.reference ? { reference: row.reference } : {}),
    ...(row.detail ? { detail: row.detail } : {}),
    createdAt: row.createdAt ?? row.ts,
    ...(row.traceId ? { traceId: row.traceId } : {}),
    ...(row.sessionId ? { sessionId: row.sessionId } : {}),
  };
}

/** 列表副行:`¥500.00 · 流水号 …7C2A`(只用台账里真实存在的字段,不猜) */
function summarizeOperations(rows: Array<HistoryRecord & { sessionId?: string }>): string {
  const last = rows[0];
  if (!last) return "";
  const parts: string[] = [];
  if (typeof last.amount === "number") {
    parts.push(fmtYuan(last.amount));
  }
  if (last.reference) parts.push(`流水号 …${last.reference.slice(-4)}`);
  if (parts.length === 0 && last.subject) parts.push(last.subject);
  return parts.join(" · ");
}

// ============================================================================
// 请求/响应类型
// ============================================================================

interface MessageRequestBody {
  /**
   * ★ 这个字段**不参与身份判定**,只用于交叉核对。
   *
   *   身份一律取自会话令牌(见 resolveIdentity)。仍然保留这个字段是有意的:
   *   客户端如果声称自己是另一个人,服务端要能**看见这个声称并拒绝**,
   *   而不是把它悄悄丢掉 —— 被拒绝的越权请求本身就是审计证据。
   */
  customerId?: string;
  channelUserId?: string;
  sessionId?: string;
  text: string;
  /** ★ 渠道业务流水号:重试时带同一个值才会命中幂等(见 app.envelope 的说明) */
  messageId?: string;
  /**
   * ★ 上游中止意图(第 3 项:节点内中断)。
   *
   *   什么场景会带它:客户端在等待时按下了「取消」、网关判定这次调用即将超时、
   *   或运维要求停止这一批 —— 中止意图**必须随请求进来**,因为提交点是在
   *   银行核心那一侧读的,只有请求进来时它才可能早于 commit。
   *
   *   ★ 为什么这个字段不构成新的攻击面:它只能**阻止**资金动作
   *   (提交点之前中止 = 什么都不发生),永远不能促成任何一笔操作。
   *   最坏情况是调用者取消自己的请求 —— 那是他自己的事。
   *   ★ 也正因为如此,它必须是**只读数据快照**:不是 AbortSignal、不是命令,
   *   只有 mock.ts 的提交边界会读它。
   */
  cancel?: { requested?: boolean; reason?: string; source?: string };
}

/**
 * 把请求体里的中止意图收窄成可信的 CancellationState(第 3 项)。
 *
 * ★ 三条收窄规则,每一条都有理由:
 *   ① `requested` 必须是布尔真值 —— 缺省/假值一律当作"没有中止意图",
 *      否则一个笔误的字段就会让客户的正常操作全部落空;
 *   ② `source` 只认三个枚举值,其余归一到 "user"(它是**分类标签**,
 *      进审计后要能用来统计"谁发起的中止",不能是自由文本);
 *   ③ `reason` 截断到 120 字并去掉控制字符 —— 它会原样落进审计链
 *      (`execution_cancelled.payload.reason`),不限长就是把审计链的
 *      体积控制权交给调用方(和自由文本注入)。
 *   `at` 一律用**服务端时间**:客户端的时钟既不可信,也不该进哈希链。
 */
function readCancellation(raw: MessageRequestBody["cancel"]): CancellationState | undefined {
  if (!raw || raw.requested !== true) return undefined;
  const source =
    raw.source === "timeout" || raw.source === "operator" || raw.source === "user" ? raw.source : "user";
  const cleaned = typeof raw.reason === "string" ? raw.reason.replace(/[\u0000-\u001f\u007f]/g, "").trim() : "";
  return {
    requested: true,
    reason: cleaned.length > 0 ? cleaned.slice(0, 120) : "上游要求中止本次操作",
    at: Date.now(),
    source,
  };
}

interface ActionRequestBody {
  /** 同 MessageRequestBody.customerId:只用于交叉核对,不参与身份判定 */
  customerId?: string;
  sessionId?: string;
  action: {
    kind: "confirm" | "cancel" | "select";
    refId?: string;
    value?: string;
    authProof?: unknown;
  };
}

// ============================================================================
// 服务
// ============================================================================

export interface ServerOptions {
  port?: number;
  offline?: boolean;
  auditDir?: string;
  /** 个性化数据目录(常用流程 + 台账);不传则用 var/personalization */
  personalizationDir?: string;
  /** 会话记录目录;不传则用 var/sessions */
  sessionsDir?: string;
  /** 额外的 CORS 白名单来源(如把页面挂在别的回环端口上时) */
  allowedOrigins?: string[];
}

export async function startServer(options: ServerOptions = {}): Promise<{
  app: App;
  close: () => Promise<void>;
  port: number;
}> {
  const app = await createApp({
    ...(options.offline != null ? { offline: options.offline } : {}),
    ...(options.auditDir ? { auditDir: options.auditDir } : {}),
    ...(options.personalizationDir ? { personalizationDir: options.personalizationDir } : {}),
    ...(options.sessionsDir ? { sessionsDir: options.sessionsDir } : {}),
  });

  const port = options.port ?? Number(process.env["PORT"] ?? 8787);

  // 串行化消息处理:演示环境下避免并发写审计链导致顺序混乱
  let queue: Promise<unknown> = Promise.resolve();
  const serialize = <T>(fn: () => Promise<T>): Promise<T> => {
    const next = queue.then(fn, fn);
    queue = next.catch(() => undefined);
    return next;
  };

  const server = createServer((req, res) => {
    const policy = policyRef.current;
    // ★ CORS 响应头在这里统一下发(白名单外的来源一个头也不给),
    //   这样连 500 兜底响应也不会漏掉 —— 头只发一次,路由里不再各写一遍。
    applyCorsHeaders(req, res, policy);
    handleRequest(req, res, app, serialize, policy).catch((err) => {
      sendJson(res, 500, { ok: false, error: (err as Error).message });
    });
  });

  // ★ 返回实际绑定端口:传 0 时由系统分配(验证脚本据此在任意空闲端口起服务,
  //   不必和别的会话抢 87xx),这是"不要用固定端口"这条经验的可执行版本。
  const boundPort = await new Promise<number>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => {
      const address = server.address();
      const actual = typeof address === "object" && address != null ? address.port : port;
      /**
       * ★ CORS 白名单在**开始监听之后、处理请求之前**就位:
       *   端口一确认,请求就可能进来。默认白名单里必须有 127.0.0.1 与 localhost ——
       *   客户就是在这两个地址上打开页面的;白名单用**实际绑定端口**,
       *   所以 PORT=0(测试用随机端口)也能工作。
       *   为什么不能用 `*`:演示服务器监听回环,而浏览器里任何一个网页都能跨端口
       *   访问回环服务 —— `*` 等于把"任意网页都能调用银行接口"合法化。
       */
      policyRef.current = {
        allowedOrigins: new Set<string>([
          `http://127.0.0.1:${actual}`,
          `http://localhost:${actual}`,
          ...(options.allowedOrigins ?? []),
          ...(process.env["ALLOWED_ORIGINS"] ?? "")
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean),
        ]),
        requireLogin: process.env["AUTH_REQUIRE_LOGIN"] === "1",
        sessionTtlMs: app.auth.ttlMs,
      };
      resolve(actual);
    });
  });

  return {
    app,
    port: boundPort,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}

/**
 * 入口策略的持有者。
 *
 * ★ 为什么用一个小盒子而不是模块级 `let` 直接赋值:
 *   `createServer` 的回调在 listen 之后才可能被触发,而白名单要用实际端口 ——
 *   端口只有 listen 回来才知道。盒子的**初值**刻意是"空名单 + 强制登录",
 *   也就是"最严"的一侧:万一有请求早于装配到达,它会被拒绝,而不是被放行。
 */
const policyRef: { current: GatewayPolicy } = {
  current: { allowedOrigins: new Set<string>(), requireLogin: true, sessionTtlMs: 0 },
};

// ============================================================================
// 路由
// ============================================================================

async function handleRequest(
  req: IncomingMessage,
  res: ServerResponse,
  app: App,
  serialize: <T>(fn: () => Promise<T>) => Promise<T>,
  policy: GatewayPolicy,
): Promise<void> {
  const url = new URL(req.url ?? "/", "http://127.0.0.1");
  const path = url.pathname;
  const method = req.method ?? "GET";

  // ==========================================================================
  // 0. 来源白名单(CORS)与预检
  //
  // ★ 这里不再是 `Access-Control-Allow-Origin: *`。
  //   白名单外的来源**直接拒绝并且落审计**,而不是"发个响应让浏览器自己拦"——
  //   后者对非浏览器调用者(脚本、被挂马的进程)完全无效,而现在这些调用
  //   不但会被拒,还会在哈希链里留下"某某来源试图调用过"的证据。
  // ==========================================================================
  const origin = typeof req.headers.origin === "string" ? req.headers.origin : undefined;
  const allowedOrigin = origin && policy.allowedOrigins.has(origin) ? origin : undefined;

  if (method === "OPTIONS") {
    if (origin && !allowedOrigin) {
      await auditGatewayDenial(app, {
        kind: "origin_not_allowed",
        path,
        claimed: origin,
        detail: `来源 ${origin} 不在 CORS 白名单内,预检被拒`,
        channel: parseChannelFromEvent(req) ?? "app",
      });
      sendJson(res, 403, { ok: false, error: "来源不在白名单内" });
      return;
    }
    res.writeHead(204, { "Content-Length": "0" });
    res.end();
    return;
  }

  if (origin && !allowedOrigin) {
    await auditGatewayDenial(app, {
      kind: "origin_not_allowed",
      path,
      claimed: origin,
      detail: `来源 ${origin} 不在 CORS 白名单内,拒绝该请求(白名单:${[...policy.allowedOrigins].join(", ")})`,
      channel: parseChannelFromEvent(req) ?? "app",
    });
    sendJson(res, 403, { ok: false, error: "来源不在白名单内,已拒绝并记录审计" });
    return;
  }

  // ---- 健康检查(唯一免鉴权的业务端点;只返回聚合状态,不含任何客户数据) ----
  if (method === "GET" && path === "/api/health") {
    const verification = await app.audit.verifyChain();
    sendJson(res, 200, {
      ok: true,
      model: { provider: app.llm.provider.name, model: app.llm.provider.model, mode: app.llm.mode },
      audit: { events: app.audit.size, chainIntact: verification.intact },
      channels: Object.keys(CHANNEL_LABELS),
      auth: { requireLogin: policy.requireLogin, sessionTtlMs: policy.sessionTtlMs },
    });
    return;
  }

  // ---- 移动端 App 入口(静态页面) ----
  //
  // ★ 静态资源**在鉴权之前**处理,这是有意的:
  //   `GET /` 与它的 css/js 是"还没有身份时"就要能拿到的东西 ——
  //   否则客户连页面都打不开,更谈不上登录。它们不含任何客户数据。
  //   路径必须归一化后再拼接(serveStatic 里做了两次校验),
  //   否则 `GET /../../etc/passwd` 这类穿越会读到 public/ 之外的文件。
  if (method === "GET" && !path.startsWith("/api/")) {
    const served = await serveStatic(res, path);
    if (served) return;
  }

  // ==========================================================================
  // 1. 鉴权端点(唯一能"成为别人"的入口)
  // ==========================================================================
  if (method === "POST" && path === "/api/auth/login") {
    const body = (await readJson<{ customerId?: string; password?: string; channel?: string }>(req)) ?? {};
    const claimedId = body.customerId?.trim();
    if (!claimedId || !body.password) {
      sendJson(res, 400, { ok: false, error: "缺少 customerId 或 password" });
      return;
    }
    const channel = parseChannel(body.channel ?? "app") ?? "app";

    const lockedFor = app.auth.loginLockRemaining(claimedId, app.now());
    if (lockedFor > 0) {
      await auditGatewayDenial(app, {
        kind: "login_locked",
        path,
        claimed: claimedId,
        detail: `连续登录失败过多,该客户仍在冷静期内(剩余 ${Math.ceil(lockedFor / 1000)} 秒)`,
        channel,
      });
      sendJson(res, 429, {
        ok: false,
        error: `登录失败次数过多,请 ${Math.ceil(lockedFor / 1000)} 秒后再试`,
      });
      return;
    }

    const verdict = await app.verifyCredential(claimedId, body.password);
    if (!verdict.ok) {
      app.auth.noteLoginFailure(claimedId, app.now());
      await auditGatewayDenial(app, {
        kind: "bad_credential",
        path,
        claimed: claimedId,
        detail: `凭据校验失败(${verdict.reason});未签发任何会话`,
        channel,
      });
      // ★ 不区分"客户不存在"与"口令错误":对外只有一句话,避免账号枚举
      sendJson(res, 401, { ok: false, error: "客户号或口令不正确" });
      return;
    }
    app.auth.clearLoginFailures(claimedId);
    const { session, token } = await app.auth.login({
      customerId: claimedId,
      channel,
      userAgent: req.headers["user-agent"],
    });
    setAuthCookies(res, token, session);
    await appendAudit(app, {
      type: "auth_session_issued",
      customerId: claimedId,
      sessionId: session.sid,
      channel,
      payload: {
        kind: "login",
        sid: session.sid,
        expiresAt: session.expiresAt,
        credential: verdict.kind,
        note: "身份由服务端签发;后续所有请求的 customerId 一律取自该会话,请求体里的 customerId 只用于核对",
      },
    });
    sendJson(res, 200, {
      ok: true,
      customerId: claimedId,
      displayName: verdict.displayName,
      session: { sid: session.sid, expiresAt: session.expiresAt, kind: "login" },
    });
    return;
  }

  if (method === "POST" && path === "/api/auth/logout") {
    const cookieToken = parseCookies(req.headers.cookie)[AUTH_COOKIE];
    const session = cookieToken ? await app.auth.verify(cookieToken, app.now()) : null;
    if (session) {
      await app.auth.revoke(session.sid, app.now());
      await appendAudit(app, {
        type: "auth_session_revoked",
        customerId: session.customerId,
        sessionId: session.sid,
        channel: session.channel,
        payload: { kind: "logout", sid: session.sid, reason: "客户主动登出" },
      });
    }
    clearAuthCookies(res);
    sendJson(res, 200, { ok: true, revoked: Boolean(session) });
    return;
  }

  // ==========================================================================
  // 2. 身份:一律取自令牌;令牌无效就拒绝(或在允许时引导默认演示身份)
  // ==========================================================================
  const resolved = await resolveIdentity(req, res, app, policy);
  if (!resolved.identity) {
    await auditGatewayDenial(app, {
      kind: resolved.reason,
      path,
      claimed: url.searchParams.get("customerId") ?? undefined,
      detail: resolved.detail,
      channel: parseChannelFromEvent(req) ?? "app",
    });
    sendJson(res, 401, {
      ok: false,
      error:
        resolved.reason === "no_session"
          ? "需要先登录(POST /api/auth/login)。演示环境默认允许以本机默认演示身份上机;设 AUTH_REQUIRE_LOGIN=1 可关闭该引导"
          : "会话令牌无效或已过期,请重新登录",
    });
    return;
  }
  const identity = resolved.identity;

  // ---- 写操作:CSRF 校验 ----
  //
  // ★ 三层,都不需要前端改一行:
  //   ① 会话 Cookie 是 SameSite=Strict —— 跨站请求根本带不上它;
  //   ② Origin 必须在白名单内(上面已做)—— "同站不同端口"不算跨站,
  //      所以 SameSite 管不到的那种情形由这一层兜住;
  //   ③ Sec-Fetch-Site: cross-site 一律拒绝(现代浏览器都会带这个头)。
  //   另外支持**可选的**双提交令牌:客户端若带了 X-CSRF-Token,就必须与本会话
  //   的 CSRF 令牌一致(带了不匹配 = 攻击者借用了别人的 Cookie 在伪造请求)。
  if (method === "POST") {
    const site = req.headers["sec-fetch-site"];
    if (typeof site === "string" && site === "cross-site") {
      await auditGatewayDenial(app, {
        kind: "csrf_rejected",
        path,
        customerId: identity.customerId,
        detail: "Sec-Fetch-Site: cross-site 的写操作被拒绝",
        channel: identity.session.channel,
      });
      sendJson(res, 403, { ok: false, error: "跨站写请求被拒绝" });
      return;
    }
    const csrfHeader = req.headers["x-csrf-token"];
    if (typeof csrfHeader === "string" && csrfHeader.length > 0) {
      const csrfCookie = parseCookies(req.headers.cookie)[AUTH_CSRF_COOKIE];
      if (!csrfCookie || csrfCookie !== csrfHeader || csrfHeader !== identity.session.csrfToken) {
        await auditGatewayDenial(app, {
          kind: "csrf_rejected",
          path,
          customerId: identity.customerId,
          detail: "X-CSRF-Token 与会话内的 CSRF 令牌不一致",
          channel: identity.session.channel,
        });
        sendJson(res, 403, { ok: false, error: "CSRF 校验失败" });
        return;
      }
    }
  }

  // ---- 请求体只读一次(POST;读流是破坏性的,所以只在这里读) ----
  const body: Record<string, unknown> =
    method === "POST" ? ((await readJson<Record<string, unknown>>(req)) ?? {}) : {};

  // ==========================================================================
  // 3. 交叉核对:请求里声明的 customerId 必须就是令牌里那个人
  //
  // ★ 这是本次修补的核心一条。注意方向:
  //   · 身份**只**来自令牌(下面所有路由用的都是 identity.customerId);
  //   · 请求体/查询串里的 customerId 只被用来**核对**,不一致即拒绝并落审计。
  //   只做前者不做后者,越权尝试会静默变成"看起来正常的一次访问"——
  //   那就失去了"系统确实拦过"的证据。
  // ==========================================================================
  const claims = collectCustomerClaims(url, body);
  const mismatch = claims.find((c) => c.value !== identity.customerId);
  if (mismatch) {
    await auditGatewayDenial(app, {
      kind: "cross_customer",
      path,
      claimed: mismatch.value,
      customerId: identity.customerId,
      detail: `请求声称的 customerId(${mismatch.value},来自${mismatch.from})与会话令牌里的身份(${identity.customerId})不一致,已拒绝`,
      channel: identity.session.channel,
      extra: { claimSource: mismatch.from, tokenCustomerId: identity.customerId },
    });
    sendJson(res, 403, {
      ok: false,
      error: "请求里的 customerId 与会话身份不一致,已拒绝并记录审计",
    });
    return;
  }

  // ---- 身份端点:客户自查"我现在是谁" ----
  if (method === "GET" && path === "/api/auth/whoami") {
    sendJson(res, 200, {
      ok: true,
      customerId: identity.customerId,
      displayName: identity.customerId === app.world.primaryCustomerId ? "张先生" : "赵女士",
      session: {
        sid: identity.session.sid,
        kind: identity.session.kind,
        channel: identity.session.channel,
        issuedAt: identity.session.issuedAt,
        expiresAt: identity.session.expiresAt,
      },
      customerIdSource: "session_token",
    });
    return;
  }

  // ---- 审计事件(只读,按身份过滤:审计面板看的是**自己的**证据链) ----
  if (method === "GET" && path === "/api/audit/recent") {
    const limit = Math.min(Number(url.searchParams.get("limit") ?? 50), 500);
    const traceId = url.searchParams.get("traceId");
    const events = traceId ? await app.audit.read(traceId) : await app.audit.readAll();
    /**
     * ★ 为什么审计面板也要按身份过滤:
     *   事件里带着别人的客户号、金额与对手方。客户能读到的证据链只应是自己那一条;
     *   链的完整性校验(/api/audit/verify)是聚合结论,不泄露内容,所以仍可全局调用。
     */
    const mine = events.filter((e) => e.customerId === identity.customerId);
    sendJson(res, 200, {
      ok: true,
      count: mine.length,
      scope: "own_customer",
      customerId: identity.customerId,
      events: mine.slice(-limit).map(toAuditView),
    });
    return;
  }

  if (method === "GET" && path === "/api/audit/verify") {
    const verification = await app.audit.verifyChain();
    sendJson(res, 200, { ok: true, ...verification, total: app.audit.size });
    return;
  }

  // ---- 入站消息 ----
  const messageMatch = path.match(/^\/api\/channels\/([a-z]+)\/messages$/);
  if (method === "POST" && messageMatch) {
    const channel = parseChannel(messageMatch[1]!);
    if (!channel) {
      sendJson(res, 400, { ok: false, error: `不支持的渠道:${messageMatch[1]}` });
      return;
    }

    const messageBody = body as unknown as MessageRequestBody;
    if (!messageBody.text) {
      sendJson(res, 400, { ok: false, error: "缺少 text 字段" });
      return;
    }

    const cancellation = readCancellation(messageBody.cancel);
    const envelope = app.envelope({
      channel,
      text: messageBody.text,
      // ★ 身份来自令牌,不再看请求体里的 customerId
      customerId: identity.customerId,
      ...(messageBody.sessionId ? { sessionId: messageBody.sessionId } : {}),
      ...(messageBody.channelUserId ? { channelUserId: messageBody.channelUserId } : {}),
      // ★ 渠道业务流水号透传:重试带同一个值 → 幂等键相同 → 不会重复出账
      ...(messageBody.messageId ? { messageId: messageBody.messageId } : {}),
      // ★ 上游中止意图透传(第 3 项):只可能在提交点之前生效,见 readCancellation
      ...(cancellation ? { cancellation } : {}),
    });

    const result = await serialize(() => app.orchestrator.handleMessage(envelope));
    sendJson(res, 200, { ok: true, turn: toTurnView(result, envelope) });
    return;
  }

  // ---- 入站结构化动作 ----
  const actionMatch = path.match(/^\/api\/channels\/([a-z]+)\/actions$/);
  if (method === "POST" && actionMatch) {
    const channel = parseChannel(actionMatch[1]!);
    if (!channel) {
      sendJson(res, 400, { ok: false, error: `不支持的渠道:${actionMatch[1]}` });
      return;
    }

    const actionBody = body as unknown as ActionRequestBody;
    if (!actionBody?.action?.kind) {
      sendJson(res, 400, { ok: false, error: "缺少 action 字段" });
      return;
    }

    const baseEnvelope = app.envelope({
      channel,
      text: "",
      customerId: identity.customerId,
      ...(actionBody.sessionId ? { sessionId: actionBody.sessionId } : {}),
    });

    const result = await serialize(() =>
      app.orchestrator.submitChannelAction({
        envelope: baseEnvelope,
        action: {
          kind: actionBody.action.kind,
          ...(actionBody.action.refId ? { refId: actionBody.action.refId } : {}),
          ...(actionBody.action.value ? { value: actionBody.action.value } : {}),
          ...(actionBody.action.authProof ? { authProof: actionBody.action.authProof as never } : {}),
        },
      }),
    );

    sendJson(res, 200, { ok: true, turn: toTurnView(result, baseEnvelope) });
    return;
  }

  // ---- 演示辅助:签发强验证回执(仅演示用,生产环境由安全环境签发) ----
  //
  // ★ 这个端点曾经是一个**通用签名预言机**:给任意 payloadHash 就回一份签名合法的回执,
  //   而 CORS 是 `*`、没有任何鉴权 —— 于是任何能访问回环端口的调用者(包括浏览器里
  //   任意网页)都能"发起一笔红色档操作 → 取 payloadHash → 换真回执 → 执行",
  //   强验证这道闸门在交付物里等于不存在;文档却写着"即使 Agent 被完全攻破也无法伪造回执"。
  //
  //   上一版把语义收窄为"只为本进程确实产生过、且尚未执行的待办签发"。
  //   本次再补上另一半 —— **归属**:回执只签给"令牌里那个人自己的"待办。
  //   否则任何拿到会话的人仍然可以拿别人的 payloadHash 换一份合法回执,
  //   再配合越权确认去动别人的钱。与"回执绑定载荷哈希"同源:
  //   签发对象必须由服务端**主动认定**,客户端提交的哈希只能用来**核对**,
  //   不能用来**指定要签哪一笔**。
  if (method === "POST" && path === "/api/demo/sign-auth-proof") {
    const signBody = body as unknown as { method?: string; payloadHash?: string; refId?: string };
    const now = app.now();

    /**
     * 目标由服务端认定,顺序固定:
     *   ① 给了 refId → 就签那一笔(必须是**本会话身份**的待办);
     *   ② 只给 payloadHash → 该哈希必须是**本会话身份名下**、尚未执行的待办;
     *   ③ 都没给 → 签本会话身份当前最新的一笔待办(这就是"当前 pending 动作")。
     */
    const byRef = signBody.refId ? app.orchestrator.pending.get(signBody.refId) : undefined;
    const byHash = signBody.payloadHash
      ? app.orchestrator.pending.findByPayloadHash(signBody.payloadHash, now)
      : undefined;
    const target =
      byRef ??
      byHash ??
      app.orchestrator.pending.latestForSession(identity.customerId, identity.session.sid, now) ??
      app.orchestrator.pending.latestFor(identity.customerId, now);

    if (!target || target.expiresAt <= now) {
      await auditGatewayDenial(app, {
        kind: "sign_proof_target_missing",
        path,
        claimed: signBody.refId ?? signBody.payloadHash,
        customerId: identity.customerId,
        detail: "该载荷/待办没有对应的、尚未执行的待确认动作,拒绝签发回执",
        channel: identity.session.channel,
        extra: { refId: signBody.refId ?? null, payloadHash: signBody.payloadHash ?? null },
      });
      sendJson(res, 403, {
        ok: false,
        error: "该载荷没有对应的待确认动作(可能已执行、已过期,或根本不是本进程发起的操作),拒绝签发回执",
      });
      return;
    }

    // ★ 归属校验:别人的待办,一份也不签
    if (target.customerId !== identity.customerId) {
      await auditGatewayDenial(app, {
        kind: "sign_proof_not_owner",
        path,
        claimed: target.customerId,
        customerId: identity.customerId,
        detail: `待办 ${target.pendingId} 属于 ${target.customerId},与当前会话身份 ${identity.customerId} 不一致,拒绝签发回执`,
        channel: identity.session.channel,
        extra: { pendingId: target.pendingId, ownerCustomerId: target.customerId },
      });
      sendJson(res, 403, { ok: false, error: "该待确认动作不属于当前登录客户,拒绝签发回执" });
      return;
    }

    // ★ 客户端提交的哈希/refId 只能是**核对条件**,不能改变签发对象
    if (signBody.payloadHash && signBody.payloadHash !== target.payloadHash) {
      await auditGatewayDenial(app, {
        kind: "sign_proof_hash_mismatch",
        path,
        claimed: signBody.payloadHash,
        customerId: identity.customerId,
        detail: "提交的 payloadHash 与服务端认定的待确认动作不一致(可能是已过期或被替换的载荷),拒绝签发回执",
        channel: identity.session.channel,
        extra: { pendingId: target.pendingId, expected: target.payloadHash },
      });
      sendJson(res, 409, { ok: false, error: "payloadHash 与服务端当前待确认动作不一致,拒绝签发回执" });
      return;
    }
    if (signBody.refId && signBody.refId !== target.pendingId) {
      await auditGatewayDenial(app, {
        kind: "sign_proof_ref_mismatch",
        path,
        claimed: signBody.refId,
        customerId: identity.customerId,
        detail: "refId 与 payloadHash 指向的不是同一个待确认动作,拒绝签发回执",
        channel: identity.session.channel,
      });
      sendJson(res, 409, {
        ok: false,
        error: "refId 与 payloadHash 指向的不是同一个待确认动作,拒绝签发回执",
      });
      return;
    }

    const { signAuthProof } = await import("./app.ts");
    const proof = signAuthProof({
      method: (signBody.method as "biometric") ?? "biometric",
      boundPayloadHash: target.payloadHash,
      now,
    });
    await appendAudit(app, {
      type: "strong_auth_requested",
      customerId: identity.customerId,
      sessionId: target.sessionId,
      channel: identity.session.channel,
      payload: {
        capability: target.capability,
        pendingId: target.pendingId,
        issuedBy: "demo-endpoint",
        source: "demo-secure-enclave",
        note: "回执只为本会话身份名下、尚未执行的待确认动作签发(payloadHash 仅作核对)",
      },
    });
    sendJson(res, 200, {
      ok: true,
      proof,
      pendingId: target.pendingId,
      warning: "此端点仅用于演示,生产环境由安全环境签发回执;且只为本会话身份名下未执行的待办签发",
    });
    return;
  }

  // ---- 演示辅助:查看待确认动作(供前端拿到 payloadHash 用于演示强验证) ----
  if (method === "GET" && path === "/api/demo/pending") {
    const customerId = identity.customerId;
    const refId = url.searchParams.get("refId");
    /**
     * ★ 支持按 refId 精确取,而不是永远取"最新那一条"。
     *
     *   为什么要这么改:验证弹层过去一律签"当前最新的待确认动作"的载荷。
     *   如果用户先点了一次"完成身份验证",接着又发起了另一笔业务,
     *   再点旧那条消息上的验证按钮,签的就会是**另一笔**业务的载荷 ——
     *   界面在办 A,服务端盖的是 B 的章。按 refId 取,按钮与操作永远一一对应。
     *
     *   取不到就如实返回 null(已经办完或已过期),让界面提示"这笔处理过了",
     *   而不是悄悄改签最新那一笔。
     */
    const candidate = refId
      ? app.orchestrator.pending.get(refId)
      : app.orchestrator.pending.latestFor(customerId, app.now());
    const pending =
      candidate && candidate.customerId === customerId && candidate.expiresAt > app.now()
        ? candidate
        : undefined;
    /**
     * ★ 返回的是**面向界面**的视图(人话摘要 + 已剥离 `__` 内部字段的冻结载荷)。
     *
     *   为什么要连摘要一起给:一个未决的待确认动作会**挡住客户的下一个请求** ——
     *   用户接着说「我要转给房东」时,界面只回一句「你还有一个操作在等确认」,
     *   他是不知道自己上一次到底冻结了什么内容的,于是既不敢确认、也不知道该取消什么。
     *   界面只有拿到这份摘要,才能把那张卡**重新画出来**并给出确认/取消按钮。
     */
    sendJson(res, 200, {
      ok: true,
      pending: pending
        ? {
            ...toPendingActionView({
              pendingId: pending.pendingId,
              capability: pending.capability,
              requiredTier: pending.requiredTier,
              payloadHash: pending.payloadHash,
              input: pending.input,
            }),
            createdAt: pending.createdAt,
            expiresAt: pending.expiresAt,
            fraudLevel: pending.fraudLevel,
            authSpec: pending.authSpec ?? null,
          }
        : null,
    });
    return;
  }

  // ==========================================================================
  // 会话与台账(只读)—— 31 文档 §5
  //
  // ★ 这组接口的定位是「能看不能办」:
  //   历史上能查一切,但不能从历史里"顺手办掉"任何东西。
  //   因此:① 不返回 pendingId(界面即使被改也没有可确认的对象);
  //        ② 只有 GET,没有任何"从这里确认/取消"的入口 ——
  //           跨会话确认由编排器的 G2 硬门禁拦着,这里是第一层。
  //
  // ★ 本次修补补充:这组接口的 customerId **只能**来自会话令牌。
  //   它们是最容易被拿来横向越权的一类(纯查询、参数直观),
  //   所以"身份从哪来"必须与其他接口完全一致 —— 一处例外就是一个洞。
  // ==========================================================================

  // ---- 会话列表(倒序)----
  if (method === "GET" && path === "/api/sessions") {
    const customerId = identity.customerId;
    const current = url.searchParams.get("current");
    const limitRaw = Number(url.searchParams.get("limit") ?? 50);
    const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.min(limitRaw, 50) : 50;

    const [records, ledger] = await Promise.all([
      app.sessions.list(customerId),
      app.personalization.ledger(customerId),
    ]);
    const sessions = records.slice(0, limit).map((s) => {
      // ledger() 已按时间倒序;取该会话的操作,第一条就是最近一笔
      const ops = ledger.filter((row) => row.sessionId === s.sessionId);
      return {
        sessionId: s.sessionId,
        startedAt: s.startedAt,
        lastAt: s.lastAt,
        title: s.title,
        status: s.status,
        statusLabel: s.statusLabel,
        tone: OPERATION_STATUS_TONE[s.status],
        opCount: s.operationIds.length,
        summary: summarizeOperations(ops),
        isCurrent: current != null && current === s.sessionId,
      };
    });

    sendJson(res, 200, { ok: true, customerId, sessions });
    return;
  }

  // ---- 会话详情(只读回放 + 该会话的操作)----
  const sessionMatch = path.match(/^\/api\/sessions\/([^/]+)$/);
  if (method === "GET" && sessionMatch) {
    const customerId = identity.customerId;
    const sessionId = decodeURIComponent(sessionMatch[1]!);
    const record = await app.sessions.get(customerId, sessionId);
    if (!record) {
      sendJson(res, 404, { ok: false, error: "没有找到这个会话(可能已超过保留期)" });
      return;
    }
    const ledger = await app.personalization.ledger(customerId);
    const ops = ledger.filter((row) => row.sessionId === sessionId);

    sendJson(res, 200, {
      ok: true,
      session: {
        sessionId: record.sessionId,
        title: record.title,
        status: record.status,
        statusLabel: record.statusLabel,
        tone: OPERATION_STATUS_TONE[record.status],
        startedAt: record.startedAt,
        lastAt: record.lastAt,
        /**
         * ★ 两个刻意写死的只读标记(而不是让前端自己"别渲染按钮"):
         *   · readonly: true —— 语义交给服务端给,前端不做判断(红线 #8);
         *   · operations 里没有 pendingId —— 即使前端被改,也没有可确认的对象。
         */
        readonly: true,
        turns: record.turns.map((t) => ({
          ts: t.ts,
          role: t.role,
          text: t.text,
          ...(t.cardTitle ? { cardTitle: t.cardTitle } : {}),
          ...(t.promptKind ? { promptKind: t.promptKind } : {}),
          traceId: t.traceId,
        })),
        operations: ops.map(toOperationView),
        /**
         * ★ 同一批台账的两种读法,口径不同、用途不同:
         *   · operations:事件流水(一步一行)—— 一笔转账会有「待你确认」+「已转账成功」两行;
         *   · businesses:一笔业务一行(折叠后)—— 界面上的"这次对话办了几件事"用它。
         *   客户点进来找的是"我那一笔",所以详情页的业务清单一律读 businesses;
         *   operations 保留原样,谁要追溯确认过程都还能查到,不丢信息。
         */
        businesses: collapseBusinesses(ops).map(toOperationView),
      },
    });
    return;
  }

  // ---- 台账列表(跨会话,**业务粒度**)----
  //
  // ★ 这是历史列表的数据源:一行一笔业务(opId),不是一个会话一行。
  //
  //   为什么必须按业务而不是按会话列出(客户已确认的改动):
  //   一次对话里可以办好几件事 —— 同一天在同一个标签页转账、挂失、提额,
  //   前端只有一个 sessionId。若列表按会话聚合,第 2 笔起就"看不见"了:
  //   标题只认第一笔,状态是全会话的聚合(一笔"已提交待审核"会盖住另一笔
  //   "已转账成功")。客户要找的是**那一笔**,所以列表的行必须是那一笔本身。
  //
  //   会话仍然是**回放的容器**:每行带 sessionId,点进去看所属对话的原话与卡片。
  //   两个粒度各司其职,不互相替代:
  //     · 业务粒度(opId)→ "我办了哪几件、各办到哪一步";
  //     · 会话粒度(sessionId)→ "那次对话说了什么、能不能再办一次"。
  if (method === "GET" && path === "/api/ledger/recent") {
    const customerId = identity.customerId;
    /** 前端把自己当前的 sessionId 传上来,用于标出"本次对话办的" */
    const current = url.searchParams.get("current");
    const limitRaw = Number(url.searchParams.get("limit") ?? 20);
    const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.min(limitRaw, 100) : 20;

    const [ledger, records] = await Promise.all([
      // ★ 用**业务台账**(一笔业务一行),不是 ledger() 的事件流水:
      //   事件流水里一笔转账是两行(「待你确认」+「已转账成功」),
      //   直接铺出去客户会以为同一笔钱转了两回。
      app.personalization.businessLedger(customerId),
      app.sessions.list(customerId),
    ]);
    /**
     * sessionId → 会话。
     *
     * ★ 只用来回答一个问题:"这一笔所属的对话还在不在保留期内"。
     *   在,则这一行可点开回放;不在(超过 30 天 / 被容量裁剪),也要能点 ——
     *   那时前端走单条台账详情,而不是给客户一个点不动的行。
     *   会话的标题与时间不在这里回传:列表要的是"这一笔是什么",
     *   那次对话的标题与起始时间属于详情页(§5.2)。
     */
    const knownSessions = new Set(records.map((s) => s.sessionId));

    sendJson(res, 200, {
      ok: true,
      customerId,
      operations: ledger.slice(0, limit).map((row) => ({
        ...toOperationView(row),
        // ★ 状态只代表这一笔,不与同会话的其它业务做优先级聚合
        isCurrent: current != null && row.sessionId === current,
        hasSession: Boolean(row.sessionId) && knownSessions.has(row.sessionId!),
      })),
    });
    return;
  }

  // ---- 单条操作 ----
  const ledgerMatch = path.match(/^\/api\/ledger\/([^/]+)$/);
  if (method === "GET" && ledgerMatch) {
    const customerId = identity.customerId;
    const opId = decodeURIComponent(ledgerMatch[1]!);
    const entry = await app.personalization.getLedgerEntry(customerId, opId);
    if (!entry) {
      sendJson(res, 404, { ok: false, error: "没有找到这条操作记录" });
      return;
    }
    sendJson(res, 200, { ok: true, operation: toOperationView(entry) });
    return;
  }

  // ---- 个性化:常用流程 + 历史业务 + 智能建议(首页"常用服务"的数据来源) ----
  if (method === "GET" && path === "/api/personalization") {
    const customerId = identity.customerId;
    const view = await app.personalizationView(customerId);
    sendJson(res, 200, {
      ok: true,
      customerId,
      flows: view.flows.map((f) => ({
        templateId: f.templateId,
        name: f.name,
        capability: f.capability,
        say: f.say,
        params: f.params,
        fixed: f.fixed,
        useCount: f.useCount,
        lastUsedAt: f.lastUsedAt ?? null,
        createdAt: f.createdAt,
      })),
      history: view.history,
      suggestions: view.suggestions,
    });
    return;
  }

  // ---- 把常用流程实例化成一句可直接发送的话 ----
  if (method === "POST" && path === "/api/flows/instantiate") {
    const flowBody = body as unknown as { templateId?: string; values?: Record<string, string> };
    if (!flowBody.templateId) {
      sendJson(res, 400, { ok: false, error: "缺少 templateId" });
      return;
    }
    const customerId = identity.customerId;
    const flows = await app.listFlows(customerId);
    const flow = flows.find((f) => f.templateId === flowBody.templateId);
    if (!flow) {
      sendJson(res, 404, { ok: false, error: "这条常用流程不存在(可能已被删除)" });
      return;
    }
    // ★ 点开入口 = 准备用一次。把使用次数记上,常用服务的排序与"闲置提醒"才准。
    await app.personalization.touchFlow(customerId, flow.templateId, app.now());
    const { instantiateTemplate } = await import("../../core/src/agent/flowTrace.ts");
    sendJson(res, 200, { ok: true, text: instantiateTemplate(flow, flowBody.values ?? {}) });
    return;
  }

  /**
   * 保存常用流程。
   *
   * ★ 服务端重新派生模板,而不是照单全收前端传来的模板。
   *   如果允许前端直接写模板(含能力名与固定字段),那"常用流程"就成了一条
   *   绕过服务端的写入口 —— 前端可以塞进任意能力与参数。
   *   这里只接受"哪一次办理",由服务端按**与自动保存同一个**派生逻辑生成模板。
   *
   * ★ 为什么必须与自动保存共用实现:资金类操作跨两轮,
   *   "执行那一轮"的审计事件里没有确认卡 —— 各写一遍必然漏掉一边。
   *   实测:手动保存曾经存下一条空壳模板(`给 {收款人} 转 {金额} 元`,无对象无金额),
   *   而且按 templateId 覆盖掉了自动保存那条好的。
   *
   * ★ 本次修补:写操作的 customerId 同样只来自令牌(不再读请求体里的字段)。
   */
  if (method === "POST" && path === "/api/flows/save") {
    const flowSaveBody = body as unknown as { traceId?: string; sessionId?: string; name?: string };
    const customerId = identity.customerId;
    if (!flowSaveBody.traceId) {
      sendJson(res, 400, { ok: false, error: "缺少 traceId" });
      return;
    }

    const template = await app.deriveFlowForTrace({
      traceId: flowSaveBody.traceId,
      customerId,
      sessionId: flowSaveBody.sessionId ?? app.envelope({ channel: "app", text: "" }).sessionId ?? "",
    });
    if (!template) {
      sendJson(res, 400, {
        ok: false,
        error:
          "这一轮没有可保存的办理结果(可能是:没有成功办结的能力,或这是查询类操作 —— " +
          "没办成/不值得再办一次的事不该进常用服务)",
      });
      return;
    }

    const saved = await app.saveFlow(customerId, {
      ...template,
      ...(flowSaveBody.name ? { name: flowSaveBody.name } : {}),
    });
    const { templateToSay } = await import("../../core/src/agent/flowTrace.ts");
    sendJson(res, 200, {
      ok: true,
      flow: { ...saved, say: templateToSay(saved) },
      savedTo: `var/personalization/${customerId.replace(/[^a-zA-Z0-9_-]/g, "_")}.json`,
      whereToFind: "手机银行 App 首页 →「常用服务」→ 我的常用流程",
    });
    return;
  }

  // ---- 删除常用流程 ----
  if (method === "POST" && path === "/api/flows/delete") {
    const flowDeleteBody = body as unknown as { templateId?: string };
    if (!flowDeleteBody.templateId) {
      sendJson(res, 400, { ok: false, error: "缺少 templateId" });
      return;
    }
    const ok = await app.removeFlow(identity.customerId, flowDeleteBody.templateId);
    sendJson(res, 200, { ok, removed: ok });
    return;
  }

  // ---- 客户与账户概况(供界面初始化) ----
  if (method === "GET" && path === "/api/demo/profile") {
    const customerId = identity.customerId;
    const accounts = await app.bank.listAccounts(customerId);
    const cards = await app.bank.listCards(customerId);
    const profile = await app.bank.getRiskProfile(customerId);
    sendJson(res, 200, {
      ok: true,
      customerId,
      displayName: customerId === app.world.primaryCustomerId ? "张先生" : "赵女士",
      channelCapabilities: CHANNEL_CAPABILITIES.app,
      accounts: accounts.map((a) => ({
        accountId: a.accountId,
        maskedNo: a.maskedNo,
        type: a.type,
        balance: a.balance,
        availableBalance: a.availableBalance,
        currency: a.currency,
      })),
      payees: [...app.world.payees.values()]
        .filter((p) => p.ownerCustomerId === customerId)
        .map((p) => ({
          payeeId: p.payeeId,
          name: p.name,
          bankName: p.bankName,
          aliases: p.aliases,
          successCount: p.successHistory.length,
        })),
      /**
       * ★ 卡片概况:App 首页的"我的卡片"要能一眼看出哪张卡不能用。
       *   数据来自银行核心(与 Agent 看到的是同一份),界面不做任何二次判断 ——
       *   否则就会出现"App 说正常、Agent 说已挂失"这种自相矛盾。
       */
      cards: cards.map((c) => ({
        cardId: c.cardId,
        productName: c.productName,
        kind: c.kind,
        kindLabel: c.kindLabel,
        last4: c.last4,
        status: c.status,
        statusLabel: c.statusLabel,
        activated: c.activated,
        creditLimit: c.creditLimit,
        availableLimit: c.availableLimit,
        usedAmount: c.usedAmount,
        restrictionCause: c.restriction?.cause ?? null,
        restrictionCauseLabel: c.restriction?.causeLabel ?? null,
      })),
      wealth: {
        assessed: profile.assessed,
        level: profile.level,
        levelLabel: profile.levelLabel,
        expired: profile.expired,
      },
      /**
       * ★ 首页"常用服务"的数据:客户保存过的常用流程 + 此刻适用的智能建议。
       *
       * 与 /api/personalization 分开返回,是因为初始化一次就够 ——
       * 首页渲染不该等两次请求。
       */
      personalization: await app.personalizationView(customerId),
    });
    return;
  }

  sendJson(res, 404, { ok: false, error: `未找到路由:${method} ${path}` });
}

// ============================================================================
// 网关安全辅助(身份 / 审计 / CORS)
// ============================================================================

/** 只对白名单内的来源下发 CORS 响应头;白名单外一个头也不给 */
function applyCorsHeaders(req: IncomingMessage, res: ServerResponse, policy: GatewayPolicy): void {
  const origin = typeof req.headers.origin === "string" ? req.headers.origin : undefined;
  if (!origin || !policy.allowedOrigins.has(origin)) return;
  res.setHeader("Access-Control-Allow-Origin", origin);
  // ★ Vary: Origin —— 否则中间缓存会把"给 A 来源的许可"复用给 B 来源
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
}

/** 追加一条网关侧的审计事件(鉴权类),统一归属字段与时钟 */
async function appendAudit(
  app: App,
  input: {
    type: AuditEvent["type"];
    customerId: string;
    sessionId: string;
    channel: Channel;
    payload: Record<string, unknown>;
  },
): Promise<void> {
  await app.audit.append({
    ts: app.now(),
    // ★ 网关事件不属于任何一次"业务回合",给它一个独立 traceId 前缀,
    //   这样在审计面板里能一眼区分"这是谁在被拒绝"与"这是谁在办业务"
    traceId: `gw_${randomUUID().slice(0, 12)}`,
    sessionId: input.sessionId,
    customerId: input.customerId,
    channel: input.channel,
    type: input.type,
    payload: input.payload,
  });
}

/**
 * 记录一次"网关拒绝"。
 *
 * ★ 为什么所有拒绝都走同一个函数:
 *   被拒绝的请求**不会执行**,所以它自己没有机会写审计 —— 与"阻断级操作"
 *   同理(见 types.ts 里 request_rejected 的说明)。统一出口保证三件事:
 *     ① 事件类型固定为 auth_denied,一条 grep 就能捞出全部越权尝试;
 *     ② payload 里同时留下"请求声称是谁"与"令牌里其实是谁";
 *     ③ 拒绝原因用稳定 kind 标识(而不是靠读一段中文),便于统计与回归测试。
 */
async function auditGatewayDenial(
  app: App,
  input: {
    /** 稳定原因标识:origin_not_allowed / no_session / invalid_session / cross_customer / csrf_rejected / bad_credential / login_locked / sign_proof_* */
    kind: string;
    path: string;
    /** 请求**声称**的身份(可能是攻击者的目标客户号) */
    claimed?: string | undefined;
    /** 服务端认定的身份(没有会话时为空 —— 那就记 anonymous) */
    customerId?: string;
    detail: string;
    channel: Channel;
    extra?: Record<string, unknown>;
  },
): Promise<void> {
  await appendAudit(app, {
    type: "auth_denied",
    customerId: input.customerId ?? "anonymous",
    sessionId: "gateway",
    channel: input.channel,
    payload: {
      ok: false,
      kind: input.kind,
      path: input.path,
      /**
       * ★ 两个身份都记,不是二选一:
       *   只记"声称"会把越权尝试伪装成"这个人来过";
       *   只记"令牌"则丢掉了攻击者想动的目标是谁。
       */
      claimedCustomerId: input.claimed ?? null,
      identityCustomerId: input.customerId ?? null,
      detail: input.detail,
      ...(input.extra ?? {}),
    },
  });
}

/**
 * 解析"这次请求是谁"。
 *
 * ★ 顺序与分支都是有意的:
 *   ① 有合法令牌 → 就是那个人(身份的唯一正常来源);
 *   ② 令牌无效/已过期 → **先落一条 auth_denied**(这是证据),再按策略决定是否引导;
 *   ③ 没有令牌 → 允许引导时给"默认演示身份"(前端零改动的唯一办法);
 *      不允许引导(严格模式)则 401 并要求登录。
 */
async function resolveIdentity(
  req: IncomingMessage,
  res: ServerResponse,
  app: App,
  policy: GatewayPolicy,
): Promise<{ identity: RequestIdentity } | IdentityFailure> {
  const cookies = parseCookies(req.headers.cookie);
  const token = cookies[AUTH_COOKIE];
  const session = await app.auth.verify(token, app.now());
  if (session) {
    return { identity: { session, customerId: session.customerId } };
  }

  const hadToken = Boolean(token);
  const channel = parseChannelFromEvent(req) ?? "app";

  if (policy.requireLogin) {
    return {
      identity: null,
      reason: hadToken ? "invalid_session" : "no_session",
      detail: hadToken
        ? "会话令牌无效或已过期;严格模式(AUTH_REQUIRE_LOGIN=1)下不引导默认身份"
        : "请求未携带会话令牌;严格模式(AUTH_REQUIRE_LOGIN=1)下必须显式登录",
    };
  }

  if (hadToken) {
    /**
     * ★ 令牌坏了也要留痕,然后再引导。
     *   这条记录回答的是"那个坏令牌是什么时候被用过的" ——
     *   如果它是被伪造出来的,这就是攻击的第一步证据(而不是被静默吞掉)。
     */
    await auditGatewayDenial(app, {
      kind: "invalid_session",
      path: new URL(req.url ?? "/", "http://127.0.0.1").pathname,
      detail: "携带的会话令牌无效或已过期;已按演示引导重新签发默认演示身份会话",
      channel,
    });
  }

  const bootstrapped = await app.auth.bootstrap({
    customerId: app.world.primaryCustomerId,
    channel,
    userAgent: req.headers["user-agent"],
  });
  setAuthCookies(res, bootstrapped.token, bootstrapped.session);
  await appendAudit(app, {
    type: "auth_session_issued",
    customerId: bootstrapped.session.customerId,
    sessionId: bootstrapped.session.sid,
    channel,
    payload: {
      kind: "demo_bootstrap",
      sid: bootstrapped.session.sid,
      expiresAt: bootstrapped.session.expiresAt,
      reason: hadToken ? "令牌无效,重新引导" : "首次访问,引导本机默认演示身份",
      note:
        "本机演示引导只给**默认演示客户**这一个身份;要成为别的客户必须走 /api/auth/login。" +
        "设 AUTH_REQUIRE_LOGIN=1 可关闭该引导。",
    },
  });
  return {
    identity: { session: bootstrapped.session, customerId: bootstrapped.session.customerId },
  };
}

/**
 * 收集请求里**声称**的 customerId(查询串 + 请求体)。
 *
 * ★ 只收集,不采信。它的唯一用途是与令牌里的身份做交叉核对:
 *   一致 = 客户端说的和系统认为的是同一个人(正常);
 *   不一致 = 横向越权的尝试(拒绝 + 落审计)。
 *   注意这里**不需要**枚举所有可能的位置 —— 只要有一处能影响身份判定,
 *   就必须在这里被看见;而下面所有路由都不再从 body 取身份,所以核对点只有这里。
 */
function collectCustomerClaims(url: URL, body: Record<string, unknown>): Array<{ value: string; from: string }> {
  const claims: Array<{ value: string; from: string }> = [];
  const fromQuery = url.searchParams.get("customerId");
  if (fromQuery) claims.push({ value: fromQuery, from: "query.customerId" });
  const fromBody = body["customerId"];
  if (typeof fromBody === "string" && fromBody.length > 0) {
    claims.push({ value: fromBody, from: "body.customerId" });
  }
  return claims;
}

/** 从请求路径里认出渠道(用于审计归属;认不出就是 app) */
function parseChannelFromEvent(req: IncomingMessage): Channel | null {
  const match = (req.url ?? "").match(/^\/api\/channels\/([a-z]+)\//);
  return match ? parseChannel(match[1]!) : null;
}

/** 下发会话 Cookie(HttpOnly)+ CSRF 双提交 Cookie(可读) */
function setAuthCookies(res: ServerResponse, token: string, session: AuthSession): void {
  const maxAgeMs = Math.max(0, session.expiresAt - session.issuedAt);
  res.appendHeader("Set-Cookie", buildCookie(AUTH_COOKIE, token, { maxAgeMs }));
  res.appendHeader("Set-Cookie", buildCookie(AUTH_CSRF_COOKIE, session.csrfToken, { maxAgeMs, httpOnly: false }));
}

/** 清除会话 Cookie(登出时"清 Cookie"只是表面动作,真正的撤销在服务端) */
function clearAuthCookies(res: ServerResponse): void {
  res.appendHeader("Set-Cookie", buildCookie(AUTH_COOKIE, "", { clear: true }));
  res.appendHeader("Set-Cookie", buildCookie(AUTH_CSRF_COOKIE, "", { clear: true, httpOnly: false }));
}

// ============================================================================
// 静态资源
// ============================================================================

const PUBLIC_DIR = resolvePath(fileURLToPath(new URL("../public/", import.meta.url)));

const CONTENT_TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".webmanifest": "application/manifest+json",
};

/**
 * 托管 public/ 下的静态文件。
 *
 * 返回 true 表示已经响应(文件已发出或是 404),false 表示不是静态资源请求。
 */
async function serveStatic(res: ServerResponse, path: string): Promise<boolean> {
  // 只接受干净的相对路径
  const rel = path === "/" ? "index.html" : path.replace(/^\/+/, "");
  const normalized = normalize(rel);
  if (normalized.startsWith("..") || normalized.includes("..\\") || normalized.includes("../")) {
    sendJson(res, 400, { ok: false, error: "非法路径" });
    return true;
  }

  const full = join(PUBLIC_DIR, normalized);
  // 二次确认:拼接后的绝对路径必须仍在 public/ 之内
  if (!full.startsWith(PUBLIC_DIR)) {
    sendJson(res, 400, { ok: false, error: "非法路径" });
    return true;
  }

  // 无扩展名的路径一律回首页(单页应用的 client-side 路由)
  const candidates = extname(full) ? [full] : [join(full, "index.html"), `${full}.html`];

  for (const file of candidates) {
    try {
      const body = await readFile(file);
      const type = CONTENT_TYPES[extname(file).toLowerCase()] ?? "application/octet-stream";
      res.writeHead(200, {
        "Content-Type": type,
        "Content-Length": body.length,
        // 演示页面会频繁改动,禁掉缓存免得改了看不到
        "Cache-Control": "no-store",
      });
      res.end(body);
      return true;
    } catch {
      // 试下一个候选
    }
  }

  // 真的没有这个文件才 404(而不是被后面的 JSON 路由接走)
  sendJson(res, 404, { ok: false, error: `静态文件不存在:${normalized}` });
  return true;
}

// ============================================================================
// 视图转换
// ============================================================================

function toTurnView(
  result: Awaited<ReturnType<App["orchestrator"]["handleMessage"]>>,
  envelope: MessageEnvelope,
) {
  return {
    turnId: result.turnId,
    traceId: result.traceId,
    channel: envelope.channel,
    reply: result.reply,
    card: result.card ?? null,
    promptFor: result.promptFor ?? null,
    terminal: result.terminal ?? null,
    // 面向界面的裁决摘要(隐藏内部证据细节)
    policySummary:
      result.policySummary?.map((r) => ({
        ruleId: r.ruleId,
        message: r.message,
        effect: r.effect ?? null,
      })) ?? [],
    /**
     * ★ 交互体验三件套:办理流程 / 来源标注 / 主动建议。
     *
     * 它们都是**服务端算好的结构化数据**,前端只负责画 ——
     * 界面里没有一行判断"这一步该显示什么颜色",颜色由 lane 字段决定。
     * 这条边界与"前端零业务判断"是同一条:流程的画法与业务的判定必须分开,
     * 否则改一次规则就要改两处代码。
     */
    flow: result.flow ?? null,
    citations: result.citations ?? [],
    suggestions: result.suggestions ?? [],
    /** ★ 可视块(材料比对 / 复核决策 / 误报撤回):界面按 kind 画,不做业务判断 */
    visual: result.visual ?? null,
  };
}

function toAuditView(e: {
  seq: number;
  ts: number;
  traceId: string;
  customerId: string;
  channel: string;
  type: string;
  payload: Record<string, unknown>;
  hash: string;
  prevHash: string;
}) {
  return {
    seq: e.seq,
    ts: e.ts,
    traceId: e.traceId,
    channel: e.channel,
    type: e.type,
    payload: e.payload,
    hashShort: e.hash.slice(0, 12),
    prevHashShort: e.prevHash.slice(0, 12),
  };
}

const CHANNEL_LABELS: Record<Channel, string> = {
  app: "手机银行 App",
  im: "IM 机器人",
  web: "网页控制台",
  voice: "语音渠道",
};

const C_BOLD = "\u001b[1m";
const C_DIM = "\u001b[2m";
const C_RESET = "\u001b[0m";

// ============================================================================
// 工具
// ============================================================================

function parseChannel(raw: string): Channel | null {
  return VALID_CHANNELS.includes(raw as Channel) ? (raw as Channel) : null;
}

async function readJson<T>(req: IncomingMessage): Promise<T | null> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  if (chunks.length === 0) return null;
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8")) as T;
  } catch {
    return null;
  }
}

/**
 * 回 JSON。
 *
 * ★ CORS 响应头**不在这里**设置:它在请求进入时就按白名单统一下发
 *   (见 applyCorsHeaders)。放在这里的话,每个响应分支都要记得带上它,
 *   漏掉一处就成了"某个端点能被任意网页读"。
 */
function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const text = JSON.stringify(body, null, 2);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(text),
    // 鉴权与业务响应一律不缓存:缓存一个"已登录"的响应等于把身份缓存出去
    "Cache-Control": "no-store",
  });
  res.end(text);
}

// ============================================================================
// 直接运行
// ============================================================================

const isMain = process.argv[1]?.replace(/\\/g, "/").endsWith("packages/server/src/index.ts");
if (isMain) {
  const { default: dotenv } = await import("dotenv");
  dotenv.config();

  const offline = process.argv.includes("--offline");
  const { app, port, close } = await startServer({ offline });

  console.log("");
  console.log("  银行 AI 智能体 —— 渠道网关已启动");
  console.log("  ─────────────────────────────────────────────");
  console.log(`  ${C_BOLD}移动端 App 入口:http://127.0.0.1:${port}/${C_RESET}`);
  console.log(`  ${C_DIM}(手机浏览器打开就是原生 App 的样子;桌面浏览器会显示成手机外框)${C_RESET}`);
  console.log(`  接口根地址:http://127.0.0.1:${port}`);
  console.log(`  模型:${app.llm.provider.name} / ${app.llm.provider.model}(${app.llm.mode})`);
  console.log(`  ${app.llm.reason}`);
  console.log("  ─────────────────────────────────────────────");
  console.log(`  ${C_BOLD}身份${C_RESET}:会话令牌(HttpOnly Cookie) · 请求体里的 customerId 只作核对`);
  console.log(
    `        登录端点 POST /api/auth/login · 越权尝试一律拒绝并落 ${C_BOLD}auth_denied${C_RESET} 审计事件`,
  );
  console.log(
    `        CORS 白名单:http://127.0.0.1:${port} / http://localhost:${port}(可用 ALLOWED_ORIGINS 追加)`,
  );
  if (policyRef.current.requireLogin) {
    console.log(`        ${C_DIM}严格模式 AUTH_REQUIRE_LOGIN=1:连默认演示身份也必须先登录${C_RESET}`);
  } else {
    console.log(
      `        ${C_DIM}演示引导:本机首次访问自动以默认演示客户上机(AUTH_REQUIRE_LOGIN=1 可关闭)${C_RESET}`,
    );
  }
  if (app.auth.usingEphemeralSecret) {
    console.log(
      `        ${C_DIM}会话签名密钥为本进程随机生成(重启后需重新上机);生产环境用 AUTH_SESSION_SECRET 注入${C_RESET}`,
    );
  }
  console.log("  ─────────────────────────────────────────────");
  console.log("  端点:");
  console.log("    GET  /                                 移动端 App 入口");
  console.log("    POST /api/auth/login                   凭据登录 → 签发会话令牌");
  console.log("    POST /api/auth/logout                  登出(服务端撤销)");
  console.log("    GET  /api/auth/whoami                  当前会话身份");
  console.log("    POST /api/channels/:channel/messages   发送消息");
  console.log("    POST /api/channels/:channel/actions    确认/取消/选择");
  console.log("    GET  /api/audit/recent                 审计事件(按身份过滤)");
  console.log("    GET  /api/audit/verify                 哈希链校验");
  console.log("    GET  /api/demo/profile                 客户、账户与卡片概况");
  console.log("    GET  /api/demo/pending                 待确认动作");
  console.log("    POST /api/demo/sign-auth-proof         签发强验证回执(仅演示,只签本会话身份的待办)");
  console.log("    GET  /api/health                       健康检查(免鉴权)");
  console.log("  ─────────────────────────────────────────────");
  console.log("  渠道:app | im | web | voice");
  console.log("");

  const shutdown = async (): Promise<void> => {
    console.log("\n  正在关闭...");
    await close();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

export { CHANNEL_LABELS, randomUUID };