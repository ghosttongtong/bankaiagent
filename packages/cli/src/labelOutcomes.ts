/**
 * 事后结局标签回填(第 4 项第 1 步:标签管道)
 *
 * 用途:
 *   把**事后才知道的事实**回填到历史评分记录上,给训练器提供 y 值。
 *   评分记录本身已经在链上(`policy_evaluated` 的 `payload.riskFactors`),
 *   本工具只**追加** `outcome_labeled` 事件,用 `payload.targetTraceId`
 *   指回被标注的那一笔请求 —— 不修改、不重写任何历史事件。
 *
 * ★ 为什么标签必须由外部喂进来,而不是"训练时顺手造一批":
 *   标签是**外部事实**(欺诈确认来自风控调查、投诉来自客服工单、
 *   退款冲正来自账务)。它的来源必须与模型解耦 ——
 *   模型不能自己定义"什么叫坏账",否则就是自己出题自己判卷。
 *   所以每个标签都记下"哪个数据源、多长观察窗、什么时候回填的"。
 *
 * ★★ 两种标签来源的区别,是这件工具最要紧的一句话 ★★
 *   --feed=<path>     真实运营导出的结局(JSONL),来源记为 external_feed。
 *                     只有它能支撑"模型是否有效"的判断。
 *   --synthetic=<N>   按稳定哈希,从**已在链上**的记录里合成 N 条结局,
 *                     来源记为 synthetic_demo。
 *                     它**只能证明管道跑得通**
 *                     (记录 → 特征 → 标签 → 训练 → 影子对比),
 *                     **永远不能证明模型能识别欺诈**:它答对的是我们自己
 *                     写进生成规则里的那点弱相关,不是真实世界。
 *   输出对 synthetic_demo 全程标注,生成的模型文件里也会如实写
 *   labelSource=synthetic_demo(见 trainScorer.ts)。
 *
 * ★ 为什么只标注"观察窗已经过去"的记录:
 *   结局需要时间才发生(欺诈确认往往在几天到几周后)。刚发生的一笔转账
 *   此刻没有标签,不代表它是干净的 —— 把窗口不足的记录当负样本喂给模型,
 *   等于往训练集里灌"还没出事的欺诈",模型会学到一个偏低的先验。
 *   宁可少标一批,也不要制造系统性偏差。
 *
 * 用法:
 *   node packages/cli/src/labelOutcomes.ts --synthetic=2000
 *   node packages/cli/src/labelOutcomes.ts --feed=./ops-outcomes.jsonl
 *   node packages/cli/src/labelOutcomes.ts --synthetic=500 --dry-run
 *   node packages/cli/src/labelOutcomes.ts --synthetic=500 --limit=50 --window-days=30
 *   node packages/cli/src/labelOutcomes.ts --dir=D:\tmp\audit --synthetic=200
 *
 *   参数:
 *     --dir=<path>        审计目录,默认 ./var/audit(相对路径按当前工作目录解析)
 *     --feed=<path>       真实结局 JSONL,每行 {"traceId","outcome","windowDays?","note?"}
 *                         outcome ∈ fraud_confirmed|complaint_filed|refund_settled
 *     --synthetic=<N>     合成 N 条结局(只覆盖已在链上的记录,绝不新造 traceId)
 *     --window-days=<n>   结局观察窗,默认 30 天(记录 ts 必须早于 now-窗口 才可入选)
 *     --limit=<n>         最多写入 n 条标签(按 seq 升序取前 n 条,保证可复现)
 *     --dry-run           只打印将要写入什么,一个字节都不写
 *
 * 退出码:
 *   0 正常(含 --dry-run,以及"没有可回填记录"这种空跑)
 *   1 用法错误 / feed 文件缺失或格式非法 / 审计目录不存在
 *   2 审计链已损坏 —— 拒绝往一条已经断裂的链上追加证据
 */

import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { HashChainAudit } from "../../core/src/audit/hashChain.ts";
import { RISK_FEATURE_NAMES } from "../../core/src/policy/engine.ts";
import type { RiskFeatures } from "../../core/src/policy/engine.ts";
import type { AuditEvent, Channel } from "../../core/src/types.ts";

// ============================================================================
// 零依赖参数解析(与 verifyAudit / probeCapabilities 同一风格,不引第三方库)
// ============================================================================

/**
 * ★ 为什么三个 scorers CLI 各自抄一份 argValue,而不是抽一个公共模块:
 *   项目里现有 CLI(verifyAudit / probeCapabilities / diagnoseLlm)都是这么写的,
 *   每个脚本都要能单独拷出去跑。多一个共享模块就多一处"改一处影响三个工具
 *   的参数语义"的风险 —— 参数解析是工具的门面,宁可重复也不要耦合。
 */
function argValue(name: string): string | undefined {
  const hit = process.argv.slice(2).find((a) => a.startsWith(`--${name}=`));
  return hit ? hit.slice(name.length + 3) : undefined;
}

function hasFlag(name: string): boolean {
  return process.argv.slice(2).includes(`--${name}`);
}

/** 读一个非负整数参数;给了但不像数就当场退出(静默回落会让人以为参数生效了) */
function intArg(name: string): number | undefined {
  const raw = argValue(name);
  if (raw == null) return undefined;
  const n = Number(raw);
  if (!Number.isFinite(n) || n < 0) {
    console.log(`  ✗ 参数 --${name}=${raw} 不是合法的非负数。`);
    process.exit(1);
  }
  return Math.floor(n);
}

/**
 * `--name=`(值恰好为空)不是"没给这个参数",而是"给了一个空路径"。
 *
 * ★ 必须单独挡一下:`resolve(cwd, "")` 得到的是**当前工作目录本身**,
 *   于是 `--dir=` 会把整个仓库根当成审计目录,还会在里面留下一把写入锁
 *   (锁文件会被退出钩子删掉,但"目录被当成审计目录"这件事本身已经错了)。
 *   静默回落成默认值同样不行:那会让一个打错的参数看起来生效了。
 */
function requireNonEmpty(name: string): void {
  const raw = argValue(name);
  if (raw != null && raw.trim() === "") {
    console.log(`  ✗ --${name}= 的值为空 —— 请给出真实路径(空值会被解析成当前目录)。`);
    process.exit(1);
  }
}

// ============================================================================
// 类型与常量
// ============================================================================

/** 事后结局的种类(与 types.ts 里 outcome_labeled 的注释一致) */
type LabelKind = "fraud_confirmed" | "complaint_filed" | "refund_settled";
type LabelSource = "external_feed" | "synthetic_demo";

const LABEL_KINDS: readonly LabelKind[] = ["fraud_confirmed", "complaint_filed", "refund_settled"];

/** 默认结局观察窗(天) */
const DEFAULT_WINDOW_DAYS = 30;
const DAY_MS = 86_400_000;

/**
 * 合成标签的盐。
 *
 * ★ 为什么要一个显式盐、而不是直接哈希 traceId:
 *   将来若再需要一类"演示用的别的合成标注"(例如合成投诉工单),
 *   换一个盐就能得到一批与本次**互不相关**的抽样,而不是同一批记录的同一批标签。
 *   同时它也把"这是演示数据"这件事写进哈希输入里 ——
 *   即便有人把合成标签误当真实标签,凭 payload.matchedBy 也能一眼看出。
 */
const SYNTHETIC_SALT = "bank-agent/outcome-label/v1";

// ============================================================================
// 哈希与合成抽样
// ============================================================================

/**
 * FNV-1a 32 位哈希(自己写,零依赖)。
 *
 * ★ 为什么绝不用 Math.random:合成标签必须**可复现** ——
 *   同一份审计链、同一个 N,今天、明天、评委的机器上都必须得到同一批标签。
 *   否则"训练结果可复现"这句话不成立,`--synthetic` 也就失去了演示价值。
 * ★ 为什么用 Math.imul 而不是 `h * 0x01000193 >>> 0`:
 *   后者在 h 接近 2^32 时乘积约 7.2e16,虽然仍在 double 的精确整数范围内
 *   (所以结果碰巧也对),但那是依赖"恰好没超 2^53"这个隐含前提;
 *   imul 直接就是 32 位整数乘法,前提写在代码里,不靠读者验算。
 * ★ 局限(如实说明):charCodeAt 取的是 UTF-16 码元,不是字节。
 *   对 ASCII 的 traceId 与规范 FNV-1a 完全一致,对非 ASCII 则与规范不同。
 *   这里要的是**确定性**而不是与某个哈希规范兼容,所以刻意不改。
 */
function fnv1a(input: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    h ^= input.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}

/** 把哈希映射到 [0,1),用于"抽样" */
function hashUnit(traceId: string, purpose: string): number {
  return fnv1a(`${traceId}|${purpose}|${SYNTHETIC_SALT}`) / 0x1_0000_0000;
}

/**
 * 合成"这一笔最终被确认有问题"的概率。
 *
 * ★ 为什么故意做成"弱相关、幅度小"(而不是"欺诈 = 高风险分"):
 *   合成标签的全部用途是**让管道跑起来**(证明特征能进模型、模型能被训、
 *   影子模式能报分歧)。如果按 legacy 分数或大权重来造标签,
 *   训出来的 AUC 会接近 1.0 —— 那个数字只反映"我把答案抄进了生成规则",
 *   一旦被人当成"模型有效"的证据,就是自欺。
 *   所以这里只用几个**语义上说得通、权重克制**的特征,并且封顶 0.6:
 *   分数不够高是**预期结果**,不是缺陷。
 * ★ 只用 amountExposure / payeeFirstTime / sessionSuspicion 等非硬命中特征:
 *   名单命中与拆分交易由确定性规则顶格,本来就不交给模型(训练器会排除),
 *   让合成标签去依赖它们只会制造"标签与已排除样本纠缠"的假相关。
 */
function syntheticPositiveProbability(f: RiskFeatures): number {
  const p =
    0.04 +
    0.3 * f.amountExposure +
    0.22 * f.payeeFirstTime +
    0.16 * f.sessionSuspicion +
    0.1 * f.deviceUntrusted +
    0.08 * f.hourAnomaly +
    0.06 * f.channelRisk;
  // 封顶 0.6:即便是"金额顶格 + 首次收款人 + 会话可疑"也不到 2/3,
  // 免得合成数据自己把先验抬到不真实的高度。
  return Math.min(0.6, p);
}

/** 合成结局的种类分布(45% / 35% / 20%,顺序固定以便复现) */
function syntheticKind(traceId: string): LabelKind {
  const r = hashUnit(traceId, "kind");
  if (r < 0.45) return "fraud_confirmed";
  if (r < 0.8) return "complaint_filed";
  return "refund_settled";
}

// ============================================================================
// 审计记录读取
// ============================================================================

/** 链上一条可用的评分记录 */
interface ScoringRecord {
  seq: number;
  ts: number;
  traceId: string;
  sessionId: string;
  customerId: string;
  channel: Channel;
  /** `payload.riskFactors.score`(当时生效的评分器给的分) */
  score: number;
  features: RiskFeatures;
  /** 名单命中或拆分交易 —— 由确定性规则顶格,不进训练集 */
  hardHit: boolean;
}

/**
 * 从 `payload.riskFactors.features` 读回特征。
 *
 * ★ 为什么只认 `RISK_FEATURE_NAMES` 这一份名单、并且要求**每一个**特征都是数字:
 *   引擎的契约是"features 的键集合与顺序必须等于 RISK_FEATURE_NAMES"。
 *   若某条记录少了一个特征就当它不可用,而不是补 0 ——
 *   补 0 会让"特征缺失"伪装成"该特征没命中",训练出来的权重是错的,
 *   而且没有任何报错。宁可少几条样本,也不要静默喂错数据。
 */
function readFeatures(raw: unknown): RiskFeatures | undefined {
  if (raw == null || typeof raw !== "object") return undefined;
  const obj = raw as Record<string, unknown>;
  const picked: Record<string, number> = {};
  for (const name of RISK_FEATURE_NAMES) {
    const v = obj[name];
    if (typeof v !== "number" || !Number.isFinite(v)) return undefined;
    picked[name] = v;
  }
  // 到这里 picked 已按契约覆盖全部键;不做逐字段列举,
  // 免得出现第二份特征名单(名单有两份就一定会漂移)。
  return picked as unknown as RiskFeatures;
}

interface ScoringScan {
  records: ScoringRecord[];
  /** 有 riskFactors 但没有 features 的旧记录(第 4 项改造之前落的链) */
  withoutFeatures: number;
  /** 有 riskFactors 但 score 不是有限数(数据本身坏了) */
  unusable: number;
}

function scanScoringRecords(events: readonly AuditEvent[]): ScoringScan {
  const records: ScoringRecord[] = [];
  let withoutFeatures = 0;
  let unusable = 0;
  for (const e of events) {
    if (e.type !== "policy_evaluated") continue;
    const rawFactors = e.payload["riskFactors"];
    if (rawFactors == null || typeof rawFactors !== "object") continue;
    const snapshot = rawFactors as Record<string, unknown>;
    const score = snapshot["score"];
    if (typeof score !== "number" || !Number.isFinite(score)) {
      unusable++;
      continue;
    }
    const features = readFeatures(snapshot["features"]);
    if (!features) {
      withoutFeatures++;
      continue;
    }
    records.push({
      seq: e.seq,
      ts: e.ts,
      traceId: e.traceId,
      sessionId: e.sessionId,
      customerId: e.customerId,
      channel: e.channel,
      score,
      features,
      hardHit: features.watchlistHit === 1 || features.structuring === 1,
    });
  }
  return { records, withoutFeatures, unusable };
}

/** 已存在的标签(`source:label`),用于避免重复回填 */
function scanExistingLabels(events: readonly AuditEvent[]): Map<string, Set<string>> {
  const map = new Map<string, Set<string>>();
  for (const e of events) {
    if (e.type !== "outcome_labeled") continue;
    const target = e.payload["targetTraceId"];
    const label = e.payload["label"];
    const source = e.payload["source"];
    if (typeof target !== "string" || typeof label !== "string" || typeof source !== "string") continue;
    let set = map.get(target);
    if (!set) {
      set = new Set<string>();
      map.set(target, set);
    }
    set.add(`${source}:${label}`);
  }
  return map;
}

// ============================================================================
// 计划(要写什么之前先把"要写什么"算清楚)
// ============================================================================

interface PlannedLabel {
  record: ScoringRecord;
  label: LabelKind;
  /** 该条标签用的观察窗(真实 feed 可以逐行覆盖) */
  windowDays: number;
  source: LabelSource;
  note: string;
  matchedBy: string;
}

interface Counters {
  /** 因 ts 太新、观察窗还没走完而跳过 */
  tooRecent: number;
  /** feed 里的 traceId 在链上找不到对应评分记录 */
  unmatched: number;
  /** 同一记录 + 同一来源 + 同一标签已经存在(重复回填) */
  alreadyLabeled: number;
  /** 合成模式下"抽样判定为阴性"的记录数 */
  syntheticNegatives: number;
}

/** feed 一行 */
interface FeedLine {
  traceId: string;
  outcome: LabelKind;
  windowDays?: number;
  note?: string;
}

function parseFeed(text: string, path: string): FeedLine[] {
  const out: FeedLine[] = [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = (lines[i] ?? "").trim();
    if (!line) continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      console.log(`  ✗ ${path} 第 ${i + 1} 行不是合法 JSON —— 拒绝用一份读不懂的结局文件训练模型。`);
      process.exit(1);
    }
    if (parsed == null || typeof parsed !== "object") {
      console.log(`  ✗ ${path} 第 ${i + 1} 行不是 JSON 对象。`);
      process.exit(1);
    }
    const row = parsed as Record<string, unknown>;
    const traceId = row["traceId"];
    const outcome = row["outcome"];
    if (typeof traceId !== "string" || !traceId) {
      console.log(`  ✗ ${path} 第 ${i + 1} 行缺 traceId。`);
      process.exit(1);
    }
    if (typeof outcome !== "string" || !LABEL_KINDS.includes(outcome as LabelKind)) {
      console.log(
        `  ✗ ${path} 第 ${i + 1} 行的 outcome=${String(outcome)} 不在 ` +
          `${LABEL_KINDS.join("|")} 之内。`,
      );
      process.exit(1);
    }
    const windowDays = row["windowDays"];
    if (windowDays != null && (typeof windowDays !== "number" || !Number.isFinite(windowDays) || windowDays < 0)) {
      console.log(`  ✗ ${path} 第 ${i + 1} 行的 windowDays 不是合法的非负数。`);
      process.exit(1);
    }
    const note = row["note"];
    out.push({
      traceId,
      outcome: outcome as LabelKind,
      ...(typeof windowDays === "number" ? { windowDays } : {}),
      ...(typeof note === "string" && note ? { note } : {}),
    });
  }
  return out;
}

// ============================================================================
// 主流程
// ============================================================================

const dryRun = hasFlag("dry-run");
const auditDir = resolve(process.cwd(), argValue("dir") ?? "./var/audit");
const feedPath = argValue("feed");
const syntheticCount = intArg("synthetic");
const windowDaysArg = intArg("window-days");
const windowDays = windowDaysArg ?? DEFAULT_WINDOW_DAYS;
const limit = intArg("limit");

requireNonEmpty("dir");
requireNonEmpty("feed");

console.log("");
console.log("═".repeat(66));
console.log("  事后结局标签回填(第 4 项:标签管道)");
console.log("═".repeat(66));
console.log(`  审计目录:${auditDir}`);

// ---- 参数校验:两种来源二选一,不给就退出 ----
if (feedPath == null && syntheticCount == null) {
  console.log("");
  console.log("  用法:本工具需要**明确**指定标签来源,不会替你选一个默认值 ——");
  console.log("       因为'这份标签是真实的还是合成的'决定了它能支撑什么结论。");
  console.log("");
  console.log("    node packages/cli/src/labelOutcomes.ts --feed=./ops-outcomes.jsonl");
  console.log("    node packages/cli/src/labelOutcomes.ts --synthetic=2000");
  console.log("");
  console.log("  可选:--dir=<审计目录> --window-days=<观察窗天数> --limit=<最多写几条> --dry-run");
  console.log("");
  process.exit(1);
}
if (feedPath != null && syntheticCount != null) {
  console.log("");
  console.log("  ✗ --feed 与 --synthetic 只能给一个:两种来源的标签语义不同,");
  console.log("    混在一批里会让'这批标签到底是什么'变成需要翻 payload 才知道的事。");
  console.log("");
  process.exit(1);
}
if (syntheticCount != null && syntheticCount < 1) {
  console.log("  ✗ --synthetic 至少为 1(为 0 时没有任何事可做)。");
  process.exit(1);
}
if (syntheticCount != null && windowDaysArg == null) {
  // 默认值照旧,但白纸黑字说清楚它生效了 —— 合成演示最容易被误当成真实评估。
  console.log(`  观察窗:默认 ${DEFAULT_WINDOW_DAYS} 天(可用 --window-days=<n> 覆盖)`);
}

if (!existsSync(auditDir)) {
  console.log("");
  console.log("  ✗ 审计目录不存在 —— 还没有可回填的评分记录。");
  console.log("    先跑一次演示或探针产生审计:");
  console.log("      npm run demo -- --offline");
  console.log("");
  process.exit(1);
}

const audit = new HashChainAudit({ auditDir });
const loaded = await audit.loadFromDisk();
console.log(`  已载入事件:${loaded.loaded} 条`);

/**
 * ★ 先校验、后写入:绝不往一条已经断裂的链上追加证据。
 *   断链之后再追加,只会让"从哪一条开始被篡改"更难定位 ——
 *   取证价值是负的。所以发现断链就直接退出 2。
 *   (替代方案"照写不误、末尾提示链已损坏"被否决:那等于用新证据
 *    把断点埋起来。)
 */
const before = await audit.verifyChain();
if (!before.intact) {
  console.log("");
  console.log(`  ✗ 审计链已损坏(断点在第 ${before.brokenAtSeq ?? "?"} 条)—— 拒绝写入。`);
  console.log("    请先跑 npm run verify-audit 定位,再决定是修复还是另起目录。");
  console.log("");
  process.exit(2);
}
console.log(`  链完整性(写入前):✓ 完整(覆盖 ${before.checkedEvents ?? 0} 条)`);

const events = await audit.readAll();
const scan = scanScoringRecords(events);
const existing = scanExistingLabels(events);
const now = Date.now();

console.log("");
console.log("  ── 评分记录 ──");
console.log(`    可用(带 features):${scan.records.length} 条`);
if (scan.withoutFeatures > 0) {
  console.log(
    `    ★ 有 ${scan.withoutFeatures} 条 policy_evaluated 带 riskFactors 但没有 features` +
      "(评分器升级之前落的链),无法用于训练,已跳过。",
  );
}
if (scan.unusable > 0) {
  console.log(`    ★ 有 ${scan.unusable} 条 riskFactors.score 不是有限数(数据本身有问题),已跳过。`);
}

const counters: Counters = {
  tooRecent: 0,
  unmatched: 0,
  alreadyLabeled: 0,
  syntheticNegatives: 0,
};

const byRecord = new Map<string, ScoringRecord>();
for (const r of scan.records) {
  // 同一 traceId 可能有多条评分事件(重规划/多次评估);标签按 traceId 关联,
  // 取 seq 最小的那一条作为"当时那一笔请求"的快照,保证可复现。
  if (!byRecord.has(r.traceId)) byRecord.set(r.traceId, r);
}

const planned: PlannedLabel[] = [];

if (feedPath != null) {
  const abs = resolve(process.cwd(), feedPath);
  if (!existsSync(abs)) {
    console.log("");
    console.log(`  ✗ feed 文件不存在:${abs}`);
    console.log("");
    process.exit(1);
  }
  const text = await readFile(abs, "utf8");
  const rows = parseFeed(text, abs);

  console.log("");
  console.log("  ★★ 标签来源:真实运营导出(external_feed)★★");
  console.log(`    feed 文件:${abs}(${rows.length} 行)`);
  console.log("    这是唯一能支撑「模型是否有效」这一判断的来源。");

  for (const row of rows) {
    const record = byRecord.get(row.traceId);
    if (!record) {
      counters.unmatched++;
      continue;
    }
    const win = row.windowDays ?? windowDays;
    if (record.ts > now - win * DAY_MS) {
      counters.tooRecent++;
      continue;
    }
    if (existing.get(row.traceId)?.has(`external_feed:${row.outcome}`)) {
      counters.alreadyLabeled++;
      continue;
    }
    planned.push({
      record,
      label: row.outcome,
      windowDays: win,
      source: "external_feed",
      note: row.note ?? `运营结局导出回填(${row.outcome})`,
      matchedBy: "targetTraceId",
    });
  }
} else {
  const want = syntheticCount ?? 0;
  console.log("");
  console.log("  ★★ 标签来源:合成演示(synthetic_demo)★★");
  console.log("    合成标签只能证明「记录→特征→标签→训练→影子对比」这条管道跑得通,");
  console.log("    **不能**证明模型有效 —— 它答对的是我们写进生成规则里的弱相关。");
  console.log("    要判断效果,请用 --feed 喂真实结局。");
  console.log(`    抽样规则:FNV-1a(traceId|purpose|${SYNTHETIC_SALT}),无随机数、无时间依赖。`);

  /**
   * ★ 先按观察窗把"可入选记录"整体算出来,再在它上面抽样。
   *   为什么不在抽样循环里顺手判断 ts:
   *   循环一到配额就 break,后面那些"太新"的记录根本没被看过,
   *   于是"太新跳过 N 条"这个统计会随配额大小变化 —— 一个会变的统计
   *   比没有统计更糟,读者会拿两次不同的运行去对比。
   */
  const eligible = scan.records.filter((r) => r.ts <= now - windowDays * DAY_MS);
  counters.tooRecent = scan.records.length - eligible.length;

  /**
   * ★ 配额用"抽样判为阳性的第几条"来数,而不是"新写了几条":
   *   否则同一个 --synthetic=500 跑两遍,第一遍写了 500 条、第二遍会把
   *   已存在的 500 条跳过、再从后面的记录里另凑 500 条 ——
   *   "同一个 N 得到同一批标签"这句话就不成立了。
   *   现在第二遍计划的条数是 0(全部 alreadyLabeled),幂等。
   */
  let positivesFound = 0;
  for (const record of eligible) {
    if (positivesFound >= want) break;
    /**
     * ★ 抽样判据只用 traceId 的哈希,与"这是第几条记录"无关,带来两个好性质:
     *   ① 换一台机器、换一次运行,N 相同则标签集合相同(可复现);
     *   ② 把 N 从 500 调到 2000 时,原来那 500 条**原样保留**、只会追加,
     *      两次演示的结果可直接比较(单调性)。
     */
    const u = hashUnit(record.traceId, "select");
    if (u >= syntheticPositiveProbability(record.features)) {
      counters.syntheticNegatives++;
      continue;
    }
    positivesFound++;
    const label = syntheticKind(record.traceId);
    if (existing.get(record.traceId)?.has(`synthetic_demo:${label}`)) {
      counters.alreadyLabeled++;
      continue;
    }
    planned.push({
      record,
      label,
      windowDays,
      source: "synthetic_demo",
      note: `合成标签(演示管道用):由 traceId 稳定哈希抽样,概率随 amountExposure/payeeFirstTime/sessionSuspicion 等特征弱上升。不代表真实结局。`,
      matchedBy: "fnv1a(traceId|select|" + SYNTHETIC_SALT + ")",
    });
  }
  if (positivesFound < want) {
    console.log("");
    console.log(
      `    ★ 请求合成 ${want} 条,可在窗口内入选的记录只够抽出 ${positivesFound} 条阳性:`,
    );
    console.log("      (这不是失败:合成阳性率本就低,避免把合成数据做成'满屏欺诈'。)");
  }
}

const truncated = limit != null && planned.length > limit ? planned.slice(0, limit) : planned;
const windowStart = new Date(now - windowDays * DAY_MS).toISOString();

console.log("");
console.log("  ── 关联统计 ──");
console.log(`    观察窗:${windowDays} 天(窗口起点 ${windowStart})`);
console.log(`    已在链上的评分记录:${scan.records.length} 条,去重后 traceId:${byRecord.size} 个`);
console.log(`    太新(窗口未走完)跳过:${counters.tooRecent} 条`);
if (feedPath != null) console.log(`    feed 中找不到对应评分记录:${counters.unmatched} 条`);
if (syntheticCount != null) console.log(`    抽样判为阴性(不标注):${counters.syntheticNegatives} 条`);
console.log(`    已存在同源同种标签(不重复写):${counters.alreadyLabeled} 条`);
console.log(`    本次计划写入:${planned.length} 条` + (truncated.length !== planned.length ? `(--limit=${limit} 截断为 ${truncated.length} 条)` : ""));

for (const kind of LABEL_KINDS) {
  const n = truncated.filter((p) => p.label === kind).length;
  console.log(`      · ${kind.padEnd(16)} ${n} 条`);
}
const hardHitPlanned = truncated.filter((p) => p.record.hardHit).length;
if (hardHitPlanned > 0) {
  console.log(
    `    ★ 其中硬命中(名单/拆分)记录 ${hardHitPlanned} 条:它们仍会被标注` +
      "(结局是事实),但训练器会把这些样本排除 —— 硬命中由确定性规则定档,不交给模型。",
  );
}

if (truncated.length === 0) {
  console.log("");
  console.log("  没有可回填的记录(空跑)。这不等于出错:窗口没走完或链上还没有评分记录都会这样。");
  console.log(`  链完整:${(await audit.verifyChain()).intact}`);
  console.log("");
  await audit.releaseWriterLock();
  process.exit(0);
}

const preview = truncated.slice(0, 40);
console.log("");
console.log(`  ── 将要写入的标签(显示前 ${preview.length} 条)──`);
for (const p of preview) {
  const when = new Date(p.record.ts).toISOString().slice(0, 10);
  console.log(
    `    seq=${String(p.record.seq).padStart(5)} ${p.record.traceId.padEnd(26)} ` +
      `${p.label.padEnd(16)} ts=${when} 窗口=${p.windowDays}天`,
  );
}
if (truncated.length > preview.length) console.log(`    … 其余 ${truncated.length - preview.length} 条略。`);

if (dryRun) {
  console.log("");
  console.log(`  干跑(dry-run):以上 ${truncated.length} 条标签**不会**写入,链上零变化。`);
  const after = await audit.verifyChain();
  console.log(`  链完整:${after.intact}`);
  console.log("");
  // ★ 干跑也要把写入权还回去:否则目录里会留一把我们自己的锁,
  //   下一次真实写入会被判成"目录被占用"而改走分片 —— 那是自找的麻烦。
  await audit.releaseWriterLock();
  process.exit(0);
}

/**
 * ★ 标签事件的归属四要素沿用被标注的那条评分记录(traceId / sessionId /
 *   customerId / channel),而不是新造一个 traceId。
 *   理由:取证时最常问的是"这一笔当时怎么判的、后来怎么了" ——
 *   `audit.read(traceId)` 能一次拿到评分与结局,不必再做一次 join。
 *   替代方案(给标签事件发一个新 traceId)会让结局变成"孤岛事件",
 *   只能靠全表扫描找回来。
 *
 * ★ ts 用**此刻**(回填时刻),不是"结局发生时刻":
 *   结局发生的真实时刻落在 (记录 ts, 记录 ts + 窗口) 这个区间里,我们并不知道确切值。
 *   把 ts 写成过去,会让"这条事件是什么时候进链的"永远答不出来 ——
 *   而审计首先要回答的就是"记录本身可不可信"。
 */
let written = 0;
for (const p of truncated) {
  await audit.append({
    ts: Date.now(),
    traceId: p.record.traceId,
    sessionId: p.record.sessionId,
    customerId: p.record.customerId,
    channel: p.record.channel,
    type: "outcome_labeled",
    payload: {
      label: p.label,
      targetTraceId: p.record.traceId,
      customerId: p.record.customerId,
      windowDays: p.windowDays,
      source: p.source,
      ...(p.note ? { note: p.note } : {}),
      matchedBy: p.matchedBy,
    },
  });
  written++;
}

console.log("");
console.log(`  ✓ 已写入 ${written} 条 outcome_labeled 事件(落盘:${audit.path})`);
if (audit.isSegment) {
  console.log(
    "    ★ 注意:审计目录被另一个写入者持有,本次写进了分片文件 —— " +
      "下面的完整性结论只覆盖本进程这一段。",
  );
}

const after = await audit.verifyChain();
if (after.intact) {
  console.log("  ✓ 追加后哈希链仍然完整");
} else {
  console.log(`  ✗ 追加后哈希链已损坏,断点在第 ${after.brokenAtSeq ?? "?"} 条`);
}
console.log(`  链完整:${after.intact}`);
console.log("");
console.log("  下一步:npm run train-scorer(默认读同一个 ./var/audit)");
console.log("═".repeat(66));
console.log("");

await audit.releaseWriterLock();
process.exit(after.intact ? 0 : 2);
