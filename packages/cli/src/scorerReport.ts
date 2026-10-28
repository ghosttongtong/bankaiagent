/**
 * 评分器新旧对比报告(第 4 项第 4 步:验收证据)
 *
 * 用途:
 *   回答升级验收时唯一真正要回答的问题 ——
 *   **同一批请求,换评分器前后的档位分布是什么样、分歧有多少、分歧在哪。**
 *   做法:读审计链里已经落链的**特征输入**(`payload.riskFactors.features`),
 *   用 legacy 的分数与训练出来的模型各定一次档,逐条对比。
 *
 * ★ 为什么必须用"当时的输入"离线重算,而不是"把新旧分数都记在链上":
 *   链上记了旧分,但新模型是**事后**才训出来的 —— 它当时不存在,
 *   不可能有当时的影子分。要对比,只能拿当时那份输入快照重算。
 *   这也正是"把 features 单独落审计"的理由:没有它,新旧对比只能是
 *   "拿旧分数当输入",那是自欺。
 *   (若链上有 `scorer_divergence` 事件,说明那一刻影子模式真的跑过 ——
 *    本报告会把它与"离线重算"分开报,两者不是一回事。)
 *
 * ★ "legacy 列"到底是什么,必须说清楚:
 *   它就是记录里 `payload.riskFactors.score` —— **当时生效的那个评分器**给的分,
 *   不一定真的是 legacy 线性评分器。若某批记录是 `scorer=logistic` 时落的,
 *   这一列就是新模型自己的分,拿它去比"新旧"等于自己跟自己比。
 *   本报告因此额外打印每条的 scorer.mode 计数,并在出现非 legacy 记录时报警。
 *
 * 用法:
 *   node packages/cli/src/scorerReport.ts
 *   node packages/cli/src/scorerReport.ts --dir=D:\tmp\audit
 *   node packages/cli/src/scorerReport.ts --limit=200
 *   node packages/cli/src/scorerReport.ts --model=D:\tmp\trainedV1.ts   # 对比任意候选模型
 *   node packages/cli/src/scorerReport.ts --json          # 机器可读(测试用,stdout 整段可 JSON.parse)
 *
 *   参数:
 *     --dir=<path>    审计目录,默认 ./var/audit(相对路径按当前工作目录解析)
 *     --limit=<n>     只看链上最早的 n 条评分记录(按 seq 升序,保证多次运行结果一致)
 *     --model=<path>  挑战者模型文件(默认用仓库里那一份)。
 *                     ★ 为什么需要它:评估候选模型不该以"先把仓库那份覆盖掉"为代价 ——
 *                     覆盖之后基线就没了。正确顺序是 --model 先看分布与分歧 →
 *                     开影子模式线上观察 → 最后才决定换文件。
 *     --json          输出机器可读 JSON,不打标题框
 *
 * 退出码:
 *   0 正常
 *   1 没有评分记录 / 用法错误 / 模型特征顺序与引擎契约不一致 / --model 文件不存在或没导出模型
 *   2 审计链已损坏
 */

import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

import { HashChainAudit } from "../../core/src/audit/hashChain.ts";
import { RISK_FEATURE_NAMES, mapScoreToTier } from "../../core/src/policy/engine.ts";
import type { RiskFeatures } from "../../core/src/policy/engine.ts";
import { LOGISTIC_V1_MODEL } from "../../core/src/policy/model/logisticV1.ts";
import { assertModelMatchesFeatureNames, scoreWithModel } from "../../core/src/policy/scorer.ts";
import type { AuditEvent, Tier } from "../../core/src/types.ts";

// ============================================================================
// 零依赖参数解析(与 verifyAudit 同风格;三个 CLI 各自持有一份,理由见 labelOutcomes.ts)
// ============================================================================

function argValue(name: string): string | undefined {
  const hit = process.argv.slice(2).find((a) => a.startsWith(`--${name}=`));
  return hit ? hit.slice(name.length + 3) : undefined;
}

const jsonMode = process.argv.slice(2).includes("--json");
const auditDir = resolve(process.cwd(), argValue("dir") ?? "./var/audit");
const limitRaw = argValue("limit");

/** `--dir=`(空值)会被 resolve 成当前工作目录 —— 那不是"没给参数",是打错了 */
if (argValue("dir") != null && argValue("dir")!.trim() === "") {
  if (jsonMode) console.log(JSON.stringify({ ok: false, error: "--dir= 的值为空" }));
  else console.log("  ✗ --dir= 的值为空 —— 请给出真实路径(空值会被解析成当前目录)。");
  process.exit(1);
}

let limit = 0;
if (limitRaw != null) {
  const n = Number(limitRaw);
  if (!Number.isFinite(n) || n < 1) {
    /**
     * ★ --json 下连错误也要是 JSON:否则测试 `JSON.parse(stdout)` 会直接炸,
     *   而"错误路径输出的是人话、正常路径输出的是 JSON"是最容易被忽略的破绽。
     */
    if (jsonMode) console.log(JSON.stringify({ ok: false, error: `--limit=${limitRaw} 不是正整数` }));
    else console.log(`  ✗ 参数 --limit=${limitRaw} 不是正整数。`);
    process.exit(1);
  }
  limit = Math.floor(n);
}

/** 只允许这三档:mapScoreToTier 永远不返回 blocked(blocked 来自硬规则,不是评分) */
const TIERS: readonly Tier[] = ["auto", "confirm", "strong_auth"];

/**
 * ★ 要对比的挑战者模型(第 4 项第 3 步的治理工具)。
 *
 *   默认用仓库里那一份。`--model=<path>` 允许对**任意候选模型文件**做离线对比 ——
 *   这一点很重要:评估一个候选模型不该以"先把仓库里那份覆盖掉"为代价
 *   (覆盖之后就没有基线可比了,而且一不小心就把未验证的权重留在交付物里)。
 *   正确的顺序是:先 --model 看档位分布与分歧 → 再决定要不要开影子 → 最后才换文件。
 */
let challengerModel = LOGISTIC_V1_MODEL;
const modelPathRaw = argValue("model");
if (modelPathRaw != null) {
  const modelPath = resolve(process.cwd(), modelPathRaw);
  if (modelPathRaw.trim() === "" || !existsSync(modelPath)) {
    if (jsonMode) console.log(JSON.stringify({ ok: false, error: `--model 指向的文件不存在:${modelPath}` }));
    else console.log(`  ✗ --model 指向的文件不存在:${modelPath}`);
    process.exit(1);
  }
  /**
   * ★ 用带版本参数(?)的动态 import:同一进程里重复读同一个路径会命中模块缓存,
   *   于是"换了一份模型文件再跑"拿到的还是旧的 —— 这种假结果最难发现。
   */
  const mod = (await import(`${pathToFileURL(modelPath).href}?v=${Date.now()}`)) as Record<string, unknown>;
  const picked = (mod["LOGISTIC_V1_MODEL"] ?? mod["default"] ?? mod["model"]) as typeof LOGISTIC_V1_MODEL | undefined;
  if (picked == null || typeof picked !== "object" || !Array.isArray(picked.weights)) {
    if (jsonMode) {
      console.log(
        JSON.stringify({
          ok: false,
          error: `--model 文件里没有导出模型对象(应导出 LOGISTIC_V1_MODEL,含 id/featureNames/weights/bias)`,
        }),
      );
    } else {
      console.log("  ✗ --model 文件里没有导出模型对象(应导出 LOGISTIC_V1_MODEL)。");
    }
    process.exit(1);
  }
  challengerModel = picked;
}

// ============================================================================
// 读链
// ============================================================================

function readFeatures(raw: unknown): RiskFeatures | undefined {
  if (raw == null || typeof raw !== "object") return undefined;
  const obj = raw as Record<string, unknown>;
  const picked: Record<string, number> = {};
  for (const name of RISK_FEATURE_NAMES) {
    const v = obj[name];
    if (typeof v !== "number" || !Number.isFinite(v)) return undefined;
    picked[name] = v;
  }
  return picked as unknown as RiskFeatures;
}

interface Row {
  seq: number;
  traceId: string;
  /** 记录里 payload.riskFactors.score(当时生效的评分器给的分) */
  legacyScore: number;
  legacyTier: Tier;
  challengerTier: Tier;
  hardHit: boolean;
  /** payload.riskFactors.scorer.mode,旧记录没有则 undefined */
  scorerMode?: string;
  /** payload.riskFactors.shadow.divergent(记录自带的影子标记) */
  shadowDivergent: boolean;
}

function buildRows(events: readonly AuditEvent[]): { rows: Row[]; missingFeatures: number } {
  const rows: Row[] = [];
  let missingFeatures = 0;
  for (const e of events) {
    if (e.type !== "policy_evaluated") continue;
    const rawFactors = e.payload["riskFactors"];
    if (rawFactors == null || typeof rawFactors !== "object") continue;
    const snapshot = rawFactors as Record<string, unknown>;
    const legacyScore = snapshot["score"];
    if (typeof legacyScore !== "number" || !Number.isFinite(legacyScore)) continue;
    const features = readFeatures(snapshot["features"]);
    if (!features) {
      // 升级前落的链只有输出(score/factors)、没有输入(features):无法重算,如实计数
      missingFeatures++;
      continue;
    }
    const hardHit = features.watchlistHit === 1 || features.structuring === 1;
    const result = scoreWithModel(challengerModel, features, { hardHit, legacyScore });
    /**
     * ★ 硬命中用 `score`(硬顶格结果),非硬命中用 `learnedScore`:
     *   scoreWithModel 的 `score` 在硬命中时是"与 legacy 完全一致的确定性顶格",
     *   这正是线上会走的那条路;用 learnedScore 去比,等于拿一条线上不会执行的
     *   路径去算分歧,报告就会凭空多出一堆假分歧。
     */
    const challengerTier = mapScoreToTier(hardHit ? result.score : result.learnedScore);

    const scorer = snapshot["scorer"];
    const scorerMode =
      scorer != null && typeof scorer === "object" && typeof (scorer as Record<string, unknown>)["mode"] === "string"
        ? ((scorer as Record<string, unknown>)["mode"] as string)
        : undefined;
    const shadow = snapshot["shadow"];
    const shadowDivergent =
      shadow != null &&
      typeof shadow === "object" &&
      (shadow as Record<string, unknown>)["divergent"] === true;

    rows.push({
      seq: e.seq,
      traceId: e.traceId,
      legacyScore,
      legacyTier: mapScoreToTier(legacyScore),
      challengerTier,
      hardHit,
      ...(scorerMode ? { scorerMode } : {}),
      shadowDivergent,
    });
  }
  return { rows, missingFeatures };
}

/**
 * 从 scorer_divergence 事件里抽一句"分歧原因"。
 *
 * ★ 为什么写得这么宽:payload 的字段名由引擎(并行开发中)决定,
 *   报告**不应该因为引擎换了个字段名就报 0 条原因**——
 *   那会让"影子模式没有分歧"和"我没读懂 payload"看起来一模一样。
 *   所以按优先级依次尝试常见字段,最后回落到"用两侧档位拼一个原因",
 *   再不行才写"未标注原因"(并且这个字符串本身就说明要去看原始 payload)。
 */
function divergenceReason(payload: Record<string, unknown>): string {
  for (const key of ["reason", "divergenceReason", "note", "message", "detail"]) {
    const v = payload[key];
    if (typeof v === "string" && v.trim()) return v.trim();
  }
  const pick = (keys: string[]): string | undefined => {
    for (const k of keys) {
      const v = payload[k];
      if (typeof v === "string" && v.trim()) return v.trim();
    }
    return undefined;
  };
  const from = pick(["legacyTier", "fromTier", "from", "activeTier", "tier"]);
  const to = pick(["challengerTier", "toTier", "to", "shadowTier"]);
  if (from && to) return `${from} → ${to}`;
  return "未标注原因(请查看该条 scorer_divergence 的原始 payload)";
}

// ============================================================================
// 渲染
// ============================================================================

function pct(n: number, total: number): string {
  if (total === 0) return "  0.0%";
  return `${((n / total) * 100).toFixed(1)}%`;
}

function countCell(n: number, total: number): string {
  return `${String(n).padStart(5)} (${pct(n, total).padStart(6)})`;
}

if (!jsonMode) {
  console.log("");
  console.log("═".repeat(66));
  console.log("  评分器新旧对比报告(第 4 项:验收证据)");
  console.log("═".repeat(66));
  console.log(`  审计目录:${auditDir}`);
}

function fail(message: string, code: number): never {
  if (jsonMode) console.log(JSON.stringify({ ok: false, error: message }));
  else {
    console.log("");
    console.log(`  ✗ ${message}`);
    console.log("");
  }
  process.exit(code);
}

if (!existsSync(auditDir)) {
  fail(`审计目录不存在:${auditDir}(先跑一次演示产生评分记录)`, 1);
}

/**
 * ★ 模型特征顺序必须先与引擎契约对齐再出报告。
 *   理由:`scoreWithModel` 是按 `model.featureNames` 去 features 里按名取值的 ——
 *   顺序不一致时**不会报错**,只会静默地少喂/错喂特征,报告看起来一切正常。
 *   一份"看起来正常但对比对象是错的"验收证据,比没有证据更危险,所以这里直接退出 1。
 */
try {
  assertModelMatchesFeatureNames(challengerModel, RISK_FEATURE_NAMES);
} catch (err) {
  fail(`模型与引擎的特征契约不一致,报告无法作为验收证据:${(err as Error).message}`, 1);
}

const audit = new HashChainAudit({ auditDir });
const loaded = await audit.loadFromDisk();
if (!jsonMode) console.log(`  已载入事件:${loaded.loaded} 条`);

const chain = await audit.verifyChain();
if (!chain.intact) {
  fail(`审计链已损坏(断点在第 ${chain.brokenAtSeq ?? "?"} 条)—— 不可信的数据不能当验收证据`, 2);
}
if (!jsonMode) console.log(`  链完整性:✓ 完整(覆盖 ${chain.checkedEvents ?? 0} 条)`);

const events = await audit.readAll();
const built = buildRows(events);
const truncatedNote = limit > 0 && built.rows.length > limit;
const rows = limit > 0 ? built.rows.slice(0, limit) : built.rows;
const total = rows.length;

if (total === 0) {
  fail("链上没有可对比的评分记录(需要 payload.riskFactors.features;升级前的旧记录没有特征输入)", 1);
}

// ---- 统计 ----
const legacyDist = new Map<Tier, number>(TIERS.map((t) => [t, 0]));
const challengerDist = new Map<Tier, number>(TIERS.map((t) => [t, 0]));
const breakdown = new Map<string, number>();
let divergences = 0;
let hardHitCount = 0;
const modeCounts = new Map<string, number>();
let shadowFlagged = 0;

for (const r of rows) {
  legacyDist.set(r.legacyTier, (legacyDist.get(r.legacyTier) ?? 0) + 1);
  challengerDist.set(r.challengerTier, (challengerDist.get(r.challengerTier) ?? 0) + 1);
  if (r.hardHit) hardHitCount++;
  if (r.shadowDivergent) shadowFlagged++;
  modeCounts.set(r.scorerMode ?? "(未记录)", (modeCounts.get(r.scorerMode ?? "(未记录)") ?? 0) + 1);
  if (r.legacyTier !== r.challengerTier) {
    divergences++;
    const key = `${r.legacyTier} → ${r.challengerTier}`;
    breakdown.set(key, (breakdown.get(key) ?? 0) + 1);
  }
}

const shadowEvents = events.filter((e) => e.type === "scorer_divergence");
const shadowReasons = new Map<string, number>();
for (const e of shadowEvents) {
  const reason = divergenceReason(e.payload);
  shadowReasons.set(reason, (shadowReasons.get(reason) ?? 0) + 1);
}
/**
 * ★ 排序必须给定死并列规则:只按次数排,次数相同的两条在不同 Node 版本上
 *   顺序可能不同,"Top 3 原因"就变成不可复现的输出 —— 报告要进验收材料,
 *   就必须同一份链永远给出同一段文字。
 */
const topReasons = [...shadowReasons.entries()]
  .sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1))
  .slice(0, 5);
const breakdownSorted = [...breakdown.entries()].sort(
  (a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1),
);

const modelNote = challengerModel.note;
const modelSummary = {
  id: challengerModel.id,
  trainedAt: challengerModel.trainedAt,
  labelSource: challengerModel.labelSource,
  sampleSize: challengerModel.sampleSize,
  positives: challengerModel.positives,
  negatives: challengerModel.negatives,
  metrics: challengerModel.metrics,
  note: modelNote,
};

if (jsonMode) {
  console.log(
    JSON.stringify({
      ok: true,
      dir: auditDir,
      total,
      limited: truncatedNote,
      limit: limit > 0 ? limit : null,
      missingFeatures: built.missingFeatures,
      hardHit: hardHitCount,
      divergences,
      legacy: Object.fromEntries(TIERS.map((t) => [t, legacyDist.get(t) ?? 0])),
      challenger: Object.fromEntries(TIERS.map((t) => [t, challengerDist.get(t) ?? 0])),
      breakdown: breakdownSorted.map(([key, count]) => {
        const [from, to] = key.split(" → ");
        return { from, to, count };
      }),
      scorerModes: Object.fromEntries(modeCounts),
      shadow: {
        events: shadowEvents.length,
        topReasons: topReasons.map(([reason, count]) => ({ reason, count })),
        recordsFlaggedDivergent: shadowFlagged,
      },
      model: modelSummary,
      chain: { intact: chain.intact, checkedEvents: chain.checkedEvents ?? 0, legacyEvents: chain.legacyEvents ?? 0 },
    }),
  );
  process.exit(0);
}

// ---- 人读输出 ----
console.log("");
console.log("  ── 对比所用模型(先看这一段,再读数字)──");
console.log(`    ★ 模型 id      ${modelSummary.id}`);
console.log(`    ★ 训练时间     ${modelSummary.trainedAt}`);
console.log(`    ★ 样本量       ${modelSummary.sampleSize}(正 ${modelSummary.positives} / 负 ${modelSummary.negatives})`);
if (modelSummary.labelSource === "synthetic_demo") {
  console.log("    ✗ 标签来源     synthetic_demo(合成标签)");
  console.log("      ★ 合成标签**只能证明训练与推理管道跑通,不能证明模型能识别欺诈**。");
  console.log("        下面所有\"挑战者\"档位都只是演示,不能当作上线依据。");
} else {
  console.log("    ✓ 标签来源     external_feed(真实事后事实)");
  console.log("      ★ 但模型指标仍是训练集指标,泛化能力未经留出集验证。");
}
console.log(
  `    ★ 训练集指标   AUC ${modelSummary.metrics.auc.toFixed(2)} / ` +
    `准确率 ${modelSummary.metrics.accuracy.toFixed(2)} / 对数损失 ${modelSummary.metrics.logLoss.toFixed(2)}`,
);
console.log(`    ★ 模型自述     ${modelNote}`);

console.log("");
console.log(`  ── 记录范围 ──`);
console.log(`    参与对比:${total} 条评分记录(按 seq 升序取${truncatedNote ? `前 ${limit} 条` : "全部"})`);
if (built.missingFeatures > 0) {
  console.log(`    ★ 另有 ${built.missingFeatures} 条 policy_evaluated 没有 features(升级前的旧链),无法重算,已排除。`);
}
const nonLegacy = [...modeCounts.entries()].filter(([mode]) => mode !== "legacy");
console.log(
  `    ★ "legacy 列" = 记录里 payload.riskFactors.score,即**当时生效的评分器**给出的分。`,
);
console.log(`      本批 scorer.mode 计数:${[...modeCounts.entries()].map(([m, c]) => `${m}=${c}`).join(" ")}`);
if (nonLegacy.length > 0) {
  console.log("    ✗ 警告:本批记录里存在非 legacy 模式的评分 —— 此时\"legacy 列\"并不是基线,");
  console.log("      新旧对比会失真(极端情况下是拿着新模型的分跟新模型比)。请只用纯 legacy 记录做验收。");
}

console.log("");
console.log("═".repeat(66));
console.log(`  档位分布(共 ${total} 条)`);
console.log("═".repeat(66));
console.log("    档位           legacy              challenger");
for (const tier of TIERS) {
  const l = legacyDist.get(tier) ?? 0;
  const c = challengerDist.get(tier) ?? 0;
  const mark = l === c ? "✓" : "✗";
  console.log(`    ${mark} ${tier.padEnd(12)} ${countCell(l, total)}        ${countCell(c, total)}`);
}
console.log("  (评分档位只有 auto/confirm/strong_auth 三档;blocked 来自硬规则,不属于评分档位)");
console.log("═".repeat(66));

console.log("");
console.log(`  ── 分歧 ──`);
const rate = total === 0 ? 0 : (divergences / total) * 100;
console.log(
  `${divergences === 0 ? "    ✓" : "    ✗"} 档位分歧:${divergences} / ${total} 条(${rate.toFixed(1)}%)`,
);
if (breakdownSorted.length > 0) {
  console.log("    分歧明细(legacy 档位 → challenger 档位):");
  for (const [key, count] of breakdownSorted) {
    console.log(`      ✗ ${key.padEnd(26)} ${String(count).padStart(5)} 条 (${pct(count, total)})`);
  }
}
console.log(
  `    ★ 硬命中(名单/拆分)记录 ${hardHitCount} 条:两侧都由确定性规则定档,不交给模型` +
    "(这些记录不会产生分歧,因为两侧用的是同一个顶格规则)。",
);

console.log("");
console.log("  ── 影子模式证据(与上面的离线重算不是一回事)──");
if (shadowEvents.length === 0) {
  console.log("    ✗ 链上没有 scorer_divergence 事件:影子模式未开启或未落链。");
  console.log("      上面的分歧数来自**离线重算**(用当时的特征输入跑当前模型),");
  console.log("      它证明的是「同一批请求在新旧评分器下档位会怎么变」,");
  console.log("      不能替代当时那一刻影子模式留下的分歧证据。");
} else {
  console.log(`    ✓ 链上有 ${shadowEvents.length} 条 scorer_divergence 事件(影子模式确实跑过并留痕)`);
  for (const [reason, count] of topReasons) {
    console.log(`      ✗ ${String(count).padStart(5)} 条  ${reason}`);
  }
}
console.log(`    ★ 记录自带的 shadow.divergent 标记:${shadowFlagged} 条(逐条快照,与事件数是两种粒度)`);

console.log("");
console.log("═".repeat(66));
console.log(`  链完整性:${chain.intact ? "✓ 完整" : "✗ 已损坏"}`);
console.log("  一句话结论:以上档位分布与分歧数,是「同一批请求换评分器会怎样」的可复核证据;");
console.log("             它不回答\"新模型是否更准\"—— 那需要真实标签与留出集。");
console.log("═".repeat(66));
console.log("");

process.exit(0);
