/**
 * 评分器训练器(第 4 项第 2 步:训练)
 *
 * 用途:
 *   从审计链里读**评分记录**(`policy_evaluated` 的 `payload.riskFactors.features`)
 *   与**事后结局标签**(`outcome_labeled` 的 `payload.targetTraceId`),
 *   训练一个逻辑回归,并把结果写成**生成出来的源码模块**
 *   `packages/core/src/policy/model/logisticV1.ts`。
 *
 * ★ 为什么把训练结果写成 .ts 源码,而不是读一个 JSON 权重文件:
 *   core 包不读文件(与语料加载器放在 server 的理由一致),而且本仓库是
 *   **零构建、Node 24 直接跑 .ts**。生成源码模块才能让"包一进来就用得上"。
 *   代价是这个文件必须能被静态导入,于是它对自身形状有硬要求(见下)。
 *
 * ★★ 生成的模型文件**不允许有任何运行时 import** ★★
 *   ① `import { RISK_FEATURE_NAMES } from "../engine.js"` 会造成
 *      engine → model → engine 的循环导入,模型求值时读到 undefined;
 *   ② 本仓库 `.js` 说明符在运行时**解析不到**(零构建,没有 .js 文件),
 *      会直接 `ERR_MODULE_NOT_FOUND: .../policy/engine.js` ——
 *      实测已经让 npm test 崩过一次。所以特征名逐字写成字面量数组;
 *   ③ 唯一允许的是 type-only 导入(`import type ... from "../scorer.js"`),
 *      它在类型剥离时被擦除,不构成运行时依赖。
 *   这个约束由本脚本写完文件后**立刻自检**(退出码 3),不靠人记得。
 *
 * ★ 训练算法为什么是最朴素的批量梯度下降:
 *   我们要的不是"最强的模型",而是**可复现、可解释、零依赖**的模型。
 *   批量 GD 没有随机性(定序、不洗牌),同样的数据与超参在评委机器上
 *   得到的权重逐位相同;换成 SGD/Adam 反而要解释"随机种子怎么定"。
 *   特征都已在 0–1(引擎契约),所以不做标准化 —— 标准化会引入
 *   "训练时的均值方差"这份隐式状态,推理时忘带就是静默错分。
 *
 * ★ 硬命中(名单/拆分)样本**排除**出训练集:
 *   这部分请求的档位由确定性规则顶格,不交给模型。把它们留在训练集里,
 *   模型会花容量去拟合"watchlistHit=1 ⇒ 一定有问题",而这条路径
 *   在线上永远不会经过模型 —— 既浪费样本又制造假的 AUC。
 *
 * 用法:
 *   node packages/cli/src/trainScorer.ts
 *   node packages/cli/src/trainScorer.ts --dir=D:\tmp\audit
 *   node packages/cli/src/trainScorer.ts --epochs=400 --lr=1 --l2=0.01
 *   node packages/cli/src/trainScorer.ts --out=D:\tmp\logisticV1.ts   # 试跑/自检用
 *
 *   参数:
 *     --dir=<path>      审计目录,默认 ./var/audit(相对路径按当前工作目录解析)
 *     --epochs=<n>      训练轮数,默认 400
 *     --lr=<x>          学习率,默认 1
 *     --l2=<x>          L2 正则系数(只作用于权重,不作用于截距),默认 0.01
 *     --out=<path>      模型文件输出路径,默认 packages/core/src/policy/model/logisticV1.ts
 *
 * 退出码:
 *   0 正常
 *   1 用法错误 / 审计目录不存在 / 可用样本不足(< 20)/ 正负样本有一侧为空
 *     / 训练发散(权重或损失变成非有限数)
 *   2 审计链已损坏
 *   3 生成出来的模型文件自检不通过(特征名不匹配,或含有运行时 import)
 */

import { existsSync, statSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { HashChainAudit } from "../../core/src/audit/hashChain.ts";
import { RISK_FEATURE_NAMES } from "../../core/src/policy/engine.ts";
import type { RiskFeatures } from "../../core/src/policy/engine.ts";
import { scoreWithModel } from "../../core/src/policy/scorer.ts";
import type { LinearScorerModel } from "../../core/src/policy/scorer.ts";
import type { AuditEvent } from "../../core/src/types.ts";

// ============================================================================
// 零依赖参数解析(与 verifyAudit 同风格;三个 CLI 各自持有一份,理由见 labelOutcomes.ts)
// ============================================================================

function argValue(name: string): string | undefined {
  const hit = process.argv.slice(2).find((a) => a.startsWith(`--${name}=`));
  return hit ? hit.slice(name.length + 3) : undefined;
}

function numberArg(name: string, fallback: number): number {
  const raw = argValue(name);
  if (raw == null) return fallback;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) {
    console.log(`  ✗ 参数 --${name}=${raw} 不是正数。`);
    process.exit(1);
  }
  return n;
}

/**
 * `--name=`(值恰好为空)不是"没给这个参数",而是"给了一个空路径"。
 *
 * ★ 为什么必须单独挡一下:`resolve(cwd, "")` 的结果是**当前工作目录本身**,
 *   于是 `--out=` 会去 open 一个目录 → EISDIR 栈回溯(实测踩到),
 *   `--dir=` 会把整个仓库根当成审计目录,还可能在里面留下一把写入锁。
 *   静默回落成默认值同样不行:那会让一个打错的参数看起来生效了。
 */
function requireNonEmpty(name: string): void {
  const raw = argValue(name);
  if (raw != null && raw.trim() === "") {
    console.log(`  ✗ --${name}= 的值为空 —— 请给出真实路径(空值会被解析成当前目录)。`);
    process.exit(1);
  }
}

/** 默认输出路径:**相对本脚本**解析,而不是相对 cwd —— 从任何子目录调用都写对地方 */
const DEFAULT_MODEL_PATH = fileURLToPath(
  new URL("../../core/src/policy/model/logisticV1.ts", import.meta.url),
);

// ============================================================================
// 类型
// ============================================================================

type LabelKind = "fraud_confirmed" | "complaint_filed" | "refund_settled";
type LabelSource = "external_feed" | "synthetic_demo";

interface ScoringRecord {
  seq: number;
  ts: number;
  traceId: string;
  customerId: string;
  features: RiskFeatures;
  hardHit: boolean;
}

interface TrainingSample {
  seq: number;
  features: RiskFeatures;
  /** 0 / 1 */
  y: number;
  /** 该样本身上用到的标签来源(用于最终披露 labelSource) */
  labelSources: LabelSource[];
}

// ============================================================================
// 读取链上的特征与标签
// ============================================================================

/** 只认 RISK_FEATURE_NAMES 这一份名单;缺任意一项就当记录不可用(补 0 = 静默喂错数据) */
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

interface ScanResult {
  records: ScoringRecord[];
  withoutFeatures: number;
  labelsByTrace: Map<string, { label: LabelKind; source: LabelSource }[]>;
  labelsTotal: number;
}

function scanChain(events: readonly AuditEvent[]): ScanResult {
  const records: ScoringRecord[] = [];
  let withoutFeatures = 0;
  for (const e of events) {
    if (e.type !== "policy_evaluated") continue;
    const rawFactors = e.payload["riskFactors"];
    if (rawFactors == null || typeof rawFactors !== "object") continue;
    const features = readFeatures((rawFactors as Record<string, unknown>)["features"]);
    if (!features) {
      withoutFeatures++;
      continue;
    }
    records.push({
      seq: e.seq,
      ts: e.ts,
      traceId: e.traceId,
      customerId: e.customerId,
      features,
      hardHit: features.watchlistHit === 1 || features.structuring === 1,
    });
  }

  const labelsByTrace = new Map<string, { label: LabelKind; source: LabelSource }[]>();
  let labelsTotal = 0;
  for (const e of events) {
    if (e.type !== "outcome_labeled") continue;
    const target = e.payload["targetTraceId"];
    const label = e.payload["label"];
    const source = e.payload["source"];
    if (typeof target !== "string" || typeof label !== "string" || typeof source !== "string") continue;
    if (source !== "external_feed" && source !== "synthetic_demo") continue;
    const list = labelsByTrace.get(target) ?? [];
    list.push({ label: label as LabelKind, source });
    labelsByTrace.set(target, list);
    labelsTotal++;
  }

  return { records, withoutFeatures, labelsByTrace, labelsTotal };
}

// ============================================================================
// 指标(全部在**训练集**上算 —— 输出与生成文件里都必须写明这一点)
// ============================================================================

function sigmoid(z: number): number {
  if (z >= 0) return 1 / (1 + Math.exp(-z));
  const e = Math.exp(z);
  return e / (1 + e);
}

/**
 * 秩基 AUC(带并列平均秩)。
 *
 * ★ 为什么用秩基而不是"取阈值扫一遍":阈值扫描要先定一组阈值,
 *   阈值一变 AUC 就变,而 AUC 的定义本来就不依赖阈值。并列必须给平均秩
 *   (0.5 分),否则同一批同分样本的先后顺序会凭排序实现偷走 0.5 ——
 *   那正是"指标看起来是算出来的,其实是排出来的"。
 */
function computeAuc(items: readonly { p: number; y: number }[]): number {
  const pos = items.filter((i) => i.y === 1).length;
  const neg = items.length - pos;
  if (pos === 0 || neg === 0) return Number.NaN;
  const sorted = items
    .map((it, i) => ({ p: it.p, y: it.y, i }))
    .sort((a, b) => a.p - b.p || a.i - b.i);
  const ranks = new Array<number>(sorted.length).fill(0);
  let k = 0;
  while (k < sorted.length) {
    let j = k;
    while (j + 1 < sorted.length && sorted[j + 1]!.p === sorted[k]!.p) j++;
    const avgRank = (k + j) / 2 + 1; // 1 基平均秩
    for (let t = k; t <= j; t++) ranks[t] = avgRank;
    k = j + 1;
  }
  let sumPosRanks = 0;
  for (let t = 0; t < sorted.length; t++) if (sorted[t]!.y === 1) sumPosRanks += ranks[t]!;
  return (sumPosRanks - (pos * (pos + 1)) / 2) / (pos * neg);
}

interface Metrics {
  auc: number;
  accuracy: number;
  logLoss: number;
  tp: number;
  fp: number;
  tn: number;
  fn: number;
}

/**
 * 用 `scoreWithModel` 算概率,而不是在训练器里另写一遍 sigmoid(logit)。
 *
 * ★ 为什么要绕这一下:指标必须由**线上真正跑的那个推理函数**产生。
 *   若训练器自己实现一遍,哪天 scorer.ts 里的换算(比如概率→分数)
 *   改了,指标与线上就会悄悄分叉,而报告上一切正常 ——
 *   这是"看起来对、其实两套口径"的典型。
 */
function evaluate(model: LinearScorerModel, samples: readonly TrainingSample[]): Metrics {
  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;
  let loss = 0;
  const scored: { p: number; y: number }[] = [];
  for (const s of samples) {
    const { probability } = scoreWithModel(model, s.features, { hardHit: false, legacyScore: 0 });
    scored.push({ p: probability, y: s.y });
    /**
     * ★ 对数损失要夹住概率:概率恰好 0 或 1 时 log 会变成 Infinity,
     *   一个 Infinity 会把整个指标淹掉(而且只在极端样本上出现,极难察觉)。
     *   夹在 1e-12 上,损失变大但仍然是有限数 —— 如实反映"差一点就完全错了"。
     */
    const p = Math.min(1 - 1e-12, Math.max(1e-12, probability));
    loss += -(s.y * Math.log(p) + (1 - s.y) * Math.log(1 - p));
    const predicted = probability >= 0.5 ? 1 : 0;
    if (predicted === 1 && s.y === 1) tp++;
    else if (predicted === 1 && s.y === 0) fp++;
    else if (predicted === 0 && s.y === 0) tn++;
    else fn++;
  }
  return {
    auc: computeAuc(scored),
    accuracy: (tp + tn) / samples.length,
    logLoss: loss / samples.length,
    tp,
    fp,
    tn,
    fn,
  };
}

// ============================================================================
// 生成模型源码
// ============================================================================

/** 权重取 6 位小数:让"再训一次"的 diff 只反映真实变化,不反映浮点噪声 */
function round6(v: number): number {
  const r = Number(v.toFixed(6));
  return r === 0 ? 0 : r; // 把 -0 归一成 0,否则 diff 里会莫名出现 "-0.000000"
}

function tsString(s: string): string {
  return JSON.stringify(s);
}

function renderModelFile(args: {
  trainedAt: string;
  generatedBy: string;
  weights: number[];
  bias: number;
  sampleSize: number;
  positives: number;
  negatives: number;
  hardHitExcluded: number;
  auditDir: string;
  labelSource: LabelSource;
  metrics: Metrics;
  epochs: number;
  learningRate: number;
  l2: number;
}): string {
  const caveat =
    args.labelSource === "synthetic_demo"
      ? [
          "★★ 诚实声明:标签来源是 synthetic_demo(合成标签)★★",
          "  这些指标只证明「特征 → 训练 → 模型文件 → 推理」这条管道跑得通,",
          "  **不能**证明模型能识别欺诈 —— 它学到的相关是我们自己写进合成规则里的。",
          "  要判断效果,必须用 --feed 喂真实结局(external_feed),并做时间切分的留出集评估。",
        ]
      : [
          "★★ 诚实声明:标签来源是 external_feed(真实事后事实)★★",
          "  但上面的指标仍是**训练集**指标,没有留出集 —— 训练集分数不能当泛化能力。",
          "  另外\"无标签\"被当作负样本,而\"没被投诉/退款\"不等于\"没有欺诈\",",
          "  这是标签本身的天花板,真实部署前必须做时间切分的留出集评估。",
        ];

  const lines: string[] = [
    "/**",
    " * ⚠️ 生成文件 —— 本文件由训练器覆盖写入,请勿手改(手改会在下次训练时被覆盖)。",
    " *",
    ` * 标准生成命令:npm run label-outcomes -- --synthetic 2000 && npm run train-scorer`,
    ` * 实际生成命令:${args.generatedBy}`,
    ` * 生成时间(ISO):${args.trainedAt}`,
    ` * 审计目录:${args.auditDir}`,
    ` * 训练样本:${args.sampleSize}(正 ${args.positives} / 负 ${args.negatives});` +
      `硬命中排除 ${args.hardHitExcluded} 条(名单/拆分由确定性规则顶格,不交给模型)`,
    " *",
    " * 训练集指标(★ 是**训练集**指标,不是留出集,也不是线上指标):",
    ` *   AUC ${round6(args.metrics.auc).toFixed(6)}(0.5 = 随机)` +
      ` / 准确率 ${round6(args.metrics.accuracy).toFixed(6)}(阈值 0.5)` +
      ` / 对数损失 ${round6(args.metrics.logLoss).toFixed(6)}`,
    ` *   混淆:TP ${args.metrics.tp} / FP ${args.metrics.fp} / FN ${args.metrics.fn} / TN ${args.metrics.tn}`,
    " *",
    ` * 标签来源:${args.labelSource}`,
    ...caveat.map((l) => ` * ${l}`),
    " *",
    " * ★ 本文件刻意**没有任何运行时 import**(特征名与权重都是字面量):",
    " *   ① engine → model → engine 的循环导入会让模型求值时读到 undefined;",
    " *   ② 本仓库零构建、Node 24 直接跑 .ts,`.js` 说明符在运行时解析不到",
    " *      (ERR_MODULE_NOT_FOUND .../policy/engine.js);",
    " *   ③ 唯一允许的是 type-only 导入(类型剥离时被擦除,不构成运行时依赖)。",
    " *   featureNames 因此逐字写出;它与引擎 RISK_FEATURE_NAMES 是否一致,",
    " *   由 train-scorer 写完后立刻 import 复检(不一致 → 退出码 3),",
    " *   并由 scorer.ts 的 assertModelMatchesFeatureNames 在运行时再挡一道。",
    " */",
    'import type { LinearScorerModel } from "../scorer.js";',
    "",
    "export const LOGISTIC_V1_MODEL: LinearScorerModel = {",
    '  id: "logistic_v1",',
    '  kind: "logistic",',
    `  trainedAt: ${tsString(args.trainedAt)},`,
    "  // 顺序 = engine 的 RISK_FEATURE_NAMES,一格都不能错位(错位 = 权重套到别的特征上)",
    "  featureNames: [",
    ...RISK_FEATURE_NAMES.map((n) => `    ${tsString(n)},`),
    "  ],",
    "  // 权重(log-odds 空间),与 featureNames 同序;每个一行,方便 diff 定位",
    "  weights: [",
    ...args.weights.map((w) => `    ${round6(w).toFixed(6)},`),
    "  ],",
    `  bias: ${round6(args.bias).toFixed(6)},`,
    `  sampleSize: ${args.sampleSize},`,
    `  positives: ${args.positives},`,
    `  negatives: ${args.negatives},`,
    `  labelSource: ${tsString(args.labelSource)},`,
    `  metrics: { auc: ${round6(args.metrics.auc).toFixed(6)}, accuracy: ${round6(
      args.metrics.accuracy,
    ).toFixed(6)}, logLoss: ${round6(args.metrics.logLoss).toFixed(6)}, ` +
      `epochs: ${args.epochs}, learningRate: ${args.learningRate}, l2: ${args.l2} },`,
    `  note: ${tsString(buildNote(args))},`,
    "};",
    "",
  ];
  return lines.join("\n");
}

function buildNote(args: {
  labelSource: LabelSource;
  metrics: Metrics;
  sampleSize: number;
  positives: number;
}): string {
  const head =
    `训练集指标(非留出集,不代表泛化能力):AUC ${args.metrics.auc.toFixed(2)}` +
    ` / 准确率 ${args.metrics.accuracy.toFixed(2)} / 对数损失 ${args.metrics.logLoss.toFixed(2)}` +
    `;样本 ${args.sampleSize}(正 ${args.positives})。`;
  const tail =
    args.labelSource === "synthetic_demo"
      ? "标签来源 synthetic_demo(合成):只能证明训练与推理管道跑通,不能证明模型有效;真实效果需 external_feed 真实结局与留出集评估。"
      : "标签来源 external_feed(真实事后事实):指标仍是训练集指标,泛化能力需时间切分的留出集评估;无标签被当作负样本,不等于没有欺诈。";
  return head + tail;
}

// ============================================================================
// 主流程
// ============================================================================

const auditDir = resolve(process.cwd(), argValue("dir") ?? "./var/audit");
const outPath = resolve(process.cwd(), argValue("out") ?? DEFAULT_MODEL_PATH);
/**
 * ★ `--out` 存在的唯一理由:试跑与自检不能覆盖仓库里那份模型文件。
 *   本工具的默认行为(不传 --out)就是写那一份 —— 正常使用不受影响;
 *   但在"另一个进程可能正在改这个文件"或"只想验证训练管道"的场景下,
 *   必须有一条不动仓库产物的路径,否则验证就等于改生产文件。
 */
const outIsDefault = argValue("out") == null;

requireNonEmpty("dir");
requireNonEmpty("out");
/**
 * ★ 输出路径必须以 .ts 结尾,且不能是已存在的目录。
 *   生成物是 TypeScript 模块(带 type-only import 与类型标注),
 *   写成别的扩展名在"直接跑 .ts"的环境里根本加载不了;
 *   而指向一个目录时 `writeFile` 只会抛 EISDIR 栈回溯 ——
 *   参数错误的报错不该长得像程序崩了。
 */
if (!outPath.endsWith(".ts")) {
  console.log(`  ✗ --out 必须以 .ts 结尾(生成物是 TypeScript 模块):${outPath}`);
  process.exit(1);
}
try {
  if (statSync(outPath).isDirectory()) {
    console.log(`  ✗ --out 指向一个目录,不是文件:${outPath}`);
    process.exit(1);
  }
} catch {
  // 文件不存在是正常情况(马上创建);其余错误交给下面的 writeFile 如实抛出
}
const epochs = Math.floor(numberArg("epochs", 400));
const learningRate = numberArg("lr", 1.0);
const l2 = numberArg("l2", 0.01);

console.log("");
console.log("═".repeat(66));
console.log("  评分器训练(第 4 项:逻辑回归)");
console.log("═".repeat(66));
console.log(`  审计目录:${auditDir}`);
console.log(`  超参:epochs=${epochs} lr=${learningRate} l2=${l2}(批量 GD,定序、不洗牌、无随机数)`);
console.log(`  模型输出:${outPath}${outIsDefault ? "(默认路径)" : "(--out 覆盖)"}`);

if (!existsSync(auditDir)) {
  console.log("");
  console.log("  ✗ 审计目录不存在 —— 没有可训练的数据。");
  console.log("    先跑演示产生评分记录,再用 npm run label-outcomes 回填结局。");
  console.log("");
  process.exit(1);
}

const audit = new HashChainAudit({ auditDir });
const loaded = await audit.loadFromDisk();
console.log(`  已载入事件:${loaded.loaded} 条`);

const chain = await audit.verifyChain();
if (!chain.intact) {
  console.log("");
  console.log(`  ✗ 审计链已损坏(断点在第 ${chain.brokenAtSeq ?? "?"} 条)—— 拒绝用不可信的数据训练。`);
  console.log("    训练集本身不可信,模型就是不可信的 —— 先跑 npm run verify-audit。");
  console.log("");
  process.exit(2);
}
console.log(`  链完整性:✓ 完整(覆盖 ${chain.checkedEvents ?? 0} 条)`);

const events = await audit.readAll();
const scanned = scanChain(events);

// ---- 数据集 ----
const samples: TrainingSample[] = [];
let hardHitExcluded = 0;
let labelsOnTrainable = 0;
let labelsOnHardHit = 0;
const trainableTraces = new Set<string>();

for (const record of scanned.records) {
  if (record.hardHit) {
    hardHitExcluded++;
    if (scanned.labelsByTrace.has(record.traceId)) labelsOnHardHit++;
    continue;
  }
  const labels = scanned.labelsByTrace.get(record.traceId) ?? [];
  labelsOnTrainable += labels.length;
  trainableTraces.add(record.traceId);
  samples.push({
    seq: record.seq,
    features: record.features,
    /**
     * ★ "有标签 = 正样本,无标签 = 负样本"是这套标签管道的**根本假设**,
     *   必须写在输出里:漏报(欺诈发生了但没人投诉、没退款)会被当成负样本,
     *   于是模型学到的先验偏低。这是标签天花板,不是可以靠调参解决的。
     */
    y: labels.length > 0 ? 1 : 0,
    labelSources: labels.map((l) => l.source),
  });
}

let labelsUnmatched = 0;
for (const [traceId, list] of scanned.labelsByTrace) {
  if (trainableTraces.has(traceId)) continue;
  // 既不在可训练集里,也不是硬命中 → 它的评分记录根本没有 features(旧链)
  labelsUnmatched += list.length;
}

const positives = samples.filter((s) => s.y === 1).length;
const negatives = samples.length - positives;

console.log("");
console.log("  ── 数据集 ──");
console.log(`    评分记录(带 features):${scanned.records.length} 条,其中硬命中排除 ${hardHitExcluded} 条`);
if (scanned.withoutFeatures > 0) {
  console.log(`    ★ ${scanned.withoutFeatures} 条 policy_evaluated 没有 features(升级前的旧链),已跳过。`);
}
console.log(`    可用训练样本:${samples.length}(正 ${positives} / 负 ${negatives})`);
console.log(`    链上标签:${scanned.labelsTotal} 条;落在可训练样本上 ${labelsOnTrainable} 条`);
if (labelsOnHardHit > 0) console.log(`    落在硬命中记录上(不参与训练)${labelsOnHardHit} 条`);
if (labelsUnmatched > 0) console.log(`    ★ 指向无法训练的评分记录(旧链,缺 features)${labelsUnmatched} 条`);
console.log("    ★ 无标签记为负样本:漏报会被当成负样本,这是标签天花板,不是调参能解决的。");

if (samples.length < 20) {
  console.log("");
  console.log(`  ✗ 可用样本只有 ${samples.length} 条(< 20)—— 样本量不足以训出一个能看的模型。`);
  console.log("    这不是「再跑一次就好」的问题:几十条样本上训出来的 12 维权重,");
  console.log("    任何一条新数据都能把它推翻。先用 --synthetic 造足量的演示样本,或等真实标签积累。");
  console.log("");
  process.exit(1);
}
if (positives < 1 || negatives < 1) {
  console.log("");
  console.log(
    `  ✗ 正负样本有一侧为空(正 ${positives} / 负 ${negatives})—— 拒绝训练。` +
      "此时梯度只会把权重收缩成 0、截距推到极端,写出去的\"模型\"是常数函数,",
  );
  console.log("    那等于给系统装了一个假模型。请先回填标签:npm run label-outcomes -- --synthetic=...");
  console.log("");
  process.exit(1);
}
if (positives < 5) {
  console.log("");
  console.log("  ★★ 警告:正样本只有 " + positives + " 条(< 5)★★");
  console.log("    这个模型**不可信** —— 不是「效果一般」,而是统计上什么都说明不了:");
  console.log("    5 条正样本算出来的 AUC 可以凭运气是 0.95,也可以凭运气是 0.2。");
  console.log("    继续跑只是为了验证管道;任何结论都必须等真实标签(且量级足够)之后再说。");
  console.log("");
}

// ---- 训练:批量梯度下降 ----
const d = RISK_FEATURE_NAMES.length;
const n = samples.length;
const w = new Array<number>(d).fill(0);
let b = 0;
const initialLoss = (() => {
  let loss = 0;
  for (const s of samples) {
    const p = Math.min(1 - 1e-12, Math.max(1e-12, sigmoid(b)));
    loss += -(s.y * Math.log(p) + (1 - s.y) * Math.log(1 - p));
  }
  return loss / n;
})();

let diverged = false;
for (let epoch = 0; epoch < epochs; epoch++) {
  const gw = new Array<number>(d).fill(0);
  let gb = 0;
  for (const s of samples) {
    // 特征按 RISK_FEATURE_NAMES 顺序取(与模型契约同一份名单)
    let z = b;
    for (let j = 0; j < d; j++) z += w[j]! * s.features[RISK_FEATURE_NAMES[j]!];
    const err = sigmoid(z) - s.y;
    for (let j = 0; j < d; j++) gw[j] = (gw[j] ?? 0) + err * s.features[RISK_FEATURE_NAMES[j]!];
    gb += err;
  }
  for (let j = 0; j < d; j++) w[j] = w[j]! - learningRate * ((gw[j] ?? 0) / n + l2 * w[j]!);
  /**
   * ★ 截距**不加正则**:L2 惩罚截距等于把"基准风险"往 0 拽,
   *   而这里的基准风险(正样本先验)恰恰是要如实保留的量。
   *   正则的目的是防止权重被单条样本带跑,和截距无关。
   */
  b -= learningRate * (gb / n);

  if (!Number.isFinite(b) || w.some((x) => !Number.isFinite(x))) {
    diverged = true;
    break;
  }
}

if (diverged) {
  console.log("");
  console.log("  ✗ 训练发散:权重或截距变成了非有限数(NaN / Infinity)—— 拒绝写出这样的模型文件。");
  console.log(`    通常是学习率过大(当前 --lr=${learningRate});特征取值域是 0–1、共 ${d} 维,`);
  console.log("    批量 GD 的稳定上界大约在 lr < 2 / (0.25 × 特征秩),试试 --lr=0.5 或 0.1。");
  console.log("    ★ 这里刻意**不做梯度裁剪**:裁剪会让\"发散\"变成\"悄悄停在某处\",");
  console.log("      而一个停在半路的模型看起来和正常模型一模一样。宁可失败得清楚。");
  console.log("");
  process.exit(1);
}

// ---- 指标(训练集)----
const trainedAt = new Date().toISOString();
const labelSource: LabelSource = samples
  .filter((s) => s.y === 1)
  .some((s) => s.labelSources.includes("synthetic_demo"))
  ? "synthetic_demo"
  : "external_feed";

/**
 * ★ labelSource 取"最弱证据"口径:只要**任何一个正样本**用到了合成标签,
 *   整份模型就标成 synthetic_demo。反过来(有真实标签就标 external_feed)
 *   会把"混了合成数据的模型"包装成真实模型 —— 那正是我们要防的事。
 */
const draft: LinearScorerModel = {
  id: "logistic_v1",
  kind: "logistic",
  trainedAt,
  featureNames: RISK_FEATURE_NAMES,
  weights: w,
  bias: b,
  sampleSize: n,
  positives,
  negatives,
  labelSource,
  metrics: { auc: 0, accuracy: 0, logLoss: 0, epochs, learningRate, l2 },
  note: "训练中(占位,写文件前会被真实 note 覆盖)",
};
const metrics = evaluate(draft, samples);

console.log("");
console.log("  ── 训练集指标(★ 训练集,不是留出集,也不是线上指标)──");
console.log(`    最终对数损失   ${metrics.logLoss.toFixed(2)}(起始 ${initialLoss.toFixed(2)})`);
console.log(`    AUC            ${Number.isFinite(metrics.auc) ? metrics.auc.toFixed(2) : "不可计算"}(0.5 = 随机)`);
console.log(`    准确率         ${metrics.accuracy.toFixed(2)}(阈值 0.5)`);
console.log(`    混淆矩阵       TP ${metrics.tp} / FP ${metrics.fp} / FN ${metrics.fn} / TN ${metrics.tn}`);
console.log(`    标签来源       ${labelSource}` + (labelSource === "synthetic_demo" ? "(合成:只能证明管道跑通,不能证明模型有效)" : "(真实事后事实)"));

const generatedBy =
  `node packages/cli/src/trainScorer.ts --dir=${auditDir} --epochs=${epochs} --lr=${learningRate} --l2=${l2}` +
  (outIsDefault ? "" : ` --out=${outPath}`);
const content = renderModelFile({
  trainedAt,
  generatedBy,
  weights: w,
  bias: b,
  sampleSize: n,
  positives,
  negatives,
  hardHitExcluded,
  auditDir,
  labelSource,
  metrics,
  epochs,
  learningRate,
  l2,
});

/**
 * ★ 写文件前先自检"这份源码里没有运行时 import"。
 *   这不是洁癖:一旦生成的文件带运行时 import(实测发生过,
 *   `import { RISK_FEATURE_NAMES } from "../engine.js"` 直接让 npm test
 *   崩在 ERR_MODULE_NOT_FOUND 上,而且 `.js` 说明符在零构建仓库里根本解析不到),
 *   整个 core 包都加载不起来。宁可在写盘这一刻就拦住。
 */
const runtimeImport = /^\s*import\s+(?!type\s)[^\n]*from\s/m.exec(content);
if (runtimeImport) {
  console.log("");
  console.log("  ✗ 生成内容里出现了运行时 import,已拒绝写盘:");
  console.log(`    ${runtimeImport[0].trim()}`);
  console.log("    生成文件只允许 `import type ...`(类型剥离后不构成运行时依赖)。");
  console.log("");
  process.exit(3);
}

// ★ --out 可以指到还不存在的目录(试训常用):写盘前递归建目录,
//   否则 writeFile 直接 ENOENT,训练全白跑。
await mkdir(dirname(outPath), { recursive: true });
await writeFile(outPath, content, "utf8");
console.log("");
console.log(`  ✓ 模型文件已写入:${outPath}(${content.split("\n").length - 1} 行)`);

// ---- 自检:立刻 import 回来,验证特征名逐格一致 ----
const moduleUrl = `${pathToFileURL(outPath).href}?v=${Date.now()}`;
let featureNames: unknown;
try {
  const mod = (await import(moduleUrl)) as { LOGISTIC_V1_MODEL?: { featureNames?: unknown } };
  featureNames = mod.LOGISTIC_V1_MODEL?.featureNames;
} catch (err) {
  console.log("");
  console.log("  ✗ 自检失败:刚写出的模型文件无法被 import。");
  console.log(`    ${(err as Error).message}`);
  console.log("    这说明它不能在本仓库的零构建运行方式下被加载,必须修好再收工。");
  console.log("");
  process.exit(3);
}

const okLength = Array.isArray(featureNames) && featureNames.length === RISK_FEATURE_NAMES.length;
/**
 * ★ 逐格比较字符串,**不比较对象同一性**:
 *   生成文件里的 featureNames 是字面量数组(刻意的,见文件头),
 *   它与 engine 的 RISK_FEATURE_NAMES 永远是两个不同的对象 ——
 *   拿 `===` 或 Array.isArray 之外的同一性判断,只会把正确的东西判成错的。
 */
const okOrder =
  okLength &&
  (featureNames as unknown[]).every((name, i) => name === RISK_FEATURE_NAMES[i]);

if (!okOrder) {
  console.log("");
  console.log("  ✗ 自检失败:生成模型的 featureNames 与引擎契约不一致!");
  console.log(`    模型:${Array.isArray(featureNames) ? featureNames.join(",") : String(featureNames)}`);
  console.log(`    引擎:${RISK_FEATURE_NAMES.join(",")}`);
  console.log("    权重会错位套到别的特征上 —— 这是「看起来能跑、分数全是错的」那类缺陷。");
  console.log("    已写出文件但**不认为训练成功**(退出码 3),请修好 renderModelFile 后重跑。");
  console.log("");
  process.exit(3);
}

console.log(`  ✓ 自检通过:特征名 ${RISK_FEATURE_NAMES.length} 项逐格一致,文件无运行时 import`);
if (labelSource === "synthetic_demo") {
  console.log("  ★ 提醒:这份模型由合成标签训练,只能证明管道跑通,不能证明模型有效。");
}
console.log("");
console.log("  下一步:npm run scorer-report(看新旧档位分布与分歧)");
console.log("═".repeat(66));
console.log("");
process.exit(0);
