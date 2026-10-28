/**
 * ★ 第 4 项:评分器（把"手调线性权重"换成"训练出来的逻辑回归"）。
 *
 * 这一步换的**只是评分器**，裁决体系一行没动：
 *   · 输出仍然是 0–100 分；
 *   · `mapScoreToTier` 的阈值（28 / 62）一个字都没改；
 *   · 名单命中与拆分交易仍然走**确定性顶格**，不交给模型；
 *   · 硬规则（deny / force_tier）照旧在评分之前/之后覆盖。
 * 这是现有架构"评分与分级分离"的红利 —— 换模型不等于换裁决。
 *
 * ---------------------------------------------------------------
 * ★★ 必须说清楚的一句话（答辩也会被追问）★★
 *
 *   比赛环境**没有真实欺诈标签**。本文件配套的训练管道能跑通，
 *   标签可以由 `external_feed`（真实事后事实：欺诈确认 / 投诉 / 退款）
 *   喂进来；但在演示与自测里，我们只能用 **synthetic_demo** 合成标签来
 *   证明"管道是通的、模型能被训练、影子模式能对比"。
 *
 *   合成标签**证明不了模型有效**：它证明的是工程链路完整，
 *   不是"这个模型能识别欺诈"。所以：
 *     · 生成的模型文件里 `labelSource` 字段必须如实写 synthetic_demo；
 *     · 影子模式只**报告分歧**，不接管裁决；
 *     · 文档与 CLI 输出里都带这句声明，不吹。
 * ---------------------------------------------------------------
 *
 * 零依赖：训练与推理都只用四则运算（`npm run train-scorer` 训练，
 * 训练结果写成 `policy/model/logisticV1.ts` 这个**生成出来的源码模块**）。
 * 为什么生成成 .ts 而不是读 JSON 文件：core 包不读文件（与语料加载器
 * 放在 server 的理由一致），零构建 + 静态导入才能保证"包一进来就用得上"。
 */
import type { RiskFactor, RiskFeatures } from "./engine.js";

/**
 * ★ 依赖方向刻意是"单向的":scorer 只 `import type` 引擎里的**类型**
 *   （编译后被擦除），运行时不回指引擎 —— 否则就会出现
 *   engine → model → engine 的循环导入，模型文件在求值时读到 undefined。
 *   特征顺序因此由**模型自己携带**（`model.featureNames`），
 *   引擎只负责校验"模型的特征顺序与当前契约一致"。
 */

/** 评分器标识（进审计，用于回答"这一笔是谁打的分"） */
export const LEGACY_SCORER_ID = "legacy_linear_v1";

/** 训练出来的线性模型（逻辑回归） */
export interface LinearScorerModel {
  id: string;
  kind: "logistic";
  /** 生成时间（由训练器写入，便于回答"这个模型是什么时候训的"） */
  trainedAt: string;
  /** 特征名顺序：必须与 RISK_FEATURE_NAMES 完全一致 */
  featureNames: readonly string[];
  /** 权重（与 featureNames 同序，log-odds 空间） */
  weights: readonly number[];
  /** 截距（log-odds 空间） */
  bias: number;
  /** 训练样本量与标签分布（诚实披露的一部分：样本多少、几正几负） */
  sampleSize: number;
  positives: number;
  negatives: number;
  /**
   * 标签来源。
   *   external_feed  —— 真实事后事实（生产口径）
   *   synthetic_demo —— 合成标签（**只能证明管道通了**）
   */
  labelSource: "external_feed" | "synthetic_demo";
  /** 训练时算出的指标（合成标签下的指标只反映"能不能学"，不代表真实效果） */
  metrics: {
    /** 训练集上的 AUC（0.5 = 随机） */
    auc: number;
    accuracy: number;
    logLoss: number;
    /** 训练轮数/学习率，便于复现 */
    epochs: number;
    learningRate: number;
    l2: number;
  };
  /** 一句人话说明（会随审计一起被看到） */
  note: string;
}

/**
 * 推理：把特征向量映射到 0–100 分。
 *
 * 分数语义与 legacy 保持**同一量纲**（都是"这 0–100 分里越高越该验证"），
 * 因此阈值可以一个字都不动。概率 → 分数的换算刻意用 100×p：
 * 它单调、可解释（"模型认为高风险的概率"），并且 p=0.28/0.62 恰好
 * 对应 legacy 的两条阈值 —— 迁移时不需要重新校准阈值口径。
 */
export function scoreWithModel(
  model: LinearScorerModel,
  features: RiskFeatures,
  options: { hardHit: boolean; legacyScore: number },
): {
  /** 模型给出的 0–100 分（未叠加硬命中顶格） */
  learnedScore: number;
  /** 最终分：硬命中时与 legacy 完全一致地顶格 */
  score: number;
  /** 概率 */
  probability: number;
  /** 因子贡献（分数空间，可加：score ≈ base + Σ contribution） */
  factors: RiskFactor[];
  /** 硬命中是否接管了最终分 */
  hardOverride: boolean;
} {
  const order = model.featureNames;
  const vector = order.map((n) => (features as unknown as Record<string, number>)[n] ?? 0);
  let logit = model.bias;
  for (let i = 0; i < vector.length; i++) logit += (model.weights[i] ?? 0) * (vector[i] ?? 0);

  const probability = sigmoid(logit);
  const learnedScore = clamp100(probability * 100);

  /**
   * 因子贡献度按"分数空间"给,而不是直接暴露 log-odds 权重:
   *   贡献_i = 100 × [sigmoid(logit) − sigmoid(logit − w_i·x_i)]
   * 也就是"去掉这个特征后分数会掉多少"。这样：
   *   · 每个因子的单位与客户看到的分数**同一量纲**（可解释性契约不破）;
   *   · 负贡献（信任降级）自然是负数，与 legacy 的 trust_credit 语义一致。
   *
   * ★ 可加性：**精确**成立，但基准分要吸收非线性残差（实测校准过，见下）。
   *
   *   sigmoid 是非线性的，所以"每个特征的单独移除效果"直接相加**不**等于总分 −
   *   sigmoid(bias) 基准：实测占位权重下残差可达 6 分（小额 −1.6 / 大额 +6.0）。
   *   若把基准分写成 100×sigmoid(bias)，注释里说的"加起来等于总分"就是假的 ——
   *   审计一旦真的去加，就会发现对不上账。
   *   因此基准分取 `learnedScore − Σ 特征贡献`，让
   *      基准分 + Σ 特征贡献 **严格等于** 模型分
   *   成为一个可核对恒等式；残差被显式写进基准分的说明文字里，不藏。
   *
   *   注意：硬命中时最终分被确定性顶格，此时贡献之和**不会**等于最终分 ——
   *   这与 legacy 的信任降级在算分后才入列是同一类"设计特性"，不是 bug。
   */
  const featureFactors: RiskFactor[] = order.map((name, i) => {
    const w = model.weights[i] ?? 0;
    const x = vector[i] ?? 0;
    const contribution = 100 * (probability - sigmoid(logit - w * x));
    return {
      name,
      contribution,
      detail: featureDetail(name, x, w),
    };
  });
  const pureBase = sigmoid(model.bias) * 100;
  const featureSum = featureFactors.reduce((s, f) => s + f.contribution, 0);
  const base = learnedScore - featureSum;
  const factors: RiskFactor[] = [
    ...featureFactors,
    {
      name: "model_base",
      contribution: base,
      detail:
        `模型基准分 ${base.toFixed(1)}（截距 ${model.bias.toFixed(3)}）` +
        `；其中含 sigmoid 非线性残差 ${(base - pureBase).toFixed(1)} 分` +
        `（纯截距基准分 ${pureBase.toFixed(1)}），吸收进基准分是为了让` +
        `「基准分 + 各因子贡献」严格等于模型分，审计可直接核对` +
        `；模型 ${model.id}`,
    },
  ];

  const hardOverride = options.hardHit;
  const score = hardOverride ? Math.min(100, Math.max(80, options.legacyScore)) : learnedScore;

  return { learnedScore, score, probability, factors, hardOverride };
}

function sigmoid(z: number): number {
  if (z >= 0) return 1 / (1 + Math.exp(-z));
  const e = Math.exp(z);
  return e / (1 + e);
}

function clamp100(n: number): number {
  return Math.max(0, Math.min(100, n));
}

/** 特征取值 → 人话（与 legacy 的 detail 同样是"给客户/审计看的解释"） */
function featureDetail(name: string, value: number, weight: number): string {
  const sign = weight >= 0 ? "+" : "−";
  switch (name) {
    case "amountExposure":
      return `金额敞口 ${(value * 100).toFixed(0)}%（相对客户 P95 归一化）`;
    case "payeeFirstTime":
      return value ? "首次向该收款人转账" : "非首次转账";
    case "payeeThinHistory":
      return value ? "与该收款人历史成功转账不足 3 笔" : "历史往来已达信任门槛";
    case "payeeTrusted":
      return value ? "已建立信任的收款人" : "未达到信任条件";
    case "payeeSelfOwned":
      return value ? "本人名下账户互转" : "非本人账户";
    case "hourAnomaly":
      return value ? "当前不在客户常用时段" : "常用时段内";
    case "channelRisk":
      return `渠道风险 ${(value * 100).toFixed(0)}%`;
    case "deviceUntrusted":
      return value ? "未绑定可信设备" : "已绑定可信设备";
    case "watchlistHit":
      return value ? "命中阻断级名单（由确定性规则顶格）" : "未命中名单";
    case "structuring":
      return value ? "存在拆分交易特征（由确定性规则顶格）" : "无拆分特征";
    case "sessionSuspicion":
      return value ? `会话可疑度 ${(value * 100).toFixed(0)}%（连续注入命中）` : "会话无可疑注入";
    case "trustCredit":
      return value ? `信任降级强度 ${(value * 100).toFixed(0)}%` : "无信任降级";
    default:
      return `特征 ${name} = ${value}（权重 ${sign}${Math.abs(weight).toFixed(3)}）`;
  }
}

/**
 * 校验"模型的特征顺序"与"引擎当前的特征契约"一致。
 *
 * ★ 为什么要有这个运行时校验（而不是靠类型）：
 *   模型文件是**生成出来的**（`npm run train-scorer`）。若哪天引擎里
 *   新增/调整了一个特征而没重新训练，权重就会错位套到别的特征上 ——
 *   那是"看起来能跑、分数全是错的"这类最危险的缺陷。
 *   宁可在这里直接抛错，也不要静默算出一堆错分。
 */
export function assertModelMatchesFeatureNames(
  model: LinearScorerModel,
  expected: readonly string[],
): void {
  const a = model.featureNames.join(",");
  const b = expected.join(",");
  if (a !== b) {
    throw new Error(
      `评分模型 ${model.id} 的特征顺序与引擎契约不一致，拒绝使用。\n  模型：${a}\n  引擎：${b}\n` +
        `  处理：重新运行 npm run train-scorer 生成模型（或修正 model/logisticV1.ts）。`,
    );
  }
}