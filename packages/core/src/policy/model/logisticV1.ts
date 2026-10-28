/**
 * ⚠️ 生成文件 —— 本文件由 `npm run train-scorer` 覆盖写入。
 *
 * 当前这份是**占位模型**（尚未用任何数据训练）：
 * 权重是把 legacy 的 `RISK_WEIGHTS` 按 1/20 线性映射到 log-odds 量纲得到的，
 * 目的是让影子模式与 `scorer=logistic` 在"还没训练"时也能跑通、也能解释，
 * 而不是抛错或者给所有请求打 50 分。
 *
 * ★★ 诚实声明 ★★
 *   占位模型与合成标签训出来的模型都**证明不了模型有效** ——
 *   它们只证明"评分器可替换、特征可复算、影子模式能对比分歧"这条管道是通的。
 *   真实效果需要真实的欺诈确认 / 投诉 / 退款标签（`external_feed`）。
 *
 * 生成方式：`npm run label-outcomes -- --synthetic 2000` 造标签
 *         → `npm run train-scorer`（读审计链 + 标签，写出本文件）。
 */
import type { LinearScorerModel } from "../scorer.js";

/** 占位（未训练）模型 */
export const LOGISTIC_V1_MODEL: LinearScorerModel = {
  id: "logistic_v1_placeholder",
  kind: "logistic",
  trainedAt: "未训练",
  /**
   * ★ 特征顺序必须**写死在生成文件里**，不能 `import { RISK_FEATURE_NAMES } from "../engine.js"`。
   *
   *   踩过的坑（实测，启动即崩）：那样会形成 engine → model → engine 的**运行时**循环导入，
   *   而且 `.js` 扩展名在"直接跑 .ts"的零构建环境下根本解析不到文件
   *   （报 ERR_MODULE_NOT_FOUND: .../policy/engine.js）。
   *   顺序是**契约**，契约就该随生成物一起固化；
   *   引擎在运行时用 `assertModelMatchesFeatureNames` 校验它，不一致就拒绝使用。
   */
  featureNames: [
    "amountExposure",
    "payeeFirstTime",
    "payeeThinHistory",
    "payeeTrusted",
    "payeeSelfOwned",
    "hourAnomaly",
    "channelRisk",
    "deviceUntrusted",
    "watchlistHit",
    "structuring",
    "sessionSuspicion",
    "trustCredit",
  ],
  // 顺序必须与 RISK_FEATURE_NAMES 一致：
  // amountExposure, payeeFirstTime, payeeThinHistory, payeeTrusted, payeeSelfOwned,
  // hourAnomaly, channelRisk, deviceUntrusted, watchlistHit, structuring,
  // sessionSuspicion, trustCredit
  weights: [1.2, 1.3, 0.65, 0.13, 0, 0.6, 0.8, 0.5, 5, 1.5, 0.9, -1.5],
  bias: -1.6,
  sampleSize: 0,
  positives: 0,
  negatives: 0,
  labelSource: "synthetic_demo",
  metrics: { auc: 0.5, accuracy: 0, logLoss: 0, epochs: 0, learningRate: 0, l2: 0 },
  note:
    "占位模型（未训练）：权重由 legacy RISK_WEIGHTS 线性映射而来。它只能证明评分器可替换，不能证明模型有效。",
};