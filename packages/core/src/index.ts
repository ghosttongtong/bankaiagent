export * from "./types.ts";
export * from "./audit/hashChain.ts";
export * from "./policy/engine.ts";
export * from "./intent/schema.ts";
export * from "./intent/resolvePayee.ts";
export * from "./intent/fuzzyName.ts";
export * from "./security/antiFraud.ts";
export * from "./security/injection.ts";
export * from "./capabilities/registry.ts";
export * from "./capabilities/wealth.ts";
export * from "./capabilities/transferFee.ts";
export * from "./capabilities/documentCompare.ts";
/**
 * 卡片引擎(场景四)。
 *
 * ★ 这里用显式导出而不是 `export *`,理由是"公开面一目了然" ——
 *   场景四对外给了哪些东西,在这一段里能直接数出来。
 *
 * ★ 顺带更正一句曾经的注释:原文说"卡片的 fmtDay/fmtMoney 与理财的同名但无关,
 *   `export *` 会冲突" —— 这句话**当时就是错的**:两处的 fmtDay 都是
 *   `YYYY-MM-DD`、两处的 fmtMoney 都是两位小数金额,是同名同义。
 *   现在这两个函数已收归 `util/format.ts` 单一实现(见该文件说明),
 *   两处 re-export 的是同一个声明,连"同名同义"的重复都没有了。
 */
export {
  CARD_KIND_LABELS,
  CARD_STATUS_LABELS,
  POST_DELIVERY_REQUIREMENTS,
  REPLACEMENT_ETA_DAYS,
  RESTRICTION_CAUSE_LABELS,
  RESTRICTION_CHANNEL_LABELS,
  LIMIT_RULES,
  buildReplacementOptions,
  canSubmitUnblock,
  checkLimitEligibility,
  describeCard,
  detectForbiddenDelegation,
  diagnoseRestriction,
  isCardBlocked,
  isCardLostOrFrozen,
  limitApplicationWording,
  matchCardByKindHint,
  matchCardByLast4,
  matchCardByNameHint,
  monthsBetween,
  renderCardList,
  requirementForScenario,
  restrictionChannelFor,
  scenarioForActivation,
  scenarioForReplacementMode,
} from "./capabilities/card.ts";
/**
 * 订阅代扣引擎(新场景)。
 *
 * ★ 这里可以安全地用 `export *`:引擎里的格式化函数刻意都带 `Sub` 前缀
 *   (fmtSubMoney / fmtSubDay),不与理财、卡片的同名函数相撞。
 *   前缀不是审美选择,是为了让"同名不同义"的坑不再出现第二次 ——
 *   金额与日期的口径如今统一在 `util/format.ts`,带前缀的这几个只是在那之上的包装。
 */
export * from "./capabilities/subscription.ts";
export * from "./capabilities/eventPlan.ts";
export * from "./agent/replyComposer.ts";
export * from "./retrieval/tokenizer.ts";
export * from "./retrieval/bm25.ts";
export * from "./retrieval/chunking.ts";
export * from "./retrieval/guard.ts";
export * from "./retrieval/index.ts";
export * from "./agent/turnExtras.ts";
export * from "./agent/flowTrace.ts";
export * from "./agent/provenance.ts";
export * from "./agent/suggestion.ts";
export * from "./agent/approval.ts";
export * from "./agent/brevity.ts";
export * from "./agent/anomalyReview.ts";
export * from "./agent/specialists.ts";
export * from "./agent/operationStatus.ts";
export * from "./agent/capabilityLabels.ts";
export * from "./agent/orchestrator.ts";
