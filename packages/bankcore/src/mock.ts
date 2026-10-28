/**
 * 模拟银行核心(Mock Bank Core)
 *
 * 生产环境下这一层是对核心系统的受限服务调用。比赛中用内存账本替代,
 * 但**数据结构、状态机、幂等语义、可撤销窗口都按真实系统建模** ——
 * 这样 Agent 侧的代码在换成真实核心时不需要改逻辑。
 *
 * 这里同时是**数据脱敏边界**:所有对外暴露的账号都是掩码形式,
 * 完整账号只在内部账本中存在,永不进入 LLM 上下文。
 */

import { createHash } from "node:crypto";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";

import type {
  Account,
  BankPort,
  BankCard,
  CancelResult,
  CardActivationReceipt,
  CardApplication,
  CardApplicationInput,
  CardLimitAdjustment,
  CardLimitAdjustmentInput,
  CardLimitAdjustmentReceipt,
  CardLossReceipt,
  CardReplacementInput,
  CardReplacementOrder,
  CardRestriction,
  CardUnblockInput,
  CardUnblockReceipt,
  BankSubscription,
  Collection,
  CollectionIntent,
  CustomerDocument,
  DeliverabilityResult,
  EventExternalStepInput,
  EventExternalStepReceipt,
  EventFundStepInput,
  EventFundStepReceipt,
  ExternalMerchant,
  LifeEvent,
  LifeEventInput,
  Payee,
  PayeeQuery,
  Schedule,
  ScheduleIntent,
  ScreeningResult,
  SubscriptionCadence,
  SubscriptionCancelInput,
  SubscriptionCancelReceipt,
  Transaction,
  TransactionQuery,
  TransferDraft,
  TransferIntent,
  TransferReceipt,
  DemandDepositRate,
  MaturityDisposition,
  WealthHolding,
  WealthProduct,
  WealthRolloverChoice,
  WealthProductQuery,
  WealthPurchaseInput,
  WealthPurchaseReceipt,
  WealthRedemptionInput,
  WealthRedemptionReceipt,
  WealthRiskProfile,
  RiskLevel,
  // ★ 第 3 项:两阶段提交
  AbortOutcome,
  CommitOutcome,
  OperationScope,
  PreparedOperation,
} from "../../core/src/types.ts";
import {
  OperationCancelledError,
  decideAtCommitBoundary,
} from "../../core/src/policy/twoPhase.ts";
import { scoreName } from "../../core/src/intent/fuzzyName.ts";
import {
  buildRiskProfile,
  emptyRiskProfile,
  computePurchase,
  computeRedemption,
  round2,
  settlementDays,
} from "../../core/src/capabilities/wealth.ts";
import {
  CARD_KIND_LABELS,
  CARD_STATUS_LABELS,
  CARD_APPLICATION_REVIEW_BUSINESS_DAYS,
  LIMIT_RULES,
  REPLACEMENT_ETA_DAYS,
  RESTRICTION_CAUSE_LABELS,
  restrictionChannelFor,
  scenarioForReplacementMode,
  requirementForScenario,
} from "../../core/src/capabilities/card.ts";
import { cadenceLabel } from "../../core/src/capabilities/subscription.ts";
import { transferFeeOf } from "../../core/src/capabilities/transferFee.ts";
import { getPolicyConfig } from "../../core/src/policy/engine.ts";

/**
 * 本行(演示银行)的银行代码。
 * 跨行判定要看它:收款人银行码 ≠ 它,才是跨行 —— 跨行才谈得上手续费/到账时效。
 * 这个字面量原来散在多处(种子数据、可达性判定),收成一个名字,
 * 免得将来加一家银行时漏改其中一处。
 */
const SELF_BANK_CODE = "CMB";

// ============================================================================
// 种子随机数(可复现的演示数据)
// ============================================================================

function createRng(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    // xorshift32
    s ^= s << 13;
    s >>>= 0;
    s ^= s >> 17;
    s ^= s << 5;
    s >>>= 0;
    return s / 0xffffffff;
  };
}

/** 生成确定性的 UUID 风格 ID */
function detId(prefix: string, n: number): string {
  const h = createHash("sha1").update(`${prefix}:${n}`).digest("hex");
  return `${prefix}_${h.slice(0, 12)}`;
}

function detIdFromString(prefix: string, key: string): string {
  const h = createHash("sha1").update(key).digest("hex");
  return `${prefix}_${h.slice(0, 12)}`;
}

/** YYYY-MM-DD(确定性格式,不依赖运行环境的 locale) */
function formatYmd(ts: number): string {
  const d = new Date(ts);
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  return `${d.getFullYear()}-${mm}-${dd}`;
}

/**
 * 下一个"每月 N 号"。
 *
 * ★ 为什么不能写成 `上次扣款 + 30 天`:
 *   代扣是按**日历**签的(每月 14 号),不是按 720 小时。
 *   用 30 天推进,过几个月就会漂到 13 号、12 号 ——
 *   客户按系统给的日期等扣款,等来的却是一笔提前的扣款。
 *   这个函数与账单分析里 detectRecurring 的日历推算是**同一口径**。
 */
function nextMonthlyOccurrence(now: number, day: number): number {
  const d = new Date(now);
  d.setHours(9, 0, 0, 0);
  d.setDate(1);
  // 月份先加一,再定为 N 号:这样"本月 N 号已过"与"本月 N 号未到"都能算对
  d.setMonth(d.getMonth() + 1);
  d.setDate(day);
  if (d.getTime() <= now) d.setMonth(d.getMonth() + 1);
  return d.getTime();
}

// ============================================================================
// 内部账本结构(含敏感字段,永不外泄)
// ============================================================================

interface InternalPayee {
  payeeId: string;
  ownerCustomerId: string;
  name: string;
  /** 完整账号 —— 仅内部可见 */
  accountNo: string;
  phone?: string;
  bankCode: string;
  bankName: string;
  isSelfOwned: boolean;
  isWhitelisted: boolean;
  aliases: string[];
  /** 成功转账历史(时间戳数组) —— 用于计算新颖度 */
  successHistory: number[];
  /** 名单标记(演示用) */
  listFlag?: { listType: "fraud" | "judicial" | "sanction" | "internal_blacklist" | "reported_account"; severity: "block" | "warn"; detail: string };
}

interface InternalAccount extends Account {
  /** 完整账号 —— 仅内部可见 */
  fullNo: string;
}

// ============================================================================
// 理财产品目录(演示数据)
// ============================================================================

/**
 * 演示用理财产品目录。
 *
 * ★ 数据设计上刻意做三件事:
 *   ① **覆盖 R1–R5 全等级** —— 否则演示不了"等级不匹配需签确认书";
 *   ② 收益与风险**正相关** —— 高收益配高风险、长锁定期,
 *      这是真实市场的约束,不能出现"又保本又高收益"这种诱导性组合;
 *   ③ **没有任何"预期收益/保证收益"字段** —— 收益率只有"近 7 日年化""近 1 年"
 *      "业绩比较基准"三种口径,措辞与真实银行一致。
 */
export interface WealthProductSeed {
  productCode: string;
  name: string;
  type: WealthProduct["type"];
  riskLevel: WealthProduct["riskLevel"];
  minAmount: number;
  incrementAmount: number;
  termDays: number | null;
  yield7d: number | null;
  yield1y: number | null;
  performanceBenchmark: number | null;
  nav: number;
  managementFeeRate: number;
  custodyFeeRate: number;
  purchaseFeeRate: number;
  settlement: WealthProduct["settlement"];
  redeemable: boolean;
  minHoldingDays: number;
  status: WealthProduct["status"];
  riskDisclosure: string;
  highlight: string;
  /** 净值日期(由目录构建时统一写入) */
  navDate?: number;
}

const STD_DISCLOSURE =
  "本产品为非保本浮动收益型产品。理财非存款,产品有风险,投资须谨慎。" +
  "历史业绩不代表未来表现,管理人不保证本金安全,不保证最低收益。";

export function buildProductCatalog(now: number): WealthProductSeed[] {
  const day = 24 * 3600 * 1000;
  const seeds: WealthProductSeed[] = [
    {
      productCode: "LC1001",
      name: "天天利货币A",
      type: "cash",
      riskLevel: "R1",
      minAmount: 100,
      incrementAmount: 1,
      termDays: null,
      yield7d: 1.85,
      yield1y: null,
      performanceBenchmark: null,
      nav: 1.0,
      managementFeeRate: 0.15,
      custodyFeeRate: 0.05,
      purchaseFeeRate: 0,
      settlement: "T+0",
      redeemable: true,
      minHoldingDays: 0,
      status: "on_sale",
      riskDisclosure: STD_DISCLOSURE,
      highlight: "随时可取、当日到账,适合放置短期闲置资金",
    },
    {
      productCode: "LC1002",
      name: "稳健增利90天",
      type: "fixed_income",
      riskLevel: "R2",
      minAmount: 1000,
      incrementAmount: 1000,
      termDays: 90,
      yield7d: null,
      yield1y: 3.12,
      performanceBenchmark: 3.0,
      nav: 1.0873,
      managementFeeRate: 0.3,
      custodyFeeRate: 0.05,
      purchaseFeeRate: 0,
      settlement: "T+1",
      redeemable: false,
      minHoldingDays: 90,
      status: "on_sale",
      riskDisclosure: STD_DISCLOSURE,
      highlight: "以债券等固收资产为主,波动较小,持有 90 天到期自动回款",
    },
    {
      productCode: "LC1003",
      name: "纯债添利B",
      type: "fixed_income",
      riskLevel: "R2",
      minAmount: 1000,
      incrementAmount: 100,
      termDays: null,
      yield7d: null,
      yield1y: 3.45,
      performanceBenchmark: 3.2,
      nav: 1.1245,
      managementFeeRate: 0.4,
      custodyFeeRate: 0.08,
      purchaseFeeRate: 0,
      settlement: "T+1",
      redeemable: true,
      minHoldingDays: 7,
      status: "on_sale",
      riskDisclosure: STD_DISCLOSURE,
      highlight: "纯债策略不参与股票投资,持有满 7 天后可随时赎回",
    },
    {
      productCode: "LC2001",
      name: "固收+双利180天",
      type: "mixed",
      riskLevel: "R3",
      minAmount: 5000,
      incrementAmount: 1000,
      termDays: 180,
      yield7d: null,
      yield1y: 4.86,
      performanceBenchmark: 4.2,
      nav: 1.2031,
      managementFeeRate: 0.6,
      custodyFeeRate: 0.1,
      purchaseFeeRate: 0.1,
      settlement: "T+2",
      redeemable: false,
      minHoldingDays: 180,
      status: "on_sale",
      riskDisclosure: STD_DISCLOSURE,
      highlight: "以固收打底、少量权益增强,净值会有波动,180 天封闭",
    },
    {
      productCode: "LC2002",
      name: "平衡配置混合C",
      type: "mixed",
      riskLevel: "R3",
      minAmount: 1000,
      incrementAmount: 100,
      termDays: null,
      yield7d: null,
      yield1y: 5.24,
      performanceBenchmark: 4.5,
      nav: 1.3318,
      managementFeeRate: 0.8,
      custodyFeeRate: 0.12,
      purchaseFeeRate: 0.3,
      settlement: "T+1",
      redeemable: true,
      minHoldingDays: 0,
      status: "on_sale",
      riskDisclosure: STD_DISCLOSURE,
      highlight: "股债均衡配置,可随时赎回,适合能接受净值波动的客户",
    },
    {
      productCode: "LC3001",
      name: "沪深300指数增强",
      type: "equity",
      riskLevel: "R4",
      minAmount: 1000,
      incrementAmount: 100,
      termDays: null,
      yield7d: null,
      yield1y: 8.63,
      performanceBenchmark: 7.5,
      nav: 1.4826,
      managementFeeRate: 1.0,
      custodyFeeRate: 0.15,
      purchaseFeeRate: 0.5,
      settlement: "T+2",
      redeemable: true,
      minHoldingDays: 0,
      status: "on_sale",
      riskDisclosure: STD_DISCLOSURE,
      highlight: "跟踪沪深300并有增强策略,短期波动明显,建议持有一年以上",
    },
    {
      productCode: "LC3002",
      name: "科技成长精选",
      type: "equity",
      riskLevel: "R5",
      minAmount: 10_000,
      incrementAmount: 1000,
      termDays: null,
      yield7d: null,
      yield1y: 14.28,
      performanceBenchmark: 10.0,
      nav: 1.7654,
      managementFeeRate: 1.2,
      custodyFeeRate: 0.2,
      purchaseFeeRate: 0.8,
      settlement: "T+2",
      redeemable: true,
      minHoldingDays: 0,
      status: "on_sale",
      riskDisclosure: STD_DISCLOSURE,
      highlight: "集中投资科技成长板块,净值波动大,历史最大回撤超 25%",
    },
    {
      productCode: "LC4001",
      name: "大额存单3年期",
      type: "deposit",
      riskLevel: "R1",
      minAmount: 200_000,
      incrementAmount: 10_000,
      termDays: 1095,
      yield7d: null,
      yield1y: null,
      performanceBenchmark: 2.9,
      nav: 1.0,
      managementFeeRate: 0,
      custodyFeeRate: 0,
      purchaseFeeRate: 0,
      settlement: "T+1",
      redeemable: false,
      minHoldingDays: 1095,
      status: "on_sale",
      riskDisclosure: "本产品为存款类产品,受存款保险条例保障(同一银行 50 万元以内本息全额偿付)。",
      highlight: "利率固定、到期一次性还本付息,门槛较高",
    },
    {
      productCode: "LC5001",
      name: "海外高收益债QDII",
      type: "fixed_income",
      riskLevel: "R5",
      minAmount: 50_000,
      incrementAmount: 10_000,
      termDays: null,
      yield7d: null,
      yield1y: 11.5,
      performanceBenchmark: 9.0,
      nav: 1.0552,
      managementFeeRate: 1.1,
      custodyFeeRate: 0.2,
      purchaseFeeRate: 0.6,
      settlement: "T+2",
      redeemable: true,
      minHoldingDays: 30,
      status: "suspended",
      riskDisclosure:
        "本产品投资境外高收益债券,除市场风险外还承担汇率风险与流动性风险,风险等级为 R5。理财非存款,产品有风险,投资须谨慎。",
      highlight: "境外高收益债,含汇率风险,当前暂停申购",
    },
  ];
  for (const s of seeds) s.navDate = now - day;
  return seeds;
}

interface InternalHolding {
  holdingId: string;
  ownerCustomerId: string;
  productCode: string;
  shares: number;
  costAmount: number;
  firstPurchaseAt: number;
  /** 银行侧到期日。开放式产品不填 */
  maturityAt?: number;
  maturityDisposition?: MaturityDisposition;
  /** 到期资金已记入活期。演示种子不置位,避免到期前就能申购 */
  maturityCredited?: boolean;
}

interface InternalRedemption {
  orderId: string;
  ownerCustomerId: string;
  productCode: string;
  shares: number;
  amount: number;
  fee: number;
  realizedProfit: number;
  settlement: WealthProduct["settlement"];
  submittedAt: number;
  estimatedArrivalAt: number;
  settled: boolean;
  reference: string;
}

interface InternalPurchaseOrder {
  orderId: string;
  ownerCustomerId: string;
  productCode: string;
  amount: number;
  fee: number;
  shares: number;
  confirmedNav: number;
  confirmedAt: number;
  frozenAmount: number;
  consentRef?: string;
  reference: string;
}

// ============================================================================
// 数据工厂
// ============================================================================

// ★ 日常消费分类(不包括住房/教育 —— 这两类是月度账单,不是日常小额消费,
//   否则"房租/学费"会以每天随机几笔的形式混进数据,把账单分析的数字做假)。
const CATEGORIES = [
  "餐饮美食",
  "交通出行",
  "日用百货",
  "服饰美容",
  "居家生活",
  "医疗健康",
  "文化娱乐",
  "通讯服务",
];

/** 各日常分类的单笔基准金额 → 消费量级接近真实工薪族 */
const DAILY_CATEGORY_BASE: Record<string, number> = {
  餐饮美食: 60,
  交通出行: 40,
  日用百货: 80,
  服饰美容: 200,
  居家生活: 120,
  医疗健康: 150,
  文化娱乐: 80,
  通讯服务: 60,
};

const MERCHANTS: Record<string, string[]> = {
  餐饮美食: ["星巴克咖啡", "肯德基", "海底捞火锅", "美团外卖", "瑞幸咖啡", "兰州拉面馆", "湘菜小馆"],
  交通出行: ["滴滴出行", "地铁乘车码", "中石化加油", "高德打车", "共享单车", "高铁票款"],
  日用百货: ["永辉超市", "盒马鲜生", "屈臣氏", "全家便利店", "沃尔玛"],
  服饰美容: ["优衣库", "淘宝服饰", "丝芙兰", "理发店"],
  居家生活: ["京东超市", "宜家家居", "小米之家", "物业服务费"],
  医疗健康: ["同仁堂药店", "市第一医院", "体检中心", "口腔诊所"],
  // ★ 订阅类商户不在日常随机池里:腾讯视频会员/网易云音乐/健身房月卡
  //   是每月固定扣款,由"定期支出"种子数据单独生成。
  //   若混进日常池,规律性会被随机金额污染,定期支出识别就失效了。
  文化娱乐: ["猫眼电影", "KTV欢唱", "桌游馆", "图书网购"],
  // ★ 云服务器是月度账单,不在日常随机池(否则会被误判为"每日固定支出")
  通讯服务: ["中国移动话费", "中国电信宽带"],
};

/**
 * 生成演示数据。种子固定 → 每次启动数据一致 → 演示可复现。
 */
export function buildDemoWorld(options?: { now?: number; months?: number; seed?: number }) {
  const now = options?.now ?? Date.now();
  const months = options?.months ?? 6;
  const rng = createRng(options?.seed ?? 20260101);

  const PRIMARY = "CUST-DEMO-001";
  const SPOUSE = "CUST-DEMO-002";

  const accounts = new Map<string, InternalAccount>();
  const payees = new Map<string, InternalPayee>();
  const transactions: Transaction[] = [];
  const aliases = new Map<string, string>(); // `${customerId}:${alias}` → payeeId
  const drafts = new Map<string, TransferDraft & { __consumed: boolean }>();
  const receipts = new Map<string, TransferReceipt>();
  const schedules = new Map<string, Schedule>();
  const collections = new Map<string, Collection>();
  const idempotency = new Map<string, TransferReceipt>();

  // ---- 理财(场景三)----
  const wealthProducts = new Map<string, WealthProductSeed>();
  for (const p of buildProductCatalog(now)) wealthProducts.set(p.productCode, p);
  /** 持仓:按 `${customerId}:${productCode}` 索引,同一产品只有一条持仓记录 */
  const wealthHoldings = new Map<string, InternalHolding>();
  /** 风险测评结果 —— ★ 演示数据里**故意留空**,让"首次购买先测评"这条规则能被真实触发 */
  const wealthRiskProfiles = new Map<string, WealthRiskProfile>();
  const wealthPurchases: InternalPurchaseOrder[] = [];
  const wealthRedemptions: InternalRedemption[] = [];
  /**
   * 风险测评作答留痕。
   *
   * ★ 为什么问卷原文要单独存:监管核查"这个客户为什么被评为 C4"时,
   *   需要的不是等级本身,而是**他当时到底答了什么**。
   *   只存结果是不可复核的 —— 而不可复核的评级在合规上等于没有评级。
   */
  /** 到期续接选择。按 `${customerId}:${holdingId}` 只留最新一条,不代表已申购 */
  const wealthRolloverChoices = new Map<string, WealthRolloverChoice>();
  const riskAssessmentLog: Array<{
    customerId: string;
    score: number;
    level: RiskLevel;
    answers: Array<{ questionId: string; optionId: string }>;
    assessedAt: number;
    validUntil: number;
  }> = [];

  // ---- 订阅代扣(新场景)----
  /**
   * 代扣协议(银行侧事实)。
   *
   * ★ 这里刻意**不给每一笔订阅都配协议**:演示数据里 iCloud 云空间
   *   就是一笔"有流水、没有本行协议"的商户侧自动续费(App Store 订阅的真实形态)。
   *   有了它,"识别出来 ≠ 可以在本行取消"这条纪律才不是一句空话 ——
   *   系统必须能在客户说「把 iCloud 关了」时如实说"这笔我关不了"。
   */
  const subscriptions = new Map<string, BankSubscription>();

  // ---- 账户 ----
  const accDefs: Array<Omit<InternalAccount, "accountId"> & { key: string }> = [
    {
      key: "salary",
      customerId: PRIMARY,
      fullNo: "6217000010001234567",
      maskedNo: "**** **** **** 4567",
      type: "current",
      currency: "CNY",
      balance: 128_450.62,
      availableBalance: 128_450.62,
      status: "active",
    },
    {
      key: "savings",
      customerId: PRIMARY,
      fullNo: "6217000010009876543",
      maskedNo: "**** **** **** 6543",
      type: "savings",
      currency: "CNY",
      balance: 356_800.0,
      availableBalance: 356_800.0,
      status: "active",
    },
    {
      key: "credit",
      customerId: PRIMARY,
      fullNo: "6225880010005558888",
      maskedNo: "**** **** **** 8888",
      type: "credit",
      currency: "CNY",
      balance: -8_642.35,
      availableBalance: 41_357.65,
      creditLimit: 50_000,
      status: "active",
    },
    {
      key: "ewallet",
      customerId: PRIMARY,
      fullNo: "6217000010002223334",
      maskedNo: "**** **** **** 3334",
      type: "ewallet",
      currency: "CNY",
      balance: 2_380.5,
      availableBalance: 2_380.5,
      status: "active",
    },
  ];
  for (const def of accDefs) {
    const { key, ...rest } = def;
    const accountId = detIdFromString("ACC", `${def.customerId}:${key}`);
    accounts.set(accountId, { ...rest, accountId });
  }

  const primaryAccounts = [...accounts.values()].filter((a) => a.customerId === PRIMARY);
  const salaryAcc = primaryAccounts.find((a) => a.type === "current")!;
  const savingsAcc = primaryAccounts.find((a) => a.type === "savings")!;
  const creditAcc = primaryAccounts.find((a) => a.type === "credit")!;

  // ---- 收款人 ----
  function addPayee(def: Omit<InternalPayee, "payeeId" | "successHistory"> & { successHistory?: number[] }): InternalPayee {
    const payeeId = detIdFromString("PAYEE", `${def.ownerCustomerId}:${def.name}:${def.accountNo}`);
    const payee: InternalPayee = { ...def, payeeId, successHistory: def.successHistory ?? [] };
    payees.set(payeeId, payee);
    return payee;
  }

  const daysAgo = (d: number) => now - d * 24 * 60 * 60 * 1000;

  // 常用收款人(高频,已建立信任)
  const mom = addPayee({
    ownerCustomerId: PRIMARY,
    name: "王秀兰",
    accountNo: "6222021001122334455",
    phone: "13801380001",
    bankCode: "ICBC",
    bankName: "中国工商银行",
    isSelfOwned: false,
    isWhitelisted: true,
    aliases: ["老妈", "妈", "妈妈"],
    successHistory: [daysAgo(120), daysAgo(90), daysAgo(62), daysAgo(33), daysAgo(12)],
  });
  aliases.set(`${PRIMARY}:老妈`, mom.payeeId);
  aliases.set(`${PRIMARY}:妈`, mom.payeeId);
  aliases.set(`${PRIMARY}:妈妈`, mom.payeeId);

  const landlord = addPayee({
    ownerCustomerId: PRIMARY,
    name: "陈建国",
    accountNo: "6212261000987654321",
    phone: "13901390002",
    bankCode: "CCB",
    bankName: "中国建设银行",
    isSelfOwned: false,
    isWhitelisted: true,
    aliases: ["房东", "房东陈叔"],
    successHistory: [daysAgo(150), daysAgo(120), daysAgo(90), daysAgo(60), daysAgo(30), daysAgo(2)],
  });
  aliases.set(`${PRIMARY}:房东`, landlord.payeeId);
  aliases.set(`${PRIMARY}:房东陈叔`, landlord.payeeId);

  const colleague = addPayee({
    ownerCustomerId: PRIMARY,
    name: "李明",
    accountNo: "6216611000778899001",
    phone: "13701370003",
    bankCode: "BOC",
    bankName: "中国银行",
    isSelfOwned: false,
    isWhitelisted: true,
    aliases: ["李明同事", "老李"],
    successHistory: [daysAgo(200), daysAgo(160), daysAgo(75)],
  });
  aliases.set(`${PRIMARY}:老李`, colleague.payeeId);

  // ★ 同名歧义场景:两个"张伟",用于演示消歧卡片
  const zhangweiA = addPayee({
    ownerCustomerId: PRIMARY,
    name: "张伟",
    accountNo: "6217001210001111222",
    phone: "13611112222",
    bankCode: "CMB",
    bankName: "招商银行",
    isSelfOwned: false,
    isWhitelisted: false,
    aliases: ["张伟设计"],
    successHistory: [daysAgo(45), daysAgo(18)],
  });
  const zhangweiB = addPayee({
    ownerCustomerId: PRIMARY,
    name: "张伟",
    accountNo: "6228480402564890018",
    phone: "13533334444",
    bankCode: "ABC",
    bankName: "中国农业银行",
    isSelfOwned: false,
    isWhitelisted: false,
    aliases: ["张伟同学"],
    successHistory: [],
  });

  // ★ 仅手机号可识别的新收款人(首次)
  const phoneOnly = addPayee({
    ownerCustomerId: PRIMARY,
    name: "刘倩",
    accountNo: "6214830201234567",
    phone: "13800138999",
    bankCode: "CMB",
    bankName: "招商银行",
    isSelfOwned: false,
    isWhitelisted: false,
    aliases: [],
    successHistory: [],
  });

  // ★ 专用"零历史"收款人:保证「首次转账」相关场景在任何执行顺序下都可复现。
  //   演示脚本会改动账本状态,若共用收款人,后续场景的首次判定会被前序场景破坏。
  const neverUsed = addPayee({
    ownerCustomerId: PRIMARY,
    name: "孙浩",
    accountNo: "6217001210005556667",
    phone: "13566667777",
    bankCode: "CMB",
    bankName: "招商银行",
    isSelfOwned: false,
    isWhitelisted: false,
    aliases: [],
    successHistory: [],
  });

  // ★ 反诈干预演示用收款人:不在任何名单上、无历史记录。
  //   专门用于展示"反诈干预机制本身"(冷静期 + 话术拆解),
  //   而不是被名单阻断规则提前拦下 —— 后者是另一条防线,不该混淆演示。
  const fraudDemoPayee = addPayee({
    ownerCustomerId: PRIMARY,
    name: "周慧",
    accountNo: "6217001210008889990",
    phone: "13788889999",
    bankCode: "CCB",
    bankName: "中国建设银行",
    isSelfOwned: false,
    isWhitelisted: false,
    aliases: [],
    successHistory: [],
  });

  // ★ 名单命中场景:演示硬阻断
  const risky = addPayee({
    ownerCustomerId: PRIMARY,
    name: "王强",
    accountNo: "6222020200987654321",
    phone: "13011119999",
    bankCode: "ABC",
    bankName: "中国农业银行",
    isSelfOwned: false,
    isWhitelisted: false,
    aliases: [],
    successHistory: [],
    listFlag: {
      listType: "fraud",
      severity: "block",
      detail: "涉诈账户(公安部电信诈骗涉案账户名单)",
    },
  });

  // 本人名下他行账户(演示"本人互转"低风险通道)
  const selfOtherBank = addPayee({
    ownerCustomerId: PRIMARY,
    name: "本人(交通银行储蓄卡)",
    accountNo: "6222600910007778888",
    bankCode: "BOCOM",
    bankName: "交通银行",
    isSelfOwned: true,
    isWhitelisted: true,
    aliases: ["我自己交行卡", "交行卡"],
    successHistory: [daysAgo(80), daysAgo(40), daysAgo(15)],
  });

  // 配偶账户(同户名不同客户,演示 AA 收款对手方)
  addPayee({
    ownerCustomerId: SPOUSE,
    name: "赵敏",
    accountNo: "6217000010001234999",
    phone: "13600136000",
    bankCode: "CMB",
    bankName: "招商银行",
    isSelfOwned: false,
    isWhitelisted: true,
    aliases: [],
    successHistory: [],
  });

  // ---- 交易流水(6 个月) ----
  let txCounter = 0;
  const txPush = (tx: Omit<Transaction, "transactionId">) => {
    transactions.push({ ...tx, transactionId: detId("TXN", ++txCounter) });
  };

  for (let day = months * 30; day >= 0; day--) {
    const ts = daysAgo(day);
    const date = new Date(ts);
    const dayOfMonth = date.getDate();
    if (day > 0 && ts > now) continue;

    // 每月 10 号工资入账
    if (dayOfMonth === 10) {
      txPush({
        accountId: salaryAcc.accountId,
        direction: "in",
        amount: 28_650.0,
        currency: "CNY",
        counterpartyName: "某某科技有限公司",
        counterpartyId: "CORP-001",
        category: "工资收入",
        memo: "代发工资",
        balanceAfter: 0,
        ts,
      });
    }

    // 每月 1 号房租
    if (dayOfMonth === 1) {
      txPush({
        accountId: salaryAcc.accountId,
        direction: "out",
        amount: 5_800.0,
        currency: "CNY",
        counterpartyName: landlord.name,
        counterpartyId: landlord.payeeId,
        category: "住房物业",
        memo: "房租",
        balanceAfter: 0,
        ts,
      });
    }

    // ★ 每月固定订阅(账单分析场景的"定期支出识别"演示数据)
    //   这几笔在每月固定日出现、金额固定 —— 正好构成"规律性扣款"信号,
    //   也天然形成"多个视频/音乐会员重叠"的省钱洞察。
    const SUBSCRIPTIONS: Array<{ day: number; merchant: string; amount: number; category: string }> = [
      { day: 5, merchant: "在线英语课程", amount: 199, category: "教育培训" },
      { day: 14, merchant: "爱奇艺会员", amount: 19, category: "文化娱乐" },
      { day: 15, merchant: "腾讯视频会员", amount: 25, category: "文化娱乐" },
      { day: 16, merchant: "网易云音乐", amount: 15, category: "文化娱乐" },
      { day: 17, merchant: "健身房月卡", amount: 99, category: "文化娱乐" },
      { day: 18, merchant: "iCloud 云空间", amount: 6, category: "通讯服务" },
      // ★ 这一笔刻意**没有订阅关键词**,也刻意不是文化娱乐类:
      //   它只能靠"固定周期 + 固定金额"被认出来(引擎的第二条识别路径)。
      //   保费代扣取消的后果(保障中断)也与关会员完全不同,是"取消的代价必须说清"的落点。
      { day: 20, merchant: "平安健康保险", amount: 58, category: "保险" },
    ];
    for (const sub of SUBSCRIPTIONS) {
      if (dayOfMonth === sub.day) {
        txPush({
          accountId: salaryAcc.accountId,
          direction: "out",
          amount: sub.amount,
          currency: "CNY",
          counterpartyName: sub.merchant,
          category: sub.category,
          memo: "自动续费",
          balanceAfter: 0,
          ts,
        });
      }
    }

    // 每天 1–3 笔消费(量级贴近真实工薪族,避免账单数字失真)
    const count = 1 + Math.floor(rng() * 3);
    for (let i = 0; i < count; i++) {
      const category = CATEGORIES[Math.floor(rng() * CATEGORIES.length)]!;
      const merchants = MERCHANTS[category]!;
      const merchant = merchants[Math.floor(rng() * merchants.length)]!;
      const base = DAILY_CATEGORY_BASE[category] ?? 80;
      const amount = Math.round((base + rng() * base * 2) * 100) / 100;
      const hour = 7 + Math.floor(rng() * 15);
      const txTs = new Date(ts);
      txTs.setHours(hour, Math.floor(rng() * 60), 0, 0);
      txPush({
        accountId: rng() > 0.35 ? salaryAcc.accountId : creditAcc.accountId,
        direction: "out",
        amount,
        currency: "CNY",
        counterpartyName: merchant,
        category,
        memo: rng() > 0.85 ? "日常消费" : undefined,
        balanceAfter: 0,
        ts: txTs.getTime(),
      });
    }
  }

  // ★ 异常交易识别演示数据(账单分析场景)
  //   三类信号各造一笔:深夜消费、新对手方大额、短时重复扣款。
  //   它们都是"看起来可疑、需要用户核实"的典型 ——
  //   正常客户每月都会碰到其中一两类,不是刻意夸张的欺诈。

  // 1) 深夜消费:凌晨 2:30 的便利店支付
  const lateNight = new Date(daysAgo(9));
  lateNight.setHours(2, 30, 0, 0);
  txPush({
    accountId: salaryAcc.accountId,
    direction: "out",
    amount: 328.0,
    currency: "CNY",
    counterpartyName: "24小时便利店",
    category: "日用百货",
    memo: undefined,
    balanceAfter: 0,
    ts: lateNight.getTime(),
  });

  // 2) 新对手方大额:一次性数码城消费
  txPush({
    accountId: salaryAcc.accountId,
    direction: "out",
    amount: 12_800.0,
    currency: "CNY",
    counterpartyName: "华强北数码城",
    category: "居家生活",
    memo: undefined,
    balanceAfter: 0,
    ts: daysAgo(21),
  });

  // 3) 短时重复扣款:2 天内同商户同金额 3 笔
  for (let k = 0; k < 3; k++) {
    txPush({
      accountId: salaryAcc.accountId,
      direction: "out",
      amount: 49.9,
      currency: "CNY",
      counterpartyName: "星空影城",
      category: "文化娱乐",
      memo: undefined,
      balanceAfter: 0,
      ts: daysAgo(30 - k),
    });
  }

  // 补几笔与收款人相关的转账,让"按备注/历史查找"有真实数据
  txPush({
    accountId: salaryAcc.accountId,
    direction: "out",
    amount: 2_000.0,
    currency: "CNY",
    counterpartyName: mom.name,
    counterpartyId: mom.payeeId,
    category: "转账",
    memo: "妈这个月的生活费",
    balanceAfter: 0,
    ts: daysAgo(12),
  });
  txPush({
    accountId: salaryAcc.accountId,
    direction: "out",
    amount: 1_500.0,
    currency: "CNY",
    counterpartyName: colleague.name,
    counterpartyId: colleague.payeeId,
    category: "转账",
    memo: "上次聚餐 AA",
    balanceAfter: 0,
    ts: daysAgo(75),
  });
  txPush({
    accountId: salaryAcc.accountId,
    direction: "out",
    amount: 3_800.0,
    currency: "CNY",
    counterpartyName: zhangweiA.name,
    counterpartyId: zhangweiA.payeeId,
    category: "转账",
    memo: "设计费尾款",
    balanceAfter: 0,
    ts: daysAgo(18),
  });

  // 按时间倒序,并回填 balanceAfter(从当前余额向前推演)
  transactions.sort((a, b) => a.ts - b.ts);

  // ---- ★ 理财持仓种子数据 ----
  //   设计取舍:客户**已有两只持仓**(一赚一亏),但**从未做过风险测评**。
  //   为什么这样造数据:
  //     · 有持仓 → "查询持仓与收益"一进去就有内容,不用先买一笔才有东西看;
  //     · 一赚一亏 → 收益展示必须同时面对正负两种情况,不能只演赚钱;
  //     · 未测评 → "首次购买必须先测评"这条行业规则能被**真实触发**,
  //                而不是靠人讲解"这里本该有一次测评"。
  //   另外,种子持仓里有一只是 R3 而客户尚未评级 ——
  //   这不是数据不一致,而是真实世界的常态:存量持仓是历史遗留的,
  //   监管要求约束的是**新的申购行为**。这一点在文档里专门说明了。
  const SEED_HOLDINGS: Array<{
    productCode: string;
    shares: number;
    costAmount: number;
    daysAgoHeld: number;
    /** 相对今天的到期日。只给封闭式、且银行已经写下到期日的持仓 */
    maturityInDays?: number;
    maturityDisposition?: MaturityDisposition;
  }> = [
    { productCode: "LC2002", shares: 15_010.51, costAmount: 20_000, daysAgoHeld: 165 },
    { productCode: "LC3002", shares: 3_396.65, costAmount: 6_000, daysAgoHeld: 210 },
    /**
     * 稳健增利 90 天,T-3 到期,到期后回活期。
     * 市值故意小于另外两笔种子持仓,避免打乱「卖第2个 = 科技成长精选」的持仓序号。
     * 到期日写在持仓上,不用申购日加期限去推。
     */
    {
      productCode: "LC1002",
      shares: 3_000,
      costAmount: 3_200,
      daysAgoHeld: 87,
      maturityInDays: 3,
      maturityDisposition: "to_demand",
    },
  ];

  for (const seed of SEED_HOLDINGS) {
    const product = wealthProducts.get(seed.productCode);
    if (!product) continue;
    const purchasedAt = daysAgo(seed.daysAgoHeld);
    const holdingId = detIdFromString("HLD", `${PRIMARY}:${seed.productCode}`);
    wealthHoldings.set(`${PRIMARY}:${seed.productCode}`, {
      holdingId,
      ownerCustomerId: PRIMARY,
      productCode: seed.productCode,
      shares: seed.shares,
      costAmount: seed.costAmount,
      firstPurchaseAt: purchasedAt,
      ...(seed.maturityInDays != null ? { maturityAt: now + seed.maturityInDays * 24 * 3600 * 1000 } : {}),
      ...(seed.maturityDisposition ? { maturityDisposition: seed.maturityDisposition } : {}),
    });
    wealthPurchases.push({
      orderId: detIdFromString("WPU", `${PRIMARY}:${seed.productCode}:${purchasedAt}`),
      ownerCustomerId: PRIMARY,
      productCode: seed.productCode,
      amount: seed.costAmount,
      fee: 0,
      shares: seed.shares,
      confirmedNav: round2(seed.costAmount / seed.shares),
      confirmedAt: purchasedAt,
      frozenAmount: 0,
      reference: `REF${detIdFromString("WPU", `${PRIMARY}:${seed.productCode}`).slice(-10).toUpperCase()}`,
    });
  }

  // ---- 订阅代扣(新场景)----
  //
  // ★ 演示数据刻意造出**四种**情形,让每条规则都能被真实触发:
  //
  //   | 商户             | 协议                        | 用来触发什么 |
  //   |------------------|-----------------------------|--------------|
  //   | 爱奇艺会员       | 本行代扣协议 · 每月 19 元    | 正常的一键取消(客户原话那个例子) |
  //   | 腾讯视频会员     | 本行代扣协议 · 每月 25 元    | 多笔候选时的指认与消歧 |
  //   | 网易云音乐       | 本行代扣协议 · 每月 15 元    | 关键词路径(音乐) |
  //   | 在线英语课程     | 本行代扣协议 · 每月 199 元   | 取消后果较重(课程权益终止) |
  //   | 健身房月卡       | 本行代扣协议 · 每月 99 元    | 关键词/周期双路径 |
  //   | 平安健康保险     | 本行代扣协议 · 每月 58 元    | ★ 无关键词,只能靠固定周期金额认出;取消后果是保障中断 |
  //   | iCloud 云空间    | **没有本行协议**             | ★ 商户侧自动续费:识别得出来,但本行关不了,必须如实说 |
  //
  //   ★ 房租(每月 1 号 5800 给陈建国)与工资(每月 10 号入账)是**反例**:
  //     它们也规律、也固定金额,但一个是付给个人的合同款、一个是收入 ——
  //     识别引擎必须把它们排除掉,且说得清为什么。
  const mandateDefs: Array<{
    merchant: string;
    amount: number;
    cadence: SubscriptionCadence;
    day: number;
    category: string;
    signedDaysAgo: number;
    refundPolicy: string;
    cancelConsequence: string;
    /** 已取消的那一份(演示"再取消一次要明确告知已取消") */
    cancelled?: boolean;
    cancelledDaysAgo?: number;
  }> = [
    {
      merchant: "腾讯视频会员",
      amount: 25,
      cadence: "monthly",
      day: 15,
      category: "文化娱乐",
      signedDaysAgo: 410,
      refundPolicy: "本期已扣的 25 元不予退还(会员权益已生效使用);取消后下个扣费日不再扣款。",
      cancelConsequence: "会员到期后无法继续观看会员内容,已下载的缓存内容按平台规则处理。",
    },
    {
      merchant: "网易云音乐",
      amount: 15,
      cadence: "monthly",
      day: 16,
      category: "文化娱乐",
      signedDaysAgo: 265,
      refundPolicy: "本期已扣的 15 元不予退还(会员权益已生效使用);取消后下个扣费日不再扣款。",
      cancelConsequence: "会员到期后恢复为非会员:无损音质、下载、免广告等权益停止。",
    },
    {
      merchant: "爱奇艺会员",
      amount: 19,
      cadence: "monthly",
      day: 14,
      category: "文化娱乐",
      signedDaysAgo: 180,
      refundPolicy: "本期已扣的 19 元不予退还(会员权益已生效使用);取消后下个扣费日不再扣款。",
      cancelConsequence: "黄金会员到期后无法继续观看会员内容,同时会失去已绑定的多设备登录权益。",
    },
    {
      merchant: "在线英语课程",
      amount: 199,
      cadence: "monthly",
      day: 5,
      category: "教育培训",
      signedDaysAgo: 320,
      refundPolicy: "本期已扣的 199 元对应本月已开课的 8 节课,不予退还;取消后不再扣下一期。",
      cancelConsequence: "剩余课时到期后无法继续使用,已完成的学习记录仍可查看;重新报课可能按当时价格执行。",
    },
    {
      merchant: "健身房月卡",
      amount: 99,
      cadence: "monthly",
      day: 17,
      category: "文化娱乐",
      signedDaysAgo: 540,
      refundPolicy: "本期已扣的 99 元不予退还(本月会籍已生效);取消后下个扣费日不再扣款。",
      cancelConsequence: "会籍到期后门禁权限关闭,私教课等附加服务同步停止。",
    },
    {
      merchant: "平安健康保险",
      amount: 58,
      cadence: "monthly",
      day: 20,
      category: "保险",
      signedDaysAgo: 700,
      refundPolicy: "本期已扣的 58 元对应本月的保障期间,不予退还;取消后不再扣下一期。",
      cancelConsequence:
        "★ 取消后保障立即在当期到期时终止:这段时间内出险将无法理赔;" +
        "想重新投保需要重新健康告知,还可能重新计算等待期 —— 建议先确认新的保障已生效再取消。",
    },
  ];

  for (const def of mandateDefs) {
    const subscriptionId = detIdFromString("SUB", `${PRIMARY}:${def.merchant}`);
    const signedAt = daysAgo(def.signedDaysAgo);
    const cancelledAt = def.cancelled ? daysAgo(def.cancelledDaysAgo ?? 20) : null;
    subscriptions.set(subscriptionId, {
      subscriptionId,
      customerId: PRIMARY,
      merchantName: def.merchant,
      amount: def.amount,
      currency: "CNY",
      cadence: def.cadence,
      cadenceLabel: cadenceLabel(def.cadence),
      /**
       * ★ 下次扣款日按**日历**推进到未来,而不是"上次扣款 + 一个周期"。
       *   客户问"什么时候扣"要的是下一个真实日期:
       *   如果本月 14 号已经过了,答案必须是下月 14 号而不是本月的某个过去时间。
       */
      nextDebitAt: cancelledAt != null ? null : nextMonthlyOccurrence(now, def.day),
      status: cancelledAt != null ? "cancelled" : "active",
      statusLabel: cancelledAt != null ? "已取消" : "代扣中",
      channel: "bank_mandate",
      channelLabel: "本行代扣协议(可在本行解约)",
      signedAt,
      cancelledAt,
      cancelEffective: "next_cycle",
      refundPolicy: def.refundPolicy,
      cancelConsequence: def.cancelConsequence,
      merchantCancelPath: null,
      category: def.category,
      agreementNo: `DH${subscriptionId.slice(-8).toUpperCase()}`,
    });
  }

  // ==========================================================================
  // 跨场景事件联动(新场景)
  //
  // ★ 这里只有三件事:**关键事件**、**外部商户目录**、**两个"已确认步骤"的落库**。
  //   刻意没有"自动替客户规划"的接口 —— 规划是纯函数在能力层做的,
  //   银行核心只负责"客户确认之后那一步"真的发生。
  //
  // ★ 商户目录为什么必须存在(而不是在能力里硬编几个店名):
  //   外部订购的金额、起订线、预约提前量与退订政策都是**商户的事实**,
  //   它们必须来自一个可核实的目录,否则"退订政策"就变成了模型随口编的一句话。
  // ==========================================================================

  const lifeEvents = new Map<string, LifeEvent>();
  const dayMs = 24 * 60 * 60 * 1000;
  const startOfDayTs = (ts: number): number => {
    const d = new Date(ts);
    d.setHours(0, 0, 0, 0);
    return d.getTime();
  };
  const eventFundTasks = new Map<string, { taskId: string; customerId: string; planId: string; stepId: string; mode: string; amount: number; fromAccountId: string; createdAt: number; active: boolean; scheduleId?: string | null }>();
  const externalOrders: Array<EventExternalStepReceipt & { customerId: string }> = [];

  const eventDefs: Array<{ key: string; kind: LifeEvent["kind"]; title: string; daysAhead: number; leadDays: number; note?: string; budgetHint?: number }> = [
    {
      key: "anniversary",
      kind: "anniversary",
      title: "结婚纪念日",
      daysAhead: 38,
      leadDays: 14,
      note: "客户去年提过想安排一次两人晚餐。",
      budgetHint: 1500,
    },
    {
      key: "birthday",
      kind: "birthday",
      title: "家人生日",
      daysAhead: 11,
      leadDays: 14,
      note: "客户自述:给家里人准备蛋糕。",
    },
  ];

  for (const def of eventDefs) {
    const eventId = detIdFromString("EVT", `${PRIMARY}:${def.key}`);
    lifeEvents.set(eventId, {
      eventId,
      customerId: PRIMARY,
      kind: def.kind,
      kindLabel: def.kind === "birthday" ? "生日" : def.kind === "anniversary" ? "纪念日" : "关键事件",
      title: def.title,
      occursAt: startOfDayTs(now + def.daysAhead * dayMs),
      leadDays: def.leadDays,
      ...(def.note ? { note: def.note } : {}),
      source: "user_stated",
      sourceLabel: "客户此前自述",
      ...(def.budgetHint != null ? { budgetHint: def.budgetHint } : {}),
    });
  }

  /**
   * 外部服务商户目录。
   * ★ 四家的"提前量"刻意不同(1 / 2 / 3 / 5 天):
   *   这样"临近日期时某些商户已经约不上"这件事能被真实演示 ——
   *   方案里选中的商户会随剩余天数变化,而不是永远同一家。
   */
  const externalMerchants: ExternalMerchant[] = [
    {
      merchantId: "EXT-FLOWER-001",
      name: "花间集鲜花",
      category: "flower",
      categoryLabel: "鲜花",
      minAmount: 199,
      hotItem: "99 支红玫瑰花束",
      bookAheadDays: 1,
      sameDayDelivery: true,
      cancelPolicy: "送达前 24 小时可免费取消;当日取消收取 50% 花材费(花材已备)。",
      rating: 4.8,
    },
    {
      merchantId: "EXT-CAKE-001",
      name: "甜时烘焙",
      category: "cake",
      categoryLabel: "蛋糕",
      minAmount: 168,
      hotItem: "6 寸鲜草莓奶油蛋糕",
      bookAheadDays: 2,
      sameDayDelivery: false,
      cancelPolicy: "取货前 48 小时可全额退;48 小时内取消收取 30% 备料费。",
      rating: 4.7,
    },
    {
      merchantId: "EXT-DINING-001",
      name: "云顶西餐厅",
      category: "restaurant",
      categoryLabel: "餐厅",
      minAmount: 688,
      hotItem: "双人纪念日套餐",
      bookAheadDays: 3,
      sameDayDelivery: false,
      cancelPolicy: "预订需付套餐全款;用餐前 72 小时可免费改期一次,之后取消收取 30%。",
      rating: 4.9,
    },
    {
      merchantId: "EXT-HOTEL-001",
      name: "山海间度假酒店",
      category: "hotel",
      categoryLabel: "酒店",
      minAmount: 780,
      hotItem: "海景大床房 1 晚",
      bookAheadDays: 5,
      sameDayDelivery: false,
      cancelPolicy: "入住前 3 天可免费取消;之后取消收取首晚房费。",
      rating: 4.6,
    },
  ];

  // ---- 卡片管理(场景四)----
  //
  // ★ 演示数据是**刻意造**的,用来让每一条行业规则都能被真实触发:
  //
  //   | 卡片                 | 关键设定                    | 用来触发什么 |
  //   |----------------------|-----------------------------|--------------|
  //   | 白金卡 尾号 8888     | 距上次调额 1 个月           | 提额冷却期(约 3 个月)拦截 |
  //   | 京东联名卡 尾号 2026 | 用卡仅 2 个月               | 用卡满 6 个月这条门槛 |
  //   | 工资卡 尾号 1234     | 借记卡,无授信额度           | "借记卡没有提额这回事" |
  //   | 京东联名卡 尾号 6666 | 交易限制:安全风险           | 可提交解除申请(转审核) |
  //   | 储蓄卡 尾号 9876     | 交易限制:信息不完整         | 引导自助补全,Agent 不代办 |
  //   | 白金卡 尾号 1145     | 未激活                      | 新卡激活 + 设交易密码 |
  //   | 数字信用卡 尾号 3344 | 用卡 8 个月、半年未调额     | 提额申请可提交(申请≠已提额) |
  //
  //   ★ 三张信用卡的"可提额/不可提额"状态互不相同,是为了让
  //     "先查资格、再谈申请"这个顺序能被真实演示,而不是靠讲解。
  const cards = new Map<string, BankCard>();
  const limitAdjustments: CardLimitAdjustment[] = [];
  const cardLossRecords: Array<CardLossReceipt & { customerId: string; scenario: string | null }> = [];
  const replacementOrders: CardReplacementOrder[] = [];

  const maskOf = (full: string) => `**** **** **** ${full.slice(-4)}`;

  const cardDefs: Array<{
    key: string;
    productName: string;
    kind: BankCard["kind"];
    brand: BankCard["brand"];
    fullNo: string;
    creditLimit: number | null;
    usedAmount: number | null;
    statementDay: number | null;
    dueDay: number | null;
    openedDaysAgo: number;
    lastAdjustDaysAgo: number | null;
    lastAdjustDelta: number | null;
    restriction?: CardRestriction;
    status?: BankCard["status"];
    activated?: boolean;
    /**
     * 补发关系意图。
     *
     * ★ 这里刻意不直接写 `replacementOf` 的字面值:那个字段的语义是
     *   "等于自身 cardId = 保留原号;其他值 = 换号",而 cardId 要等循环里才算得出来。
     *   在种子数据里凭手写填一个 "keep_number" 就落进了"其他值"那一支 ——
     *   于是保留原号的补发卡被当成了换号补卡,激活时错误地要求客户重设交易密码。
     *   用这个显式标记 + 循环里翻译,语义只有一处定义,不会写歪。
     */
    replacementIntent?: "keep_number" | "new_number";
    linkedAccountId?: string | null;
  }> = [
    {
      key: "credit_primary",
      productName: "长城环球通白金卡",
      kind: "credit",
      brand: "unionpay",
      fullNo: "6225880010005558888",
      creditLimit: 50_000,
      usedAmount: 8_642.35,
      statementDay: 5,
      dueDay: 25,
      openedDaysAgo: 900,
      lastAdjustDaysAgo: 40, // ★ 冷却期内:提额会被拦下并说明还差多久
      lastAdjustDelta: 10_000,
      linkedAccountId: null,
    },
    {
      key: "credit_jd",
      productName: "京东联名信用卡",
      kind: "credit",
      brand: "visa",
      fullNo: "4392250011112026",
      creditLimit: 30_000,
      usedAmount: 3_120,
      statementDay: 12,
      dueDay: 2,
      openedDaysAgo: 62, // ★ 用卡不足 6 个月
      lastAdjustDaysAgo: null,
      lastAdjustDelta: null,
      linkedAccountId: null,
    },
    {
      key: "debit_salary",
      productName: "龙卡通工资卡",
      kind: "debit",
      brand: "unionpay",
      fullNo: "6217000010001234567",
      creditLimit: null,
      usedAmount: null,
      statementDay: null,
      dueDay: null,
      openedDaysAgo: 1_200,
      lastAdjustDaysAgo: null,
      lastAdjustDelta: null,
      linkedAccountId: null,
    },
    {
      key: "credit_security_risk",
      productName: "京东联名信用卡",
      kind: "credit",
      brand: "unionpay",
      fullNo: "6227600011116666",
      creditLimit: 20_000,
      usedAmount: 15_800,
      statementDay: 18,
      dueDay: 8,
      openedDaysAgo: 500,
      lastAdjustDaysAgo: null,
      lastAdjustDelta: null,
      // ★ 限制原因:安全风险 —— 可提交解除申请,但由银行安全团队审核
      restriction: {
        cause: "security_risk",
        causeLabel: RESTRICTION_CAUSE_LABELS.security_risk,
        detail: "系统检测到该卡在异地陌生设备上有登录记录,并伴随一笔非惯常商户的大额尝试交易,已按风控规则临时限制交易。",
        channel: restrictionChannelFor("security_risk"),
        requiredDocuments: ["本人身份证件", "近期常用设备确认"],
        estimatedResolution: "提交后 1-2 个工作日,风控团队会电话或 App 内联系您核实",
        since: daysAgo(3),
        mustInvestigateFirst: true,
      },
      linkedAccountId: null,
    },
    {
      key: "debit_savings",
      productName: "龙卡通储蓄卡",
      kind: "debit",
      brand: "unionpay",
      fullNo: "6217000010009876543",
      creditLimit: null,
      usedAmount: null,
      statementDay: null,
      dueDay: null,
      openedDaysAgo: 800,
      lastAdjustDaysAgo: null,
      lastAdjustDelta: null,
      // ★ 限制原因:信息不完整 —— Agent 不能代办,只能引导自助补全
      restriction: {
        cause: "incomplete_information",
        causeLabel: RESTRICTION_CAUSE_LABELS.incomplete_information,
        detail: "您留存的身份证件已于上月末到期,按反洗钱与账户实名制要求,证件过期后账户的非柜面交易会被限制。",
        channel: restrictionChannelFor("incomplete_information"),
        requiredDocuments: ["有效期内的身份证件", "本人人脸识别"],
        estimatedResolution: "在 App 补全后一般 1 个工作日内自动解除",
        since: daysAgo(12),
        mustInvestigateFirst: true,
      },
      linkedAccountId: null,
    },
    {
      key: "credit_pending_activation",
      productName: "长城环球通白金卡(补发)",
      kind: "credit",
      brand: "unionpay",
      fullNo: "6225880010001145",
      creditLimit: 50_000,
      usedAmount: 0,
      statementDay: 5,
      dueDay: 25,
      openedDaysAgo: 3,
      lastAdjustDaysAgo: null,
      lastAdjustDelta: null,
      // ★ 挂失补卡保留原号:需要激活,但交易密码沿用原密码
      status: "pending_activation",
      activated: false,
      replacementIntent: "keep_number",
      linkedAccountId: null,
    },
    {
      key: "credit_limit_ok",
      productName: "数字信用卡·悦享版",
      kind: "credit",
      brand: "mastercard",
      fullNo: "5319930011113344",
      creditLimit: 15_000,
      usedAmount: 2_400,
      statementDay: 22,
      dueDay: 12,
      openedDaysAgo: 300, // ★ 用卡 10 个月,且从未调额 → 符合提额申请条件
      lastAdjustDaysAgo: null,
      lastAdjustDelta: null,
      linkedAccountId: null,
    },
    {
      key: "debit_judicial",
      productName: "龙卡通储蓄卡(二类户)",
      kind: "debit",
      brand: "unionpay",
      fullNo: "6217000010002222",
      creditLimit: null,
      usedAmount: null,
      statementDay: null,
      dueDay: null,
      openedDaysAgo: 600,
      lastAdjustDaysAgo: null,
      lastAdjustDelta: null,
      // ★★ 司法冻结:本场景**最严重的一类**限制,刻意放进演示数据。
      //
      //   为什么必须有一张这样的卡在演示数据里:
      //     前四种成因(异常交易 / 信息不完整 / 安全风险 / 自设限额)都还有"出路"——
      //     可申请、可自助、可自查。只有司法冻结是**真的没有出路**:
      //     银行无权解除,Agent 连申请都不该提交。
      //     如果演示数据里没有这一张,那么"不能一刀切"这句话就只能靠讲解,
      //     而讲解是最没有说服力的论证方式 —— 评委看到的将是一段说辞,
      //     而不是一次被系统拦下来的真实请求。
      status: "frozen",
      restriction: {
        cause: "judicial_freeze",
        causeLabel: RESTRICTION_CAUSE_LABELS.judicial_freeze,
        detail:
          "依人民法院(2026)京0105执1234号协助执行通知书冻结,冻结期间该账户只收不付。" +
          "冻结文书号与经办机关可在 App「卡片详情 → 限制说明」查看。",
        channel: restrictionChannelFor("judicial_freeze"),
        requiredDocuments: ["人民法院出具的《解除冻结通知书》"],
        estimatedResolution: "银行收到解除冻结通知书后 1-2 个工作日办结",
        since: daysAgo(21),
        mustInvestigateFirst: true,
      },
      linkedAccountId: null,
    },
  ];

  for (const def of cardDefs) {
    const cardId = detIdFromString("CARD", `${PRIMARY}:${def.key}`);
    cards.set(cardId, {
      cardId,
      customerId: PRIMARY,
      productName: def.productName,
      kind: def.kind,
      kindLabel: CARD_KIND_LABELS[def.kind],
      brand: def.brand,
      brandLabel: { unionpay: "银联", visa: "Visa", mastercard: "万事达" }[def.brand],
      maskedNo: maskOf(def.fullNo),
      last4: def.fullNo.slice(-4),
      status: def.status ?? "active",
      statusLabel: CARD_STATUS_LABELS[def.status ?? "active"],
      creditLimit: def.creditLimit,
      usedAmount: def.usedAmount,
      availableLimit: def.creditLimit != null ? round2(def.creditLimit - (def.usedAmount ?? 0)) : null,
      cashLimit: def.creditLimit != null ? Math.round(def.creditLimit * 0.5) : null,
      currency: "CNY",
      statementDay: def.statementDay,
      dueDay: def.dueDay,
      expiresAt: now + 3 * 365 * 24 * 3600 * 1000,
      openedAt: daysAgo(def.openedDaysAgo),
      lastLimitAdjustmentAt: def.lastAdjustDaysAgo != null ? daysAgo(def.lastAdjustDaysAgo) : null,
      lastLimitAdjustmentDelta: def.lastAdjustDelta,
      restriction: def.restriction ?? null,
      // ★ 保留原号的补发卡 → replacementOf 等于自身 cardId;
      //   换号补发 → 任何其他值(这里用 "new_number")。这与 orderCardReplacement 的写法一致。
      replacementOf:
        def.replacementIntent == null
          ? null
          : def.replacementIntent === "keep_number"
            ? cardId
            : "new_number",
      lostAt: null,
      activated: def.activated ?? true,
      activatedAt: def.activated === false ? null : daysAgo(def.openedDaysAgo),
      // ★ 挂失补卡(保留原号)沿用原密码 —— 所以补发卡也是"已设置交易密码";
      //   只有新开户/换号补卡才需要新设,演示数据里由 card_limit_ok 代表该情形。
      transactionPasswordSet: def.key !== "credit_limit_ok",
      linkedAccountId: def.linkedAccountId ?? null,
    });
  }

  return {
    now,
    primaryCustomerId: PRIMARY,
    spouseCustomerId: SPOUSE,
    accounts,
    payees,
    transactions,
    aliases,
    drafts,
    receipts,
    schedules,
    collections,
    idempotency,
    // 理财(场景三)
    wealthProducts,
    wealthHoldings,
    wealthRolloverChoices,
    wealthRiskProfiles,
    wealthPurchases,
    wealthRedemptions,
    riskAssessmentLog,
    // 卡片管理(场景四)
    cards,
    limitAdjustments,
    cardLossRecords,
    replacementOrders,
    // 订阅代扣(新场景)
    subscriptions,
    // 跨场景事件联动(新场景)
    lifeEvents,
    externalMerchants,
    eventFundTasks,
    externalOrders,
    /** 客户侧记账批注:附加在交易上,可写不可改 —— 与银行交易记录严格分离 */
    annotations: [] as DemoAnnotation[],
    /**
     * 客户提交的材料(账单分析之上的"多份材料比对"扩展)。
     *
     * ★ 这组数据是刻意"有毛病"的 —— 三份材料里埋了四处不一致:
     *   · 合同金额 128,000 vs 发票金额 138,000(差 10,000)
     *   · 付款条件:合同「首付30%,验收后付70%」vs 报价单「首付50%」
     *   · 出据方:合同「京华装饰」vs 发票「京华建材」(主体不一致)
     *   · 完工日期:合同 2026-11-30 vs 报价单 2026-12-15
     *   另有一处"看似不同、实则一致"的干扰项(项目名称写法不同但指向同一事),
     *   用来验证比对引擎**不会把表述差异当矛盾**。
     */
    documents: buildDemoDocuments(now),
    refs: { mom, landlord, colleague, zhangweiA, zhangweiB, phoneOnly, neverUsed, fraudDemoPayee, risky, selfOtherBank, salaryAcc, savingsAcc, creditAcc },
  };
}

/**
 * 演示材料:同一笔装修业务的合同 / 报价单 / 发票。
 *
 * 字段 key 跨材料对齐(amount / paymentTerms / counterparty / completionDate / subject),
 * 比对引擎才能把它们摆到同一行上。
 */
function buildDemoDocuments(now: number): CustomerDocument[] {
  const day = 24 * 3600 * 1000;
  const base = {
    subject: "朝阳区某小区 3 号楼 1802 室整体装修",
  };
  return [
    {
      documentId: "DOC-CONTRACT-001",
      kind: "contract",
      kindLabel: "合同",
      title: "房屋装修施工合同",
      counterparty: "京华装饰工程有限公司",
      issuedAt: now - 40 * day,
      fields: [
        { key: "subject", label: "项目", value: base.subject },
        { key: "counterparty", label: "对方主体", value: "京华装饰工程有限公司" },
        { key: "amount", label: "合同总价", value: 128000, unit: "元", tolerance: 0 },
        { key: "paymentTerms", label: "付款条件", value: "首付30%,竣工验收后付70%" },
        { key: "completionDate", label: "完工日期", value: "2026-11-30" },
      ],
    },
    {
      documentId: "DOC-QUOTE-001",
      kind: "quote",
      kindLabel: "报价单",
      title: "装修工程报价单",
      counterparty: "京华装饰工程有限公司",
      issuedAt: now - 45 * day,
      fields: [
        { key: "subject", label: "项目", value: "朝阳区某小区 3 号楼 1802 室装修工程" },
        { key: "counterparty", label: "对方主体", value: "京华装饰工程有限公司" },
        { key: "amount", label: "报价总额", value: 128000, unit: "元", tolerance: 0 },
        { key: "paymentTerms", label: "付款条件", value: "首付50%,余款验收后结清" },
        { key: "completionDate", label: "完工日期", value: "2026-12-15" },
      ],
    },
    {
      documentId: "DOC-INVOICE-001",
      kind: "invoice",
      kindLabel: "发票",
      title: "增值税普通发票",
      counterparty: "京华建材贸易有限公司",
      issuedAt: now - 3 * day,
      fields: [
        { key: "subject", label: "项目", value: base.subject },
        { key: "counterparty", label: "对方主体", value: "京华建材贸易有限公司" },
        { key: "amount", label: "发票金额", value: 138000, unit: "元", tolerance: 0 },
        { key: "paymentTerms", label: "付款条件", value: "首付30%,竣工验收后付70%" },
      ],
    },
  ];
}

/**
 * 客户侧记账批注。
 *
 * ★ 设计立场:批注与银行交易记录**严格分离**。
 *   银行流水是核心系统的既有事实,客户侧只能附加说明,不能改写它。
 *   这样既满足"帮我记一下"的诉求,又不会污染对账依据 ——
 *   如果让客户备注改掉交易记录,对账和审计就都不成立了。
 */
export interface DemoAnnotation {
  annotationId: string;
  ownerCustomerId: string;
  title: string;
  amount?: number;
  direction?: "in" | "out";
  counterpartyHint?: string;
  note?: string;
  tags: string[];
  /** 关联到的交易 ID(可空:纯手工记账) */
  linkedTransactionId?: string;
  createdAt: number;
}

export type DemoWorld = ReturnType<typeof buildDemoWorld>;

// ============================================================================
// MockBankPort —— 实现 BankPort 契约
// ============================================================================

/**
 * ★ 已准备(未提交)的操作登记项(第 3 项)。
 *
 * 它记录的不是"钱动了多少",而是"提交点已经确定、但还没越过去"。
 * 之所以要留 `input`:提交时要**重新走一遍校验**再做决定 ——
 * prepare 与 commit 之间世界可能已经变了。
 */
interface PreparedEntry {
  preparedId: string;
  op: string;
  customerId: string;
  input: Record<string, unknown>;
  idempotencyKey?: string;
  amount?: number;
  preview?: Record<string, unknown>;
  preparedAt: number;
  committed: boolean;
  result?: unknown;
}

/**
 * ★ 内部控制流:prepare 到达提交点后"踩刹车"。
 *
 * 为什么用异常而不是返回值:操作方法的返回类型是业务回执(TransferReceipt 等),
 * 让它们为了配合 prepare 而返回一个联合类型,会把两阶段语义泄漏到 30 多个调用点。
 * 用一次内部控制流信号把控制权交回 `prepareOperation`,业务方法一行都不用改签名。
 * 它**只在 prepareOnly 下抛出**,且只被 prepareOperation 捕获 ——
 * 任何其它地方看到它都说明有 bug(commitOperation 里会显式报错)。
 */
class PreparedControlSignal {
  readonly preparedId: string;
  constructor(preparedId: string) {
    this.preparedId = preparedId;
  }
}

export class MockBankPort implements BankPort {
  private readonly world: DemoWorld;

  // ---- ★ 两阶段提交(第 3 项)的状态 ----
  /**
   * 已准备(未提交)的操作。它是"提交点已经确定、但钱还没动"的登记表。
   *
   * 为什么放在银行核心而不是编排器:只有银行核心知道**哪一行代码是动账的那一行**。
   * 编排器若要猜,就只能给执行器塞一个 AbortSignal —— 那正是"钱扣了、状态未知"的来源。
   */
  private readonly preparedOps = new Map<string, PreparedEntry>();
  private preparedCounter = 0;
  /** 当前执行作用域(编排器在调用能力之前设置,提交边界读它) */
  private opScope: OperationScope | null = null;
  /** >0 表示"正在提交":提交点内不再拦截,否则重入会把自己的提交掐掉 */
  private commitDepth = 0;
  /** true 表示这一趟只为 prepare:到达提交点即停下,绝不越过 */
  private prepareOnly = false;

  constructor(world: DemoWorld) {
    this.world = world;
  }

  // ---- 两阶段提交(第 3 项) ----

  beginOperationScope(scope: OperationScope): void {
    this.opScope = scope;
  }

  endOperationScope(): void {
    this.opScope = null;
  }

  async prepareOperation(req: {
    op: string;
    customerId: string;
    input: Record<string, unknown>;
    idempotencyKey?: string;
    now?: number;
  }): Promise<PreparedOperation | { ok: false; error: string }> {
    const apply = this.applyFor(req.op);
    if (!apply) {
      return {
        ok: false,
        error: `操作 ${req.op} 没有登记提交点(只有真正动钱/占额度的操作才有两阶段提交)`,
      };
    }

    /**
     * ★ prepare 的实现方式:让操作**自己跑到提交点**然后停下
     *   (commitBoundary 在 prepareOnly 下抛 PreparedControlSignal)。
     *
     * 为什么不在 prepare 里另写一份校验:那样就会出现"两套校验口径",
     * 而校验口径一旦分叉,prepare 说能提交、commit 却被拒(或者更糟:反过来),
     * 是两阶段提交最典型的翻车方式。让 prepare 复用**同一段校验代码**,
     * 停在同一行,是唯一能保证两者一致的做法。
     */
    const before = new Set(this.preparedOps.keys());
    this.prepareOnly = true;
    /** prepare 成功时登记的那一条:必须在收尾时**留下**,不能当残留清掉 */
    let kept: string | null = null;
    try {
      await apply(req.input, req.customerId, req.idempotencyKey);
    } catch (e) {
      if (e instanceof PreparedControlSignal) {
        const entry = this.preparedOps.get(e.preparedId);
        if (!entry) return { ok: false, error: "内部错误:已准备的操作登记丢失" };
        kept = entry.preparedId;
        return {
          preparedId: entry.preparedId,
          op: entry.op,
          customerId: entry.customerId,
          ...(entry.idempotencyKey ? { idempotencyKey: entry.idempotencyKey } : {}),
          ...(entry.preview ? { preview: entry.preview } : {}),
          ...(entry.amount != null ? { amount: entry.amount } : {}),
          preparedAt: entry.preparedAt,
        };
      }
      // 校验失败(账户不存在、余额不足……):这**不是取消**,也不该写"已取消"
      return { ok: false, error: e instanceof Error ? e.message : String(e) };
    } finally {
      this.prepareOnly = false;
      // 兜底:prepare 没走完提交点时,不留半条登记(避免悬挂意图)
      for (const id of this.preparedOps.keys()) {
        if (!before.has(id) && id !== kept) this.preparedOps.delete(id);
      }
    }
    return { ok: false, error: `操作 ${req.op} 没有到达提交点(不是资金操作?)` };
  }

  async commitOperation(
    preparedId: string,
    signal?: { requested: boolean; reason?: string; source?: string },
  ): Promise<CommitOutcome> {
    const entry = this.preparedOps.get(preparedId);
    if (!entry) {
      return { ok: false, committed: false, error: "未找到已准备的操作(可能已中止,或服务重启后登记已丢失)" };
    }
    // 幂等回放:同一个 preparedId 提交两次,第二次拿回第一次的回执,不再动账
    if (entry.committed) return { ok: true, committed: true, result: entry.result };

    // ★ 提交边界:取消**只在这里**有效
    if (signal?.requested) {
      this.preparedOps.delete(preparedId);
      return {
        ok: false,
        committed: false,
        cancelled: {
          reason: signal.reason ?? "上游要求中止执行",
          ...(signal.source ? { source: signal.source } : {}),
        },
      };
    }

    const apply = this.applyFor(entry.op);
    if (!apply) return { ok: false, committed: false, error: `操作 ${entry.op} 的实现已丢失` };

    this.commitDepth++;
    try {
      /**
       * 提交时**重新走一遍校验**(而不是复用 prepare 时的结论):
       *   prepare 与 commit 之间世界可能变了(余额被别处用掉、草稿过期)。
       *   真实两阶段提交也是这个语义 —— commit 才是真正做决定的那一刻。
       */
      const result = await apply(entry.input, entry.customerId, entry.idempotencyKey);
      entry.committed = true;
      entry.result = result;
      return { ok: true, committed: true, result };
    } catch (e) {
      if (e instanceof PreparedControlSignal) {
        return { ok: false, committed: false, error: "内部错误:提交阶段不允许再产生 prepare 信号" };
      }
      return { ok: false, committed: false, error: e instanceof Error ? e.message : String(e) };
    } finally {
      this.commitDepth--;
    }
  }

  async abortOperation(preparedId: string, reason: string): Promise<AbortOutcome> {
    const entry = this.preparedOps.get(preparedId);
    if (!entry) return { ok: false, error: "未找到已准备的操作(可能已中止)" };
    if (entry.committed) {
      /**
       * ★ 已经提交的操作**绝不假装撤销**:它只能走补偿链路。
       *   这里如实回报 alreadyCommitted,让调用方去走 compensateWith ——
       *   而不是把"中止失败"包装成"中止成功",那会让审计说谎。
       */
      return { ok: false, op: entry.op, alreadyCommitted: true };
    }
    this.preparedOps.delete(preparedId);
    /**
     * ★ `reason` **不在这里丢弃,也不在这里写审计**(第 3 项,实测被文档挑出来的问题)。
     *
     *   银行核心没有审计端口 —— 审计只能由编排器写(它持有 traceId/sessionId/channel
     *   与归属信息)。所以这里把原因**原样回传**,由调用方带进 `execution_cancelled`
     *   事件。之前这里写的是 `void reason;`:注释说"用于审计留痕",实现却扔掉它 ——
     *   典型的口径与实现两张皮。
     *   现在:返回体里有 reason,调用方不写审计就是它自己的责任;
     *   本层绝不假装"已经留痕"。
     */
    return { ok: true, op: entry.op, preparedId, reason };
  }

  async listPreparedOperations(customerId?: string): Promise<PreparedOperation[]> {
    return [...this.preparedOps.values()]
      .filter((p) => !p.committed && (!customerId || p.customerId === customerId))
      .map((p) => ({
        preparedId: p.preparedId,
        op: p.op,
        customerId: p.customerId,
        ...(p.idempotencyKey ? { idempotencyKey: p.idempotencyKey } : {}),
        ...(p.preview ? { preview: p.preview } : {}),
        ...(p.amount != null ? { amount: p.amount } : {}),
        preparedAt: p.preparedAt,
      }));
  }

  /**
   * ★ 提交边界。资金操作在"校验完成、即将动账"的那一行调用它。
   *
   * 它做三件事,顺序不能换:
   *   ① 登记"已准备"(登记本身零副作用);
   *   ② 读一次取消信号(信号只在提交之前有效);
   *   ③ 命中取消 → 抛 OperationCancelledError(调用方在**动账之前**退出)。
   */
  private commitBoundary(
    op: string,
    req: {
      customerId: string;
      input: Record<string, unknown>;
      amount?: number;
      preview?: Record<string, unknown>;
      idempotencyKey?: string;
    },
  ): void {
    // 正在提交(重入)时不再登记、不再拦截:提交点已经过了
    if (this.commitDepth > 0) return;

    const preparedId = `prep_${++this.preparedCounter}_${op.replace(/[^A-Za-z0-9]/g, "_")}`;
    this.preparedOps.set(preparedId, {
      preparedId,
      op,
      customerId: req.customerId,
      input: req.input,
      ...(req.idempotencyKey ? { idempotencyKey: req.idempotencyKey } : {}),
      ...(req.amount != null ? { amount: req.amount } : {}),
      ...(req.preview ? { preview: req.preview } : {}),
      preparedAt: this.world.now,
      committed: false,
    });

    const decision = decideAtCommitBoundary(this.opScope);
    if (decision.abort) {
      this.preparedOps.delete(preparedId);
      throw new OperationCancelledError({
        op,
        preparedId,
        reason: decision.reason,
        ...(decision.source ? { source: decision.source } : {}),
      });
    }
    if (this.prepareOnly) throw new PreparedControlSignal(preparedId);
  }

  /** op 名 → 实现(提交点的白名单)。表外操作没有两阶段语义。 */
  private applyFor(
    op: string,
  ): ((input: Record<string, unknown>, customerId: string, idempotencyKey?: string) => Promise<unknown>) | null {
    switch (op) {
      case "transfer.submit":
        return (input) =>
          this.submitTransfer(
            input as unknown as { draftId: string; frozenPayloadHash: string; actionToken: string },
          );
      case "wealth.purchase":
        return (input) => this.submitWealthPurchase(input as unknown as WealthPurchaseInput);
      case "wealth.redeem":
        return (input) => this.submitWealthRedemption(input as unknown as WealthRedemptionInput);
      case "event.fund_step":
        return (input) => this.applyFundStep(input as unknown as EventFundStepInput);
      default:
        return null;
    }
  }

  /** 账户 → 客户(提交边界要记清"这是谁的钱") */
  private customerIdOfAccount(accountId: string): string {
    return this.world.accounts.get(accountId)?.customerId ?? "unknown";
  }

  // ---- 账户 ----

  async getAccount(customerId: string, accountId: string): Promise<Account | null> {
    const acc = this.world.accounts.get(accountId);
    if (!acc || acc.customerId !== customerId) return null;
    return stripAccount(acc);
  }

  async listAccounts(customerId: string): Promise<Account[]> {
    return [...this.world.accounts.values()]
      .filter((a) => a.customerId === customerId)
      .map(stripAccount);
  }

  // ---- 交易 ----

  async listTransactions(customerId: string, query: TransactionQuery): Promise<Transaction[]> {
    const ownedAccountIds = new Set(
      [...this.world.accounts.values()].filter((a) => a.customerId === customerId).map((a) => a.accountId),
    );

    let result = this.world.transactions.filter((t) => ownedAccountIds.has(t.accountId));
    if (query.accountId) result = result.filter((t) => t.accountId === query.accountId);
    if (query.from != null) result = result.filter((t) => t.ts >= query.from!);
    if (query.to != null) result = result.filter((t) => t.ts <= query.to!);
    if (query.minAmount != null) result = result.filter((t) => t.amount >= query.minAmount!);
    if (query.maxAmount != null) result = result.filter((t) => t.amount <= query.maxAmount!);
    if (query.direction) result = result.filter((t) => t.direction === query.direction);
    if (query.category) result = result.filter((t) => t.category?.includes(query.category!));
    if (query.counterparty) {
      const needle = query.counterparty.toLowerCase();
      result = result.filter((t) => t.counterpartyName.toLowerCase().includes(needle));
    }

    result.sort((a, b) => b.ts - a.ts);
    // 只读能力的护栏:结果集限量,防止被诱导批量拉取
    const limit = Math.min(query.limit ?? 50, 200);
    return result.slice(0, limit).map((t) => ({ ...t }));
  }

  async fetchForAnalysis(customerId: string, query: { from?: number; to?: number }): Promise<Transaction[]> {
    // ★ 账单分析专用取数口。
    //   与 listTransactions 的区别:没有 200 条护栏,因为账单聚合需要跨月数据;
    //   但代价是**仅限本人账户 + 时间窗口受限 + 用途单一(喂聚合引擎)**。
    //   原始流水不会流向模型 —— 聚合在能力层用确定性函数完成。
    const ownedAccountIds = new Set(
      [...this.world.accounts.values()].filter((a) => a.customerId === customerId).map((a) => a.accountId),
    );
    let result = this.world.transactions.filter((t) => ownedAccountIds.has(t.accountId));
    if (query.from != null) result = result.filter((t) => t.ts >= query.from!);
    if (query.to != null) result = result.filter((t) => t.ts <= query.to!);
    result.sort((a, b) => b.ts - a.ts);
    return result.map((t) => ({ ...t }));
  }

  // ---- 收款人 ----

  async searchPayees(customerId: string, query: PayeeQuery): Promise<Payee[]> {
    const owned = [...this.world.payees.values()].filter((p) => p.ownerCustomerId === customerId);
    const scored: Array<{ payee: InternalPayee; score: number; note?: string }> = [];

    for (const p of owned) {
      let score = 0;
      let note: string | undefined;

      if (query.name) {
        // ★ 用模糊匹配引擎替代原来的"精确 + 包含"两级判断。
        //   现在覆盖:错别字(编辑距离)、同音姓氏(张玮/章伟)、拼音首字母(zw)、
        //   口头称呼(老王)、以及原有的包含关系。
        const nameScore = scoreName(query.name, p.name);
        // 别名走同一套打分,但略降权 —— 真名优先于昵称
        let aliasBest = { score: 0, basis: "none" as const, explanation: undefined as string | undefined };
        for (const a of p.aliases) {
          const s = scoreName(query.name, a);
          if (s.score > aliasBest.score) aliasBest = s as typeof aliasBest;
        }
        const aliasScore = aliasBest.score * 0.97;

        if (aliasScore > nameScore.score) {
          score = aliasScore;
          note = aliasBest.explanation;
        } else {
          score = nameScore.score;
          note = nameScore.explanation;
        }
      }

      if (query.phone) {
        const q = query.phone.replace(/\D/g, "");
        const pPhone = (p.phone ?? "").replace(/\D/g, "");
        if (q.length >= 4 && pPhone.endsWith(q)) score = Math.max(score, 1);
        else if (pPhone === q) score = Math.max(score, 1);
        else if (q.length > 0 && pPhone.includes(q)) score = Math.max(score, 0.7);
      }

      if (query.bankCode && p.bankCode === query.bankCode) score += 0.15;

      // ★ 阈值 0.75 而不是 0.35。
      //   旧的 0.35 是为"包含关系"设计的;引入编辑距离打分后,
      //   0.60 档(相差两个字)会把「王强」与「王秀兰」这种**完全不同的两个人**
      //   凑成候选,于是每次转账都要多问一句 —— 典型的"安全机制制造噪音"。
      //   低于 0.75 的情况交给 resolvePayee 的澄清流程处理,不在这里混进候选列表。
      if (score > 0.75) scored.push({ payee: p, score, ...(note ? { note } : {}) });
    }

    scored.sort((a, b) => b.score - a.score || b.payee.successHistory.length - a.payee.successHistory.length);
    return scored.slice(0, query.limit ?? 10).map((s) => stripPayee(s.payee));
  }

  async getPayee(customerId: string, payeeId: string): Promise<Payee | null> {
    const p = this.world.payees.get(payeeId);
    if (!p || p.ownerCustomerId !== customerId) return null;
    return stripPayee(p);
  }

  async resolveAlias(customerId: string, alias: string): Promise<Payee | null> {
    // 精确别名
    const exact = this.world.aliases.get(`${customerId}:${alias}`);
    if (exact) {
      const p = this.world.payees.get(exact);
      return p ? stripPayee(p) : null;
    }
    // 大小写/空格归一化后再试
    const normalized = alias.trim().toLowerCase();
    for (const [key, payeeId] of this.world.aliases) {
      const [cid, a] = key.split(":");
      if (cid !== customerId) continue;
      if ((a ?? "").trim().toLowerCase() === normalized) {
        const p = this.world.payees.get(payeeId);
        return p ? stripPayee(p) : null;
      }
    }
    return null;
  }

  async saveAlias(customerId: string, alias: string, payeeId: string): Promise<void> {
    const p = this.world.payees.get(payeeId);
    if (!p || p.ownerCustomerId !== customerId) throw new Error("收款人不存在");
    this.world.aliases.set(`${customerId}:${alias}`, payeeId);
    if (!p.aliases.includes(alias)) p.aliases.push(alias);
  }

  // ---- 可达性与名单 ----

  async verifyPayeeDeliverable(input: {
    payeeName: string;
    accountNo?: string;
    phone?: string;
    bankCode?: string;
  }): Promise<DeliverabilityResult> {
    // 若能在目录中匹配到,则视为可达
    const owned = [...this.world.payees.values()];
    const match = owned.find(
      (p) =>
        (input.accountNo && p.accountNo === input.accountNo) ||
        (input.phone && p.phone === input.phone) ||
        scoreName(input.payeeName, p.name).score >= 0.95,
    );

    const isInterbank = match ? match.bankCode !== SELF_BANK_CODE : false;
    const crossBorder = false;

    return {
      deliverable: match ? true : Boolean(input.accountNo || input.phone),
      nameMatched: match ? scoreName(input.payeeName, match.name).score >= 0.95 : false,
      actualNameMasked: match ? maskName(match.name) : undefined,
      nameSimilarity: match ? scoreName(input.payeeName, match.name).score : undefined,
      bankName: match?.bankName,
      interbank: isInterbank,
      crossBorder,
      estimatedArrival: crossBorder
        ? "预计 1–3 个工作日"
        : isInterbank
          ? "预计 2 小时内到账"
          : "实时到账",
      /**
       * ★ 这里**故意不报手续费**:手续费取决于金额,而可达性查询本身没有金额。
       *   规则与算法在 `core/capabilities/transferFee.ts`,由知道金额的地方去算
       *   (转账草稿、确认卡、试算能力)。以前这里回一个写死的 0,
       *   等于把"没算过"说成了"免手续费" —— 跨行转 6 万也显示免手续费。
       */
    };
  }

  async screenPayee(input: { payeeName: string; accountNo?: string; phone?: string }): Promise<ScreeningResult> {
    const owned = [...this.world.payees.values()];
    const match = owned.find(
      (p) =>
        (input.accountNo && p.accountNo === input.accountNo) ||
        (input.phone && p.phone === input.phone) ||
        scoreName(input.payeeName, p.name).score >= 0.95,
    );

    if (match?.listFlag) {
      return { hit: true, hits: [match.listFlag] };
    }
    return { hit: false, hits: [] };
  }

  // ---- 转账草稿与提交 ----

  async createTransferDraft(intent: TransferIntent): Promise<TransferDraft> {
    const draftId = detIdFromString("DRAFT", `${intent.fromAccountId}:${intent.payee.name}:${intent.amount}:${intent.scheduledAt ?? 0}:${Math.random()}`);
    /**
     * ★ 手续费按**制度条款**算,规则唯一出处:`core/capabilities/transferFee.ts`
     *   (行内免收;跨行 5 万以下免、5 万及以上 0.05%,最低 2 元最高 50 元)。
     *   跨行判定与可达性查询同一口径:先按 payeeId 查目录,
     *   查不到再看入参带的 bankCode;两者都判不出来时按行内算 ——
     *   宁可少收,也不凭空捏一个数字出来。
     */
    const directoryPayee = intent.payee.payeeId ? this.world.payees.get(intent.payee.payeeId) : undefined;
    const bankCode = directoryPayee?.bankCode ?? intent.payee.bankCode;
    const fee = transferFeeOf(intent.amount, bankCode != null && bankCode !== SELF_BANK_CODE);
    const estimatedArrival = intent.scheduledAt ? "按计划执行后实时到账" : "实时到账";

    const frozenPayload = {
      fromAccountId: intent.fromAccountId,
      payeeName: intent.payee.name,
      payeeId: intent.payee.payeeId ?? null,
      accountNoMasked: intent.payee.accountNo ? maskAccountNo(intent.payee.accountNo) : null,
      phone: intent.payee.phone ?? null,
      bankCode: intent.payee.bankCode ?? null,
      amount: intent.amount,
      currency: intent.currency,
      memo: intent.memo ?? null,
      scheduledAt: intent.scheduledAt ?? null,
      fee,
    };

    const frozenPayloadHash = createHash("sha256")
      .update(JSON.stringify(frozenPayload), "utf8")
      .digest("hex");

    const draft: TransferDraft = {
      draftId,
      intent,
      frozenPayloadHash,
      frozenPayload,
      fee,
      estimatedArrival,
      createdAt: this.world.now,
      expiresAt: this.world.now + 5 * 60 * 1000,
      warnings: [],
    };
    this.world.drafts.set(draftId, { ...draft, __consumed: false });
    return draft;
  }

  async submitTransfer(input: {
    draftId: string;
    frozenPayloadHash: string;
    actionToken: string;
  }): Promise<TransferReceipt> {
    const draft = this.world.drafts.get(input.draftId);
    if (!draft) throw new Error("转账草稿不存在或已过期");
    if (draft.__consumed) throw new Error("该转账草稿已被使用(幂等保护)");
    // ★ 载荷冻结校验(防 TOCTOU)
    if (draft.frozenPayloadHash !== input.frozenPayloadHash) {
      throw new Error("载荷哈希不一致:确认内容与执行内容不同,已拒绝执行");
    }
    if (this.world.now > draft.expiresAt) throw new Error("转账草稿已过期,请重新发起");

    const from = this.world.accounts.get(draft.intent.fromAccountId);
    if (!from) throw new Error("付款账户不存在");
    if (from.status !== "active") throw new Error("付款账户状态异常");
    if (from.availableBalance < draft.intent.amount) throw new Error("可用余额不足");

    /**
     * ★★ 提交点(第 3 项)★★ —— 下面这一行**之前**的一切都是零副作用的校验;
     *    **之后**的每一行才真正动账。取消只在这里有效:
     *      · 之前被取消 → 干净中止(余额、流水、回执一个字节都没动);
     *      · 之后才来的取消 → 不允许,只能走 compensateWith 补偿
     *        (transfer.cancel,受可撤销窗口约束)。
     *    这就是"不允许存在第三种状态"的落点。
     */
    this.commitBoundary("transfer.submit", {
      customerId: this.customerIdOfAccount(from.accountId),
      input: input as unknown as Record<string, unknown>,
      amount: draft.intent.amount,
      preview: {
        payeeName: draft.intent.payee.name,
        amount: draft.intent.amount,
        fromAccountId: from.accountId,
      },
    });

    // 执行
    from.balance -= draft.intent.amount;
    from.availableBalance -= draft.intent.amount;

    const transferId = detIdFromString("TRF", `${draft.draftId}:${this.world.now}`);
    // ★ 先把流水号定下来:回执要记 transactionId,撤销入口(MockBankPort.cancelTransfer)
    //   才能从流水侧回到这张回执。取值方式与原实现一致(同样的派生函数、同样的序号)。
    const transactionId = detId("TXN", this.world.transactions.length + 1);
    const receipt: TransferReceipt = {
      transferId,
      transactionId,
      fromAccountId: from.accountId,
      status: "succeeded",
      amount: draft.intent.amount,
      fee: draft.fee,
      currency: draft.intent.currency,
      payeeName: draft.intent.payee.name,
      executedAt: this.world.now,
      /**
       * ★ 撤销窗口必须与"承诺给客户的窗口"是同一个数:
       *   承诺文案取自策略配置(engine.ts 的 `cancellableWindowMs`),
       *   这里的裁决依据也读它。原来这里写死 5 分钟 ——
       *   把配置调成 10 分钟后,系统会明确承诺"10 分钟内可撤销",
       *   客户第 6 分钟点撤销却被银行核心以"已超过可撤销时间窗口"拒绝。
       */
      cancellableUntil: this.world.now + getPolicyConfig().cancellableWindowMs,
      reference: `REF${transferId.slice(-10).toUpperCase()}`,
    };

    this.world.receipts.set(transferId, receipt);
    draft.__consumed = true;

    // 记录流水
    this.world.transactions.push({
      transactionId,
      accountId: from.accountId,
      direction: "out",
      amount: draft.intent.amount,
      currency: draft.intent.currency,
      counterpartyName: draft.intent.payee.name,
      counterpartyId: draft.intent.payee.payeeId,
      category: "转账",
      memo: draft.intent.memo,
      balanceAfter: from.balance,
      ts: this.world.now,
      // ★ 双向可追溯:流水 → 回执。没有这两行,「撤销刚才那笔转账」就找不到回执。
      transferId,
      reference: receipt.reference,
    });

    // 更新收款人历史(下次转账时新颖度下降)
    if (draft.intent.payee.payeeId) {
      const p = this.world.payees.get(draft.intent.payee.payeeId);
      if (p) p.successHistory.push(this.world.now);
    }

    return receipt;
  }

  // ---- 定时任务 ----

  async createSchedule(input: ScheduleIntent): Promise<Schedule> {
    const scheduleId = detIdFromString(
      "SCH",
      `${input.transferIntent.fromAccountId}:${input.transferIntent.payee.name}:${input.firstRunAt}`,
    );
    const schedule: Schedule = {
      scheduleId,
      status: "active",
      nextRunAt: input.firstRunAt,
      intent: input.transferIntent,
      recurrence: input.recurrence,
      createdAt: this.world.now,
    };
    this.world.schedules.set(scheduleId, schedule);
    return schedule;
  }

  async listSchedules(customerId: string): Promise<Schedule[]> {
    const ownedAccountIds = new Set(
      [...this.world.accounts.values()].filter((a) => a.customerId === customerId).map((a) => a.accountId),
    );
    return [...this.world.schedules.values()].filter((s) => ownedAccountIds.has(s.intent.fromAccountId));
  }

  async cancelSchedule(customerId: string, scheduleId: string): Promise<void> {
    const s = this.world.schedules.get(scheduleId);
    if (!s) throw new Error("定时任务不存在");
    /**
     * ★ 归属校验:定时任务会真的扣钱,不能拿别人的任务号来取消。
     *   判据与 listSchedules 完全一致(任务所属账户必须属于当前客户),
     *   否则会出现"列表里看不到、但按编号却取消了"的自相矛盾。
     */
    const owner = this.world.accounts.get(s.intent.fromAccountId)?.customerId;
    if (owner !== customerId) throw new Error("这个定时任务不属于当前客户,无法取消");
    s.status = "cancelled";
  }

  // ---- AA 收款 ----

  async createCollection(customerId: string, input: CollectionIntent): Promise<Collection> {
    const collectionId = detIdFromString("COL", `${input.title}:${this.world.now}:${Math.random()}`);

    let shares: Collection["shares"];
    if (input.splitMode === "equal") {
      const each = Math.round((input.totalAmount / input.participants.length) * 100) / 100;
      // 余数给发起人承担,保证总额精确
      const sum = each * input.participants.length;
      const remainder = Math.round((input.totalAmount - sum) * 100) / 100;
      shares = input.participants.map((p, i) => ({
        participantName: p.displayName,
        participantId: p.payeeId,
        amountDue: i === 0 ? Math.round((each + remainder) * 100) / 100 : each,
        amountPaid: 0,
        status: "pending" as const,
        paymentLink: `bankapp://collect/${collectionId}/${encodeURIComponent(p.displayName)}`,
      }));
    } else if (input.splitMode === "custom") {
      shares = input.participants.map((p) => ({
        participantName: p.displayName,
        participantId: p.payeeId,
        amountDue: p.amount ?? 0,
        amountPaid: 0,
        status: "pending" as const,
        paymentLink: `bankapp://collect/${collectionId}/${encodeURIComponent(p.displayName)}`,
      }));
    } else {
      const totalShares = input.participants.reduce((s, p) => s + (p.shares ?? 1), 0);
      shares = input.participants.map((p) => ({
        participantName: p.displayName,
        participantId: p.payeeId,
        amountDue: Math.round(((input.totalAmount * (p.shares ?? 1)) / totalShares) * 100) / 100,
        amountPaid: 0,
        status: "pending" as const,
        paymentLink: `bankapp://collect/${collectionId}/${encodeURIComponent(p.displayName)}`,
      }));
    }

    const collection: Collection = {
      collectionId,
      customerId,
      title: input.title,
      totalAmount: input.totalAmount,
      currency: input.currency,
      status: "open",
      shares,
      createdAt: this.world.now,
    };
    this.world.collections.set(collectionId, collection);
    return collection;
  }

  /**
   * 列出**本客户**的 AA 账单。
   *
   * ★ 必须按归属过滤:AA 账单的 payload 里带着参与人姓名、手机号、各自欠多少 ——
   *   不过滤就等于把别人的账目念给了当前客户(实测中确实能读到全部)。
   */
  async listCollections(customerId: string): Promise<Collection[]> {
    return [...this.world.collections.values()]
      .filter((c) => c.customerId === customerId)
      .map((c) => ({ ...c, shares: c.shares.map((s) => ({ ...s })) }));
  }

  // ---- 撤销 ----

  /**
   * 撤销一笔尚未入账的转账。
   *
   * ★ 三条硬约束(早期实现三条全违反,对客路径必然失败且可能退错账户):
   *   ① 编号空间:回执以 `TRF_…` 为键,而撤销入口从流水侧过来拿的是 `TXN_…`
   *      —— 这里必须两种编号都能解析到**同一张回执**,否则「撤销刚才那笔转账」永远失败。
   *   ② 客户归属:`customerId` 必须真的被校验,不能拿别人的回执编号来撤别人的钱。
   *   ③ 退款对象:退回 `receipt.fromAccountId` 并校验命中,绝不再按"对手方名+金额"猜一条流水;
   *      找不到原出账账户就如实失败,不允许"回执说退了、账上没退"。
   */
  async cancelTransfer(customerId: string, transferId: string): Promise<CancelResult> {
    const receipt =
      this.world.receipts.get(transferId) ??
      [...this.world.receipts.values()].find((r) => r.transactionId === transferId);
    if (!receipt) return { ok: false, reason: "未找到该笔转账" };

    // ② 归属校验:回执的出账账户必须属于当前客户
    const fromAccount = this.world.accounts.get(receipt.fromAccountId);
    if (!fromAccount || fromAccount.customerId !== customerId) {
      return { ok: false, reason: "这笔转账不属于当前客户,无法撤销" };
    }

    if (receipt.status !== "succeeded") return { ok: false, reason: "该笔转账状态不支持撤销" };
    if (receipt.cancellableUntil != null && this.world.now > receipt.cancellableUntil) {
      return { ok: false, reason: "已超过可撤销时间窗口,款项可能已入账,请联系收款方协商或申请人工处理" };
    }

    // ③ 退款:退到这张回执自己的出账账户
    fromAccount.balance = round2(fromAccount.balance + receipt.amount);
    fromAccount.availableBalance = round2(fromAccount.availableBalance + receipt.amount);
    receipt.status = "failed";
    return { ok: true, refundAmount: receipt.amount };
  }

  // ---- 幂等 ----

  async findByIdempotencyKey(key: string): Promise<{ found: boolean; receipt?: TransferReceipt }> {
    const r = this.world.idempotency.get(key);
    return r ? { found: true, receipt: r } : { found: false };
  }

  /**
   * 登记幂等键 → 这笔转账的回执(提交成功后调用)。
   *
   * ★ 这是幂等链的**写端**:没有它,`findByIdempotencyKey` 永远查不到东西,
   *   能力层那段"重放不得产生第二笔转账"的分支就不可达。
   * ★ 只在成功之后写:失败的尝试不该被当成"已经办过",否则客户重试时会被
   *   当成重放而拿不到钱出去。
   */
  async rememberIdempotency(key: string, receipt: TransferReceipt): Promise<void> {
    if (!key) return;
    this.world.idempotency.set(key, { ...receipt });
  }

  // ---- 客户侧记账(annotation) ----

  /**
   * 创建一条记账批注。
   *
   * ★ 设计立场:批注与银行交易记录**严格分离**。
   *   银行流水是核心系统的既有事实,客户侧只能附加说明,不能改写。
   *   这样既满足了"帮我记一下"的诉求,又不会污染对账依据 ——
   *   如果让客户备注改掉交易记录,对账和审计就都不成立了。
   */
  async createAnnotation(input: {
    ownerCustomerId: string;
    title: string;
    amount?: number;
    direction?: "in" | "out";
    counterpartyHint?: string;
    note?: string;
    tags: string[];
    /** 自动关联:按金额+对手方在近期交易里找最匹配的一条 */
    autoLink?: boolean;
  }): Promise<{
    annotationId: string;
    linkedTransactionId?: string;
    linkedTransactionSummary?: string;
  }> {
    let linkedTransactionId: string | undefined;
    let linkedTransactionSummary: string | undefined;

    if (input.autoLink !== false) {
      const since = this.world.now - 90 * 24 * 3600 * 1000;
      const candidates = this.world.transactions.filter((t) => {
        if (t.ts < since) return false;
        if (input.amount != null && Math.abs(t.amount - input.amount) > 0.01) return false;
        if (input.direction && t.direction !== input.direction) return false;
        if (input.counterpartyHint) {
          const hint = input.counterpartyHint.toLowerCase();
          if (!t.counterpartyName.toLowerCase().includes(hint) && !(t.memo ?? "").toLowerCase().includes(hint)) {
            return false;
          }
        }
        return true;
      });
      // 取最近的一条
      candidates.sort((a, b) => b.ts - a.ts);
      const hit = candidates[0];
      if (hit) {
        linkedTransactionId = hit.transactionId;
        linkedTransactionSummary = `${hit.direction === "out" ? "支出" : "收入"} ¥${hit.amount} · ${hit.counterpartyName} · ${new Date(hit.ts).toLocaleDateString("zh-CN")}`;
      }
    }

    const annotationId = detIdFromString(
      "NOTE",
      `${input.ownerCustomerId}:${input.title}:${this.world.now}:${this.world.annotations.length}`,
    );
    this.world.annotations.push({
      annotationId,
      ownerCustomerId: input.ownerCustomerId,
      title: input.title,
      ...(input.amount != null ? { amount: input.amount } : {}),
      ...(input.direction ? { direction: input.direction } : {}),
      ...(input.counterpartyHint ? { counterpartyHint: input.counterpartyHint } : {}),
      ...(input.note ? { note: input.note } : {}),
      tags: input.tags,
      ...(linkedTransactionId ? { linkedTransactionId } : {}),
      createdAt: this.world.now,
    });

    return {
      annotationId,
      ...(linkedTransactionId ? { linkedTransactionId } : {}),
      ...(linkedTransactionSummary ? { linkedTransactionSummary } : {}),
    };
  }

  /** 查询客户的记账批注 */
  listAnnotations(ownerCustomerId: string, limit = 20): Array<{
    annotationId: string;
    title: string;
    amount?: number;
    direction?: string;
    tags: string[];
    createdAt: number;
    linkedTransactionId?: string;
  }> {
    return this.world.annotations
      .filter((a) => a.ownerCustomerId === ownerCustomerId)
      .sort((a, b) => b.createdAt - a.createdAt)
      .slice(0, limit)
      .map((a) => ({
        annotationId: a.annotationId,
        title: a.title,
        ...(a.amount != null ? { amount: a.amount } : {}),
        ...(a.direction ? { direction: a.direction } : {}),
        tags: a.tags,
        createdAt: a.createdAt,
        ...(a.linkedTransactionId ? { linkedTransactionId: a.linkedTransactionId } : {}),
      }));
  }

  /** 演示辅助:查询当前余额快照 */
  snapshotBalances(customerId: string): Array<{ type: string; maskedNo: string; balance: number }> {
    return [...this.world.accounts.values()]
      .filter((a) => a.customerId === customerId)
      .map((a) => ({ type: a.type, maskedNo: a.maskedNo, balance: a.balance }));
  }

  // ==========================================================================
  // 理财(场景三)
  // ==========================================================================

  async listWealthProducts(query: WealthProductQuery): Promise<WealthProduct[]> {
    const all = [...this.world.wealthProducts.values()].map((p) => toPublicProduct(p));
    return searchProductSeeds(all, query);
  }

  async getWealthProduct(productCode: string): Promise<WealthProduct | null> {
    const p = this.world.wealthProducts.get(productCode);
    return p ? toPublicProduct(p) : null;
  }

  async listWealthHoldings(customerId: string): Promise<WealthHolding[]> {
    this.settleMaturedRedemptions(customerId);
    const out: WealthHolding[] = [];
    for (const h of this.world.wealthHoldings.values()) {
      if (h.ownerCustomerId !== customerId) continue;
      const product = this.world.wealthProducts.get(h.productCode);
      if (!product) continue;
      if (h.shares <= 0) continue;
      const marketValue = round2(h.shares * product.nav);
      const profit = round2(marketValue - h.costAmount);
      out.push({
        holdingId: h.holdingId,
        productCode: h.productCode,
        productName: product.name,
        type: product.type,
        riskLevel: product.riskLevel,
        shares: h.shares,
        costAmount: h.costAmount,
        avgCostNav: round2(h.costAmount / h.shares),
        nav: product.nav,
        marketValue,
        profit,
        profitRate: h.costAmount > 0 ? round2((profit / h.costAmount) * 100) : 0,
        firstPurchaseAt: h.firstPurchaseAt,
        settlement: product.settlement,
        holdingDays: Math.max(0, Math.floor((this.world.now - h.firstPurchaseAt) / (24 * 3600 * 1000))),
        ...(h.maturityAt != null ? { maturityAt: h.maturityAt } : {}),
        ...(h.maturityDisposition ? { maturityDisposition: h.maturityDisposition } : {}),
        ...(h.maturityCredited ? { maturityCredited: true } : {}),
      });
    }
    return out.sort((a, b) => b.marketValue - a.marketValue);
  }

  async getDemandDepositRate(customerId: string): Promise<DemandDepositRate> {
    const asOf = this.world.now;
    return {
      annualRatePct: 0.2,
      effectiveFrom: asOf - 40 * 24 * 3600 * 1000,
      accountTypeLabel: "人民币活期存款",
      asOf,
      source: "本行人民币存款利率表",
    };
  }

  async saveRolloverChoice(input: {
    customerId: string;
    planId: string;
    holdingId: string;
    decision: WealthRolloverChoice["decision"];
    productCode: string | null;
    productName: string | null;
    amountBasis: number;
    status: WealthRolloverChoice["status"];
    gate: string;
    note: string;
  }): Promise<WealthRolloverChoice> {
    const choice: WealthRolloverChoice = {
      choiceId: detIdFromString("RCH", `${input.customerId}:${input.holdingId}:${input.planId}:${input.decision}:${this.world.now}`),
      customerId: input.customerId,
      planId: input.planId,
      holdingId: input.holdingId,
      decision: input.decision,
      productCode: input.productCode,
      productName: input.productName,
      amountBasis: input.amountBasis,
      status: input.status,
      gate: input.gate,
      createdAt: this.world.now,
      note: input.note,
    };
    this.world.wealthRolloverChoices.set(`${input.customerId}:${input.holdingId}`, choice);
    return choice;
  }

  async getRolloverChoice(customerId: string, holdingId: string): Promise<WealthRolloverChoice | null> {
    return this.world.wealthRolloverChoices.get(`${customerId}:${holdingId}`) ?? null;
  }

  async getRiskProfile(customerId: string): Promise<WealthRiskProfile> {    return this.world.wealthRiskProfiles.get(customerId) ?? emptyRiskProfile(customerId);
  }

  /**
   * 客户提交的材料(只读)。
   *
   * ★ 只返回本客户的;演示数据只给主客户准备了材料 ——
   *   配偶客户没有材料时返回空数组,由上层如实告知"没找到可比对的材料",
   *   而不是随便拿别人的材料来凑。
   */
  async listDocuments(customerId: string): Promise<CustomerDocument[]> {
    if (customerId !== this.world.primaryCustomerId) return [];
    return this.world.documents.map((d) => ({ ...d, fields: d.fields.map((f) => ({ ...f })) }));
  }

  async getDocument(customerId: string, documentId: string): Promise<CustomerDocument | null> {
    const list = await this.listDocuments(customerId);
    return list.find((d) => d.documentId === documentId) ?? null;
  }

  async saveRiskProfile(
    customerId: string,
    input: { level: RiskLevel; score: number; validUntil: number; answers: Array<{ questionId: string; optionId: string }> },
  ): Promise<WealthRiskProfile> {
    const profile = buildRiskProfile({
      customerId,
      level: input.level,
      score: input.score,
      assessedAt: this.world.now,
      validUntil: input.validUntil,
      now: this.world.now,
    });
    this.world.wealthRiskProfiles.set(customerId, profile);
    // 问卷作答原文一并留存:监管核查时要能回答"这个等级是怎么来的"
    this.world.riskAssessmentLog.push({
      customerId,
      score: input.score,
      level: input.level,
      answers: input.answers,
      assessedAt: this.world.now,
      validUntil: input.validUntil,
    });
    return profile;
  }

  async submitWealthPurchase(input: WealthPurchaseInput): Promise<WealthPurchaseReceipt> {
    const product = this.world.wealthProducts.get(input.productCode);
    if (!product) throw new Error("产品不存在");

    const account = this.world.accounts.get(input.fromAccountId);
    if (!account || account.customerId !== input.customerId) throw new Error("扣款账户不存在");
    if (account.status !== "active") throw new Error("扣款账户状态异常");

    const math = computePurchase({
      product: toPublicProduct(product),
      amount: input.amount,
      availableBalance: account.availableBalance,
      now: this.world.now,
      settlementDays: 1,
    });
    if (math.error) throw new Error(math.error);

    /**
     * ★★ 提交点 ★★ 理财申购的动账行是下面的"减可用余额"。
     *    校验(产品存在、账户归属、金额与费用计算)全部在提交点之前完成。
     */
    this.commitBoundary("wealth.purchase", {
      customerId: input.customerId,
      input: input as unknown as Record<string, unknown>,
      amount: input.amount,
      preview: { productCode: input.productCode, amount: input.amount, fromAccountId: input.fromAccountId },
    });

    // ★ 承诺类操作的资金学:**动钱,但不划走**。
    //   交易日(T日)先做资金冻结,份额在 T+1 确认时才真正从余额扣除。
    //   因此这里只减可用余额、保留账面余额 —— 这正是"承诺类"与"影响资金"的区别,
    //   也是在确认卡上必须让用户看清的一件事:钱立刻不能再用,但还没真正划走。
    account.availableBalance = round2(account.availableBalance - input.amount);
    if (account.availableBalance < 0) throw new Error("可用余额不足");

    const orderId = detIdFromString("WPU", `${input.customerId}:${product.productCode}:${this.world.now}:${input.amount}`);
    const key = `${input.customerId}:${input.productCode}`;
    const existing = this.world.wealthHoldings.get(key);
    if (existing) {
      existing.shares = round2(existing.shares + math.shares);
      existing.costAmount = round2(existing.costAmount + input.amount);
    } else {
      this.world.wealthHoldings.set(key, {
        holdingId: detIdFromString("HLD", key),
        ownerCustomerId: input.customerId,
        productCode: input.productCode,
        shares: math.shares,
        costAmount: input.amount,
        firstPurchaseAt: this.world.now,
        ...(product.termDays != null
          ? {
              maturityAt: this.world.now + product.termDays * 24 * 3600 * 1000,
              maturityDisposition: "to_demand" as const,
            }
          : {}),
      });
    }

    const order: InternalPurchaseOrder = {
      orderId,
      ownerCustomerId: input.customerId,
      productCode: input.productCode,
      amount: input.amount,
      fee: math.fee,
      shares: math.shares,
      confirmedNav: math.confirmedNav,
      confirmedAt: this.world.now,
      frozenAmount: input.amount,
      ...(input.consentRef ? { consentRef: input.consentRef } : {}),
      reference: `REF${orderId.slice(-10).toUpperCase()}`,
    };
    this.world.wealthPurchases.push(order);

    // 申购流水:资金冻结 —— 记账上先记一笔"理财申购(冻结)",份额确认后才是正式交易
    this.world.transactions.push({
      transactionId: detId("TXN", this.world.transactions.length + 1),
      accountId: account.accountId,
      direction: "out",
      amount: input.amount,
      currency: "CNY",
      counterpartyName: product.name,
      counterpartyId: product.productCode,
      category: "理财",
      memo: `申购${product.name}(份额确认中)`,
      balanceAfter: account.balance,
      ts: this.world.now,
    });

    return {
      orderId,
      status: "frozen",
      productCode: product.productCode,
      productName: product.name,
      amount: input.amount,
      confirmedNav: math.confirmedNav,
      shares: math.shares,
      fee: math.fee,
      frozenAmount: input.amount,
      confirmedAt: this.world.now,
      sharesConfirmedAt: this.world.now + 24 * 3600 * 1000,
      ...(input.consentRef ? { consentRef: input.consentRef } : {}),
      reference: order.reference,
    };
  }

  async submitWealthRedemption(input: WealthRedemptionInput): Promise<WealthRedemptionReceipt> {
    this.settleMaturedRedemptions(input.customerId);

    const holding = this.world.wealthHoldings.get(`${input.customerId}:${this.productCodeOfHolding(input.holdingId)}`);
    if (!holding || holding.ownerCustomerId !== input.customerId) throw new Error("未找到该理财持仓");

    const product = this.world.wealthProducts.get(holding.productCode);
    if (!product) throw new Error("产品不存在");

    const publicProduct = toPublicProduct(product);
    const marketValue = round2(holding.shares * product.nav);
    const holdingView: WealthHolding = {
      holdingId: holding.holdingId,
      productCode: holding.productCode,
      productName: product.name,
      type: product.type,
      riskLevel: product.riskLevel,
      shares: holding.shares,
      costAmount: holding.costAmount,
      avgCostNav: round2(holding.costAmount / holding.shares),
      nav: product.nav,
      marketValue,
      profit: round2(marketValue - holding.costAmount),
      profitRate: round2(((marketValue - holding.costAmount) / holding.costAmount) * 100),
      firstPurchaseAt: holding.firstPurchaseAt,
      settlement: product.settlement,
      holdingDays: Math.max(0, Math.floor((this.world.now - holding.firstPurchaseAt) / (24 * 3600 * 1000))),
    };

    const math = computeRedemption({
      product: publicProduct,
      holding: holdingView,
      ...(input.shares != null ? { shares: input.shares } : {}),
      ...(input.amount != null ? { amount: input.amount } : {}),
      now: this.world.now,
    });
    if (math.error) throw new Error(math.error);

    /**
     * ★★ 提交点 ★★ 赎回的"动账"是下面的份额扣减(以及 T+0 的入账)。
     *    取出份额的校验、费用与到账时间计算都在提交点之前完成。
     */
    this.commitBoundary("wealth.redeem", {
      customerId: input.customerId,
      input: input as unknown as Record<string, unknown>,
      amount: math.netAmount,
      preview: { productCode: holding.productCode, shares: math.shares, netAmount: math.netAmount },
    });

    // 份额立即减少(客户立刻不再享有这部分收益),
    // 但资金**不会立刻到账** —— 这正是赎回必须明确告知"到账时间"的原因。
    holding.shares = math.remainingShares;
    holding.costAmount = round2(holding.costAmount - math.shares * holdingView.avgCostNav);

    const orderId = detIdFromString("WRD", `${input.customerId}:${holding.productCode}:${this.world.now}:${math.shares}`);
    const order: InternalRedemption = {
      orderId,
      ownerCustomerId: input.customerId,
      productCode: holding.productCode,
      shares: math.shares,
      amount: math.netAmount,
      fee: math.fee,
      realizedProfit: math.realizedProfit,
      settlement: product.settlement,
      submittedAt: this.world.now,
      estimatedArrivalAt: math.estimatedArrivalAt,
      settled: false,
      reference: `REF${orderId.slice(-10).toUpperCase()}`,
    };
    this.world.wealthRedemptions.push(order);

    // 到账时效为 T+0 的产品立即入账;T+1/T+2 的挂账,等结算日再入账
    if (settlementDays(product.settlement) === 0) this.creditRedemption(order, holding.productCode);

    return {
      orderId,
      status: "accepted",
      productCode: holding.productCode,
      productName: product.name,
      shares: math.shares,
      estimatedAmount: math.netAmount,
      fee: math.fee,
      settlement: product.settlement,
      estimatedArrivalAt: math.estimatedArrivalAt,
      realizedProfit: math.realizedProfit,
      remainingShares: math.remainingShares,
      submittedAt: this.world.now,
      reference: order.reference,
    };
  }

  /** 按持仓 ID 反查产品代码(持仓 ID 由客户+产品派生,此处做一次反查以保证契约稳定) */
  private productCodeOfHolding(holdingId: string): string {
    for (const h of this.world.wealthHoldings.values()) {
      if (h.holdingId === holdingId) return h.productCode;
    }
    return "";
  }

  /**
   * 赎回资金入账。
   *
   * ★ 为什么单独抽出来:赎回的"份额减少"与"资金到账"在时间上是**分开**的两个事件。
   *   把它们合成一步是最常见的简化,但它会掩盖一个客户最关心的事实 ——
   *   "我的钱什么时候能用"。所以这里让到账成为一次独立的、可延迟的记账动作。
   */
  private creditRedemption(order: InternalRedemption, productCode: string): void {
    if (order.settled) return;
    const product = this.world.wealthProducts.get(productCode);
    const account = [...this.world.accounts.values()].find((a) => a.customerId === order.ownerCustomerId && a.type === "current");
    if (!account) return;
    account.balance = round2(account.balance + order.amount);
    account.availableBalance = round2(account.availableBalance + order.amount);
    order.settled = true;
    this.world.transactions.push({
      transactionId: detId("TXN", this.world.transactions.length + 1),
      accountId: account.accountId,
      direction: "in",
      amount: order.amount,
      currency: "CNY",
      counterpartyName: product?.name ?? productCode,
      counterpartyId: productCode,
      category: "理财",
      memo: `理财赎回到账(${order.settlement})`,
      balanceAfter: account.balance,
      ts: this.world.now,
    });
  }

  // ==========================================================================
  // 卡片管理(场景四)
  //
  // ★ 这一组接口有两条与前三场景不同的实现纪律:
  //
  //   ① **额度永远不由这里改变。** submitLimitAdjustment 只登记一张待审核工单,
  //      卡片上的 creditLimit 在审核通过前一动不动。真实银行核心也是这个结构 ——
  //      Agent 侧根本没有"直接改额度"的接口,想越权也没有入口。
  //
  //   ② **司法冻结在这里也解除不了。** submitUnblockRequest 对
  //      judicial_freeze 直接拒绝受理(而不是收下再说)。银行无权自行解除司法冻结,
  //      如果核心侧"收下申请",Agent 侧就有了说"已提交"的余地 —— 那是在骗客户。
  // ==========================================================================

  async listCards(customerId: string): Promise<BankCard[]> {
    return [...this.world.cards.values()]
      .filter((c) => c.customerId === customerId)
      .map((c) => ({ ...c, kindLabel: CARD_KIND_LABELS[c.kind], statusLabel: CARD_STATUS_LABELS[c.status] }));
  }

  async getCard(customerId: string, cardId: string): Promise<BankCard | null> {
    const c = this.world.cards.get(cardId);
    if (!c || c.customerId !== customerId) return null;
    return { ...c, kindLabel: CARD_KIND_LABELS[c.kind], statusLabel: CARD_STATUS_LABELS[c.status] };
  }

  /**
   * 提交额度调整申请。
   *
   * ★ 返回的 status 一定是 submitted/under_review,**永远不会是 approved**:
   *   审批权在银行审核侧,模拟核心不提供"立即生效"的路径。
   *   这条约束让"申请 ≠ 已提额"在数据层就成立,而不是靠文案自觉。
   */
  async submitLimitAdjustment(input: CardLimitAdjustmentInput): Promise<CardLimitAdjustmentReceipt> {
    const card = this.world.cards.get(input.cardId);
    if (!card || card.customerId !== input.customerId) throw new Error("卡片不存在");
    if (card.creditLimit == null) throw new Error("该卡没有授信额度");
    if (card.status !== "active") throw new Error(`卡片当前状态为「${CARD_STATUS_LABELS[card.status]}」,不受理额度调整`);
    if (input.requestedLimit <= card.creditLimit) throw new Error("申请额度必须高于当前额度");

    const days = (n: number) => this.world.now + n * 24 * 3600 * 1000;
    const applicationId = detIdFromString(
      "LMT",
      `${input.customerId}:${card.cardId}:${this.world.now}:${input.requestedLimit}`,
    );
    const application: CardLimitAdjustment = {
      applicationId,
      cardId: card.cardId,
      cardLast4: card.last4,
      requestedLimit: input.requestedLimit,
      currentLimit: card.creditLimit,
      status: "submitted",
      statusLabel: "已提交,待银行审核",
      submittedAt: this.world.now,
      estimatedDecisionAt: days(LIMIT_RULES.reviewBusinessDays),
      direction: "increase",
    };
    this.world.limitAdjustments.push(application);

    // ★ 刻意不动 card.creditLimit —— 这一行"没写"才是正确的实现。
    return {
      applicationId,
      cardId: card.cardId,
      cardLast4: card.last4,
      requestedLimit: input.requestedLimit,
      currentLimit: card.creditLimit,
      status: "submitted",
      statusLabel: application.statusLabel,
      submittedAt: application.submittedAt,
      estimatedDecisionAt: application.estimatedDecisionAt,
      wording:
        `已提交提额申请(目标额度 ${input.requestedLimit} 元);` +
        `当前额度仍为 ${card.creditLimit} 元,审核通过后才会变化。`,
      reference: `REF${applicationId.slice(-10).toUpperCase()}`,
    };
  }

  async getLimitAdjustment(customerId: string, applicationId: string): Promise<CardLimitAdjustment | null> {
    const hit = this.world.limitAdjustments.find((a) => a.applicationId === applicationId);
    if (!hit) return null;
    const card = this.world.cards.get(hit.cardId);
    if (!card || card.customerId !== customerId) return null;
    return { ...hit };
  }

  async listLimitAdjustments(customerId: string, cardId?: string): Promise<CardLimitAdjustment[]> {
    return this.world.limitAdjustments
      .filter((a) => {
        const card = this.world.cards.get(a.cardId);
        if (!card || card.customerId !== customerId) return false;
        return cardId ? a.cardId === cardId : true;
      })
      .map((a) => ({ ...a }))
      .sort((a, b) => b.submittedAt - a.submittedAt);
  }

  /**
   * 挂失(冻结)卡片 —— 紧急止损动作。
   *
   * ★ 立即生效,不做任何"二次确认"式的等待:
   *   卡丢了之后每多一轮确认,就多一笔可能被盗刷的机会。
   *   这也是全项目唯一一个由能力层自动执行(不经用户确认)的写操作。
   */
  async reportCardLoss(input: {
    customerId: string;
    cardId: string;
    reason?: string;
    scenario?: string;
  }): Promise<CardLossReceipt> {
    const card = this.world.cards.get(input.cardId);
    if (!card || card.customerId !== input.customerId) throw new Error("卡片不存在");

    const already = card.status === "lost";
    card.status = "lost";
    card.statusLabel = CARD_STATUS_LABELS.lost;
    card.lostAt = card.lostAt ?? this.world.now;
    // 挂失后该卡的交易限制一并标记为"已挂失冻结"这一客观状态

    const receipt: CardLossReceipt = {
      cardId: card.cardId,
      cardLast4: card.last4,
      ok: true,
      frozenAt: this.world.now,
      immediate: true,
      reference: `LOSS${detIdFromString("LOSS", `${input.customerId}:${card.cardId}:${this.world.now}`).slice(-8).toUpperCase()}`,
      nextSteps: [
        "补办新卡:换号补卡约 5 个工作日,保留原号约 12 个工作日",
        "补卡后需要激活;换号补卡还要重新设置交易密码",
        "已绑定的自动扣款、快捷支付会失败,补卡后需要重新绑定(保留原号则不用)",
      ],
    };
    this.world.cardLossRecords.push({ ...receipt, customerId: input.customerId, scenario: input.scenario ?? null });
    return already ? { ...receipt, immediate: true } : receipt;
  }

  /**
   * 提交解除限制申请。
   *
   * ★ 司法冻结与信息不完整类在**核心侧**就被拒绝受理 —— 不是"收下但批不了",
   *   而是"根本不该收"。银行没有权限解除司法冻结,收下申请只会让客户白等。
   */
  async submitUnblockRequest(input: CardUnblockInput): Promise<CardUnblockReceipt> {
    const card = this.world.cards.get(input.cardId);
    if (!card || card.customerId !== input.customerId) throw new Error("卡片不存在");
    if (!card.restriction) throw new Error("该卡当前没有交易限制");

    const cause = card.restriction.cause;
    const applicationId = detIdFromString("UBK", `${input.customerId}:${card.cardId}:${this.world.now}`);

    if (cause === "judicial_freeze") {
      return {
        ok: false,
        accepted: false,
        cardId: card.cardId,
        applicationId,
        cause,
        channel: card.restriction.channel,
        message:
          "司法冻结不受理解除申请:银行无权自行解除司法冻结," +
          "只能凭有权机关出具的《解除冻结通知书》办理。请联系出具冻结的机关。",
        estimatedResolution: "收到解除冻结通知书后 1-2 个工作日办结",
        reference: `REF${applicationId.slice(-10).toUpperCase()}`,
      };
    }
    if (cause === "incomplete_information") {
      return {
        ok: false,
        accepted: false,
        cardId: card.cardId,
        applicationId,
        cause,
        channel: card.restriction.channel,
        message: "身份信息不完整类不需要提交申请:请在 App 补全证件信息,提交后系统会自动解除限制。",
        estimatedResolution: "补全后 1 个工作日内自动解除",
        reference: `REF${applicationId.slice(-10).toUpperCase()}`,
      };
    }

    // 可受理:登记待审核工单,限制**继续生效**(effectiveNow = false)
    return {
      ok: true,
      accepted: true,
      cardId: card.cardId,
      applicationId,
      cause,
      channel: card.restriction.channel,
      message:
        `已受理您的解除限制申请(受理单号 ${applicationId})。` +
        "接下来由银行审核,审核期间该卡的交易限制仍然生效。",
      estimatedResolution: card.restriction.estimatedResolution,
      reference: `REF${applicationId.slice(-10).toUpperCase()}`,
    };
  }

  /** 新卡申请(新开户 / 加办卡)—— 只登记申请,批不批在审核侧 */
  async submitCardApplication(input: CardApplicationInput): Promise<CardApplication> {
    const days = (n: number) => this.world.now + n * 24 * 3600 * 1000;
    const applicationId = detIdFromString("CAP", `${input.customerId}:${input.kind}:${this.world.now}`);
    const kindLabel = CARD_KIND_LABELS[input.kind];
    const req = requirementForScenario("new_application");

    return {
      applicationId,
      kind: input.kind,
      kindLabel,
      status: "submitted",
      statusLabel: "已提交,待银行审批",
      requestedLimit: input.requestedLimit ?? null,
      submittedAt: this.world.now,
      estimatedDecisionAt: days(CARD_APPLICATION_REVIEW_BUSINESS_DAYS),
      requiredDocuments: input.kind === "credit" ? ["本人身份证件", "收入或工作证明(可能需要)"] : ["本人身份证件"],
      postApprovalSteps: [
        "① 激活新卡(卡函上有激活码)",
        `② ${req.requiresTransactionPassword ? "设置交易密码" : "确认交易密码沿用"}(新开户必须新设)`,
      ],
      reference: `REF${applicationId.slice(-10).toUpperCase()}`,
    };
  }

  /**
   * 挂失后补卡下单。
   *
   * ★ 换号与保留原号的差别在这里落成**三组不同的数据**:
   *   到手天数(5 vs 12)、卡号是否变化、要不要重设交易密码。
   *   三次差异都由 `requirementForScenario` 与 `REPLACEMENT_ETA_DAYS` 决定,
   *   不在文案里各写一遍 —— 否则迟早会出现"卡上写 5 天、回复里说 12 天"。
   */
  async orderCardReplacement(input: CardReplacementInput): Promise<CardReplacementOrder> {
    const card = this.world.cards.get(input.cardId);
    if (!card || card.customerId !== input.customerId) throw new Error("卡片不存在");
    if (card.status !== "lost" && card.status !== "frozen") throw new Error("该卡未处于挂失状态,不能补卡");

    const keep = input.mode === "keep_number";
    const etaDays = keep ? REPLACEMENT_ETA_DAYS.keepNumber : REPLACEMENT_ETA_DAYS.newNumber;
    const scenario = scenarioForReplacementMode(input.mode);
    const req = requirementForScenario(scenario);
    const newLast4 = keep ? null : this.newCardLast4(card.cardId);

    const orderId = detIdFromString("RPL", `${input.customerId}:${card.cardId}:${input.mode}:${this.world.now}`);
    const order: CardReplacementOrder = {
      orderId,
      cardId: card.cardId,
      cardLast4: card.last4,
      mode: input.mode,
      modeLabel: keep ? "保留原号补卡" : "换号补卡(新卡号)",
      status: "accepted",
      estimatedArrivalAt: this.world.now + etaDays * 24 * 3600 * 1000,
      estimatedDays: etaDays,
      requiresActivation: req.requiresActivation,
      requiresTransactionPassword: req.requiresTransactionPassword,
      cardNumberChanges: !keep,
      newCardLast4: newLast4,
      submittedAt: this.world.now,
      reference: `REF${orderId.slice(-10).toUpperCase()}`,
      wording: keep
        ? `保留原号补卡:卡号仍是尾号 ${card.last4},预计 ${etaDays} 个工作日到手。` +
          `★ 比换号补卡多等约 ${REPLACEMENT_ETA_DAYS.keepNumber - REPLACEMENT_ETA_DAYS.newNumber} 天 —— 这是保留原号的代价。` +
          "到手后需要激活,交易密码沿用原密码,已绑定的快捷支付与代扣无需重新绑定。"
        : `换号补卡:新卡尾号 ${newLast4},预计 ${etaDays} 个工作日到手。` +
          "到手后需要① 激活,② 重新设置交易密码 —— 因为卡号变了,原交易密码不会沿用到新卡上。" +
          "原卡已绑定的快捷支付、自动扣款、会员订阅都要重新绑定。",
    };
    this.world.replacementOrders.push(order);

    // ★ 补卡下单后,原卡状态推进为"补卡在途",并记录补发关系 ——
    //   激活时据此判断"要不要重设交易密码"(卡号变过就必须重设)。
    card.status = "replacement_in_transit";
    card.statusLabel = CARD_STATUS_LABELS.replacement_in_transit;
    card.replacementOf = keep ? card.cardId : "new_number";

    return order;
  }

  /** 激活新卡(可选同时引导设置交易密码) */
  async activateCard(input: {
    customerId: string;
    cardId: string;
    setTransactionPassword: boolean;
    activationCode?: string;
  }): Promise<CardActivationReceipt> {
    const card = this.world.cards.get(input.cardId);
    if (!card || card.customerId !== input.customerId) throw new Error("卡片不存在");
    if (card.activated && card.status !== "pending_activation") throw new Error("该卡已激活");
    if (card.status === "lost" || card.status === "closed") throw new Error("该卡状态不允许激活");

    card.activated = true;
    card.activatedAt = this.world.now;
    // ★ 交易密码:需要新设时置为 false(表示"尚未设置,待走原生流程"),
    //   沿用原密码时保持 true。Agent 从不接触密码本身。
    card.transactionPasswordSet = !input.setTransactionPassword;
    if (card.status === "pending_activation" || card.status === "replacement_in_transit") {
      card.status = "active";
      card.statusLabel = CARD_STATUS_LABELS.active;
    }

    return {
      cardId: card.cardId,
      cardLast4: card.last4,
      ok: true,
      activatedAt: this.world.now,
      transactionPasswordSet: input.setTransactionPassword,
      transactionPasswordInherited: !input.setTransactionPassword,
      message: input.setTransactionPassword
        ? "卡片已激活;还需在 App 设置交易密码后才能真正用于交易。"
        : "卡片已激活,交易密码沿用原密码,现在即可使用。",
      reference: `REF${detIdFromString("ACT", `${input.customerId}:${card.cardId}`).slice(-10).toUpperCase()}`,
    };
  }

  /**
   * 生成一个确定性的新卡号后四位。
   *
   * ★ 判据必须是 **cardId**,不能是 `world.now`:
   *   早期版本用 `NEW:${this.world.now}` 做键 —— 同一张卡在不同时刻补卡会得到
   *   不同尾号,而不同卡在同一时刻补卡会**撞成同一个尾号**。前者让回执前后不一致,
   *   后者更糟:两个客户(或两张卡)的新卡号看起来是同一张。
   *   补卡新号的语义是"这张卡的新号",所以键只能是卡片本身。
   *   (这段判据原本写在一份从未被调用的局部函数里 —— 声明的语义是对的,
   *    接线时却用了另一个键。这里把它按原意接上。)
   */
  private newCardLast4(cardId: string): string {
    return String(
      1000 +
        (Number.parseInt(createHash("sha1").update(`REPL:${cardId}`).digest("hex").slice(0, 6), 16) % 9000),
    );
  }

  /** 演示辅助:卡片状态快照 */
  snapshotCards(customerId: string): Array<{ productName: string; last4: string; status: string; creditLimit: number | null }> {
    return [...this.world.cards.values()]
      .filter((c) => c.customerId === customerId)
      .map((c) => ({
        productName: c.productName,
        last4: c.last4,
        status: CARD_STATUS_LABELS[c.status],
        creditLimit: c.creditLimit,
      }));
  }

  // ==========================================================================
  // 订阅代扣(新场景)
  //
  // ★ 这三行接口的设计要点只有一条:**取消之后的返回值不许再说"还会扣"**。
  //   nextDebitAt 置 null、status 置 cancelled、cancelledAt 记上时间 ——
  //   客户与企业客户复核时,证据链就在这三个字段上。
  // ==========================================================================

  async listSubscriptions(customerId: string): Promise<BankSubscription[]> {
    return [...this.world.subscriptions.values()]
      .filter((s) => s.customerId === customerId)
      .map((s) => ({ ...s }))
      .sort((a, b) => (b.nextDebitAt ?? 0) - (a.nextDebitAt ?? 0));
  }

  async getSubscription(customerId: string, subscriptionId: string): Promise<BankSubscription | null> {
    const s = this.world.subscriptions.get(subscriptionId);
    if (!s || s.customerId !== customerId) return null;
    return { ...s };
  }

  async cancelSubscription(input: SubscriptionCancelInput): Promise<SubscriptionCancelReceipt> {
    const s = this.world.subscriptions.get(input.subscriptionId);
    if (!s || s.customerId !== input.customerId) throw new Error("代扣协议不存在");
    // ★ 能力层与策略层都已经拦过一遍"已取消"与"商户侧协议",
    //   这里是最后一道:即使有人绕过路由直接调核心,也不会出现"取消了两次"。
    if (s.channel !== "bank_mandate") throw new Error("该协议签约方在商户侧,本行无权解除");
    if (s.status === "cancelled") throw new Error("该代扣协议此前已取消");

    s.status = "cancelled";
    s.statusLabel = "已取消";
    s.cancelledAt = this.world.now;
    // ★ 这一行"清掉下次扣款日"才是取消的实质:协议还在(要留痕),
    //   但它再也不会产生扣款。留着日期等于告诉客户"下个月还会扣"。
    s.nextDebitAt = null;

    return {
      ok: true,
      subscriptionId: s.subscriptionId,
      merchantName: s.merchantName,
      status: "cancelled",
      statusLabel: s.statusLabel,
      cancelledAt: this.world.now,
      effective: s.cancelEffective,
      nextDebitAtAfter: null,
      refundPolicy: s.refundPolicy,
      cancelConsequence: s.cancelConsequence,
      wording:
        `已解除「${s.merchantName}」的代扣协议:下一期起不再扣款` +
        `(本期已扣的 ${round2(s.amount)} 元按协议不予退还)。`,
      reference: `REF${detIdFromString("SUBC", `${s.customerId}:${s.subscriptionId}`).slice(-10).toUpperCase()}`,
    };
  }

  // ==========================================================================
  // 跨场景事件联动(新场景)
  //
  // ★ 三个方法各自只做一件事,合起来刚好覆盖"客户确认之后"的全部落库:
  //   listLifeEvents / saveLifeEvent —— 事件的读与登记(都不动钱);
  //   applyFundStep                 —— 预留 / 定时任务 / 解开(改的是"能不能用");
  //   placeExternalOrder            —— 外部下单(钱离开银行体系)。
  //   规划本身**没有任何接口** —— 它是能力层的纯函数,银行核心不参与"想"这件事。
  // ==========================================================================

  async listLifeEvents(customerId: string): Promise<LifeEvent[]> {
    return [...this.world.lifeEvents.values()]
      .filter((e) => e.customerId === customerId)
      .map((e) => ({ ...e }))
      .sort((a, b) => a.occursAt - b.occursAt);
  }

  async saveLifeEvent(input: LifeEventInput): Promise<LifeEvent> {
    const eventId = detIdFromString("EVT", `${input.customerId}:${input.kind}:${input.occursAt}:${input.title}`);
    /**
     * ★ 幂等:同一个客户、同一件事、同一天,重复登记只保留一条。
     *   客户说两遍"记一下我下月15号纪念日"是很常见的,
     *   若每说一遍就多一条,方案里会重复出现同一件事。
     */
    const existing = this.world.lifeEvents.get(eventId);
    if (existing) return { ...existing };

    const kindLabel: Record<LifeEvent["kind"], string> = {
      birthday: "生日",
      anniversary: "纪念日",
      payday: "发薪日",
      big_expense: "大额支出预备",
      travel: "出行",
      renewal_window: "续费窗口",
    };
    const event: LifeEvent = {
      eventId,
      customerId: input.customerId,
      kind: input.kind,
      kindLabel: kindLabel[input.kind],
      title: input.title,
      occursAt: input.occursAt,
      leadDays: input.leadDays ?? 14,
      ...(input.note ? { note: input.note } : {}),
      source: "user_stated",
      sourceLabel: "客户自述",
      ...(input.budgetHint != null ? { budgetHint: input.budgetHint } : {}),
    };
    this.world.lifeEvents.set(eventId, event);
    return { ...event };
  }

  async listExternalMerchants(query: { category?: string; keyword?: string }): Promise<ExternalMerchant[]> {
    return this.world.externalMerchants
      .filter((m) => (query.category ? m.category === query.category : true))
      .filter((m) =>
        query.keyword ? m.name.includes(query.keyword) || m.hotItem.includes(query.keyword) || m.categoryLabel.includes(query.keyword) : true,
      )
      .map((m) => ({ ...m }));
  }

  /**
   * 资金操作步骤(预留 / 定时任务 / 解开)。
   *
   * ★ 关键语义:**预留会占用可用余额,但不改余额**。
   *   balance 是"账上有多少钱",availableBalance 是"现在能动的钱"。
   *   把预留做成"从余额里扣掉"是错的(钱并没有走),做成"什么都不变"也是错的
   *   (客户会以为自己还能把这笔钱花掉,然后在下一次扣款时发现余额不足)。
   */
  async applyFundStep(input: EventFundStepInput): Promise<EventFundStepReceipt> {
    const account = this.world.accounts.get(input.fromAccountId);
    if (!account || account.customerId !== input.customerId) throw new Error("资金账户不存在");
    const taskKey = `${input.customerId}:${input.planId}:${input.stepId}`;
    const existing = this.world.eventFundTasks.get(taskKey);

    const modeLabel = { reserve: "预留(锁定)", schedule: "定时任务", release: "解除预留" }[input.mode];

    /**
     * ★ 模式互斥(这一步踩过坑):预留与定时任务是**相反的资金语义** ——
     *   预留立刻占掉可用余额,定时任务此刻一分钱都不动。而幂等判断过去只看
     *   "有没有 active 任务",没看**模式**,于是同一步骤可以中途换模式:
     *     · 先 reserve 再 schedule → 跳过"不动余额",回一句「已登记定时任务」,
     *       而系统里根本没有这笔可取消的任务(承诺"随时取消"是假的);
     *     · 先 schedule 再 reserve → 跳过扣减,却回一句「已为…预留 ¥X」(谎报资金状态)。
     *   正确做法是**不猜客户改主意**:如实拒绝,并告诉他先解开再重来。
     *   注意"同模式重复提交"仍然是幂等的(客户连点两次确认不该锁两次)。
     */
    if (existing?.active && input.mode !== "release" && existing.mode !== input.mode) {
      const holder = existing.mode === "reserve" ? "预留" : "定时任务";
      const wanted = input.mode === "reserve" ? "预留" : "定时任务";
      throw new Error(
        `这一步已经按「${holder}」处理过了,不能直接改成「${wanted}」:` +
          `两者的资金语义相反(预留会立刻占用可用余额,定时任务此刻不动钱)。` +
          `请先回复解除,再重新按您要的方式办一次。`,
      );
    }

    if (input.mode === "release") {
      // ★ 解开只能解**确实存在且仍然有效**的那一笔:重复解开等于凭空造钱。
      if (!existing || !existing.active) throw new Error("没有找到这笔可解除的预留(可能已经解开或从未预留)");
      /**
       * ★ 出账账户必须与当初预留时一致。
       *   过去只看"有没有这笔预留",不看钱当初从哪个账户划走 —— 于是换个账户解锁,
       *   可用余额会加到一个**从未被扣过**的账户上,总额凭空变多。
       */
      if (existing.fromAccountId !== input.fromAccountId) {
        throw new Error(
          `这笔资金准备当初是从另一个账户划出的(与本次指定的账户对不上),不能从当前账户解开。` +
            `请换用原出账账户操作。`,
        );
      }
      existing.active = false;
      /**
       * ★ 两种模式的"解开"不是一回事,不能共用一段代码:
       *   · 预留:当初真的从可用余额里划走了钱 → 现在加回来;
       *   · 定时任务:当初一分钱都没动 → **绝不能加钱**(加了就是凭空造钱),
       *     要做的是把那笔到点会执行的任务取消掉。
       */
      if (existing.mode === "schedule") {
        const cancelled = this.cancelEventSchedule(existing.scheduleId);
        return {
          ok: true,
          planId: input.planId,
          stepId: input.stepId,
          mode: "release",
          modeLabel,
          fromAccountId: account.accountId,
          fromAccountLabel: `${account.maskedNo}`,
          toName: input.toName,
          amount: existing.amount,
          currency: input.currency,
          reservedUntil: null,
          scheduleId: existing.scheduleId ?? null,
          nextRunAt: null,
          availableAfter: account.availableBalance,
          reference: `REF${detIdFromString("EVTR", `${taskKey}:release`).slice(-10).toUpperCase()}`,
          wording:
            `已取消这笔定时任务(¥${round2(existing.amount)})` +
            (cancelled
              ? "。它本来就不占用可用余额,所以余额没有变化。"
              : "。★ 注意:系统里没有找到对应的任务记录,已按「未占用余额」如实处理,请联系人工核对。"),
        };
      }
      account.availableBalance = round2(account.availableBalance + existing.amount);
      return {
        ok: true,
        planId: input.planId,
        stepId: input.stepId,
        mode: "release",
        modeLabel,
        fromAccountId: account.accountId,
        fromAccountLabel: `${account.maskedNo}`,
        toName: input.toName,
        amount: existing.amount,
        currency: input.currency,
        reservedUntil: null,
        scheduleId: null,
        nextRunAt: null,
        availableAfter: account.availableBalance,
        reference: `REF${detIdFromString("EVTR", `${taskKey}:release`).slice(-10).toUpperCase()}`,
        wording: `已解开此前预留的 ¥${round2(existing.amount)}:这笔钱重新回到可用余额。`,
      };
    }

    if (input.mode === "reserve") {
      if (input.amount > account.availableBalance) throw new Error("可用余额不足");
      // ★ 幂等:同一步骤重复确认不会锁两次(第二次只会看到同一笔预留)
      if (!existing || !existing.active) {
        /**
         * ★★ 提交点 ★★ 预留的动账行是下一行的"减可用余额"。
         *    注意它**只在真的会扣额度时**才设提交点(幂等重复提交时不动钱,
         *    也就不存在"提交"这个动作)。
         *    解预留在上面直接返回 —— 它是**撤销类**动作,刻意不设取消点:
         *    在撤销补偿的路径上再允许取消,等于拒绝把客户的损失还回去。
         */
        this.commitBoundary("event.fund_step", {
          customerId: input.customerId,
          input: input as unknown as Record<string, unknown>,
          amount: input.amount,
          preview: { mode: "reserve", planId: input.planId, stepId: input.stepId, toName: input.toName },
        });
        account.availableBalance = round2(account.availableBalance - input.amount);
        this.world.eventFundTasks.set(taskKey, {
          taskId: detIdFromString("ETK", taskKey),
          customerId: input.customerId,
          planId: input.planId,
          stepId: input.stepId,
          mode: "reserve",
          amount: input.amount,
          fromAccountId: account.accountId,
          createdAt: this.world.now,
          active: true,
        });
      }
      const task = this.world.eventFundTasks.get(taskKey)!;
      return {
        ok: true,
        planId: input.planId,
        stepId: input.stepId,
        mode: "reserve",
        modeLabel,
        fromAccountId: account.accountId,
        fromAccountLabel: account.maskedNo,
        toName: input.toName,
        amount: task.amount,
        currency: input.currency,
        reservedUntil: input.scheduledAt,
        scheduleId: null,
        nextRunAt: null,
        availableAfter: account.availableBalance,
        reference: `REF${detIdFromString("EVTK", taskKey).slice(-10).toUpperCase()}`,
        wording:
          `已为「${input.toName}」预留 ¥${round2(task.amount)}:` +
          `这笔钱仍在您名下,但已标记为这笔用途专用,期间不计入可用余额。`,
      };
    }

    // schedule:登记一个到点执行的定时任务(此刻不动可用余额)
    if (!existing || !existing.active) {
      /**
       * ★★ 提交点 ★★ 定时任务此刻不动钱,但它**创建一个到点会扣钱的任务**,
       *    所以同样设提交点:客户在确认页改主意时,不该留下一个他并不知道的任务。
       *    (撤销这个任务有 cancelSchedule,走的是同一套补偿语义。)
       */
      this.commitBoundary("event.fund_step", {
        customerId: input.customerId,
        input: input as unknown as Record<string, unknown>,
        amount: input.amount,
        preview: { mode: "schedule", planId: input.planId, stepId: input.stepId, at: input.scheduledAt },
      });
      /**
       * ★ 必须登记出**真的任务**,不能只回一个任务号。
       *
       *   踩过的坑:这里过去只拼了一个 `ETS…` 字符串回给客户,`world.schedules` 里
       *   什么都没有 —— 回执却写着"执行前可以随时取消"。客户真去取消时,
       *   系统里根本没有这笔任务;承诺是假的,而这正是黄色档敢让客户"先答应"的前提。
       *   现在走既有的 createSchedule,任务会出现在 listSchedules 里、也能被 cancelSchedule 取消。
       */
      const schedule = this.createScheduleSync({
        transferIntent: {
          fromAccountId: account.accountId,
          payee: { name: input.toName },
          amount: input.amount,
          currency: input.currency,
          memo: `事件联动资金准备:${input.toName}`,
          scheduledAt: input.scheduledAt,
        },
        firstRunAt: input.scheduledAt,
        recurrence: { frequency: "once", interval: 1 },
        onInsufficientFunds: "notify_and_skip",
        preExecutionReminder: true,
      });
      this.world.eventFundTasks.set(taskKey, {
        taskId: detIdFromString("ETK", taskKey),
        customerId: input.customerId,
        planId: input.planId,
        stepId: input.stepId,
        mode: "schedule",
        amount: input.amount,
        fromAccountId: account.accountId,
        createdAt: this.world.now,
        active: true,
        scheduleId: schedule.scheduleId,
      });
    }
    const task = this.world.eventFundTasks.get(taskKey)!;
    const scheduleId = task.scheduleId ?? `ETS${detIdFromString("ETS", taskKey).slice(-8).toUpperCase()}`;
    return {
      ok: true,
      planId: input.planId,
      stepId: input.stepId,
      mode: "schedule",
      modeLabel,
      fromAccountId: account.accountId,
      fromAccountLabel: account.maskedNo,
      toName: input.toName,
      amount: task.amount,
      currency: input.currency,
      reservedUntil: null,
      scheduleId,
      nextRunAt: input.scheduledAt,
      availableAfter: account.availableBalance,
      reference: `REF${detIdFromString("EVTS", taskKey).slice(-10).toUpperCase()}`,
      wording:
        `已登记定时任务:${formatYmd(input.scheduledAt)} 按您确认的口径执行这笔资金准备` +
        `(¥${round2(task.amount)},任务号 ${scheduleId})。` +
        `★ 此刻**没有**从可用余额里扣钱;执行前您可以随时取消这笔任务。`,
    };
  }

  /**
   * 登记一个定时任务(同步版,供资金步内部使用)。
   *
   * ★ 与 createSchedule 的区别:那个是 async 的 BankPort 方法,这里是内部同步实现 ——
   *   资金步要在同一个同步段里既登记任务、又拿到任务号写进回执。
   *   两者用**同一套派生规则**,所以外部通过 listSchedules 看到的就是同一笔任务。
   */
  private createScheduleSync(input: ScheduleIntent): Schedule {
    const scheduleId = detIdFromString(
      "SCH",
      `${input.transferIntent.fromAccountId}:${input.transferIntent.payee.name}:${input.firstRunAt}`,
    );
    const schedule: Schedule = {
      scheduleId,
      status: "active",
      nextRunAt: input.firstRunAt,
      intent: input.transferIntent,
      recurrence: input.recurrence,
      createdAt: this.world.now,
    };
    this.world.schedules.set(scheduleId, schedule);
    return schedule;
  }

  /**
   * 取消事件联动登记的定时任务,返回是否真的取消到了。
   *
   * ★ 如实返回:调用方据此决定回执怎么说 —— 取消不到就说"系统里没找到这笔任务",
   *   而不是照抄一句"已取消"糊过去。
   */
  private cancelEventSchedule(scheduleId: string | null | undefined): boolean {
    if (!scheduleId) return false;
    const s = this.world.schedules.get(scheduleId);
    if (!s) return false;
    s.status = "cancelled";
    return true;
  }

  /**
   * 这一步当前有没有生效中的预留(只读)。
   *
   * ★ 与 applyFundStep 里的幂等判断读的是**同一份数据**,因此不会出现
   *   "路由说有一笔、执行时说没有"这种自相矛盾。
   */
  async getEventFundTask(
    customerId: string,
    planId: string,
    stepId: string,
  ): Promise<{ active: boolean; mode: string; amount: number; fromAccountId: string } | null> {
    const task = this.world.eventFundTasks.get(`${customerId}:${planId}:${stepId}`);
    if (!task) return null;
    return { active: task.active, mode: task.mode, amount: task.amount, fromAccountId: task.fromAccountId };
  }

  /**
   * 外部服务操作步骤(向外部商户下单)。
   *
   * ★ 两个必须如实回填的事实:
   *   ① status 只能是 `submitted`(已受理)—— 商户有没有真的接单,银行侧不知道,
   *      写成"已完成"就是把"提交"读成了"结果";
   *   ② cancelPolicy 必须原样来自商户目录 —— 客户判断反悔成本的唯一依据。
   */
  async placeExternalOrder(input: EventExternalStepInput): Promise<EventExternalStepReceipt> {
    const account = this.world.accounts.get(input.fromAccountId);
    if (!account || account.customerId !== input.customerId) throw new Error("出账账户不存在");
    const merchant = this.world.externalMerchants.find((m) => m.merchantId === input.merchantId);
    if (!merchant) throw new Error("外部商户不存在");
    if (input.amount < merchant.minAmount) throw new Error(`低于商户起订金额 ${merchant.minAmount}`);

    /**
     * 幂等键 = 客户 + 步骤 + 订购内容 + 金额。
     *
     * ★ 为什么不用方案号(planId):方案会过期重建 —— 客户明天再说一次"帮我订花"
     *   就会生成一份**新方案**(新 planId),用 planId 做键等于根本不幂等,
     *   同一个纪念日会订出第二束花。步骤号(stable,形如 `evt_anniversary-S4`)才是
     *   "这一步业务动作"的身份。
     * ★ 为什么把内容与金额也放进来:换一束花、改一个金额是**新的一次订购**,
     *   不应该被幂等吃掉;只有"同一件事、同一个价"的重复提交才回放。
     */
    const orderKey = `${input.customerId}:${input.stepId}:${input.item}:${round2(input.amount)}`;
    const orderId = `EXTORD${detIdFromString("EXTORD", orderKey).slice(-8).toUpperCase()}`;

    /**
     * ★ 幂等:同一件事、同一个价的重复提交只会产生一张订单。
     *
     * 踩过的坑:这里是**无条件 push** —— 客户把同一句话再说一遍、再确认一次,
     * 就真的下了第二张单(实测 externalOrders.length 从 1 变 2,两张同号订单)。
     * 资金步有幂等判断、外部步没有,两侧不对称;而"订了两次花"是客户要自己
     * 去找商户退的**不可逆外部后果**,不能靠"用户不会重复说"来兜底。
     * 重复提交时原样回放首次受理结果(客户看到的信息完全一致),而不是新增订单。
     */
    const existing = this.world.externalOrders.find((o) => o.orderId === orderId);
    if (existing) {
      const { customerId: _owner, ...replay } = existing;
      return {
        ...replay,
        wording:
          `这一步之前已经提交过,本次没有重复下单。` +
          `已向「${existing.merchantName}」提交订单:${existing.item},金额 ¥${round2(existing.amount)}(订单号 ${existing.orderId})。` +
          `如需再加一份,请说明新的订购内容或直接与商户联系。`,
        idempotentReplay: true,
      };
    }
    const receipt: EventExternalStepReceipt = {
      ok: true,
      planId: input.planId,
      stepId: input.stepId,
      orderId,
      merchantId: merchant.merchantId,
      merchantName: merchant.name,
      item: input.item,
      amount: round2(input.amount),
      currency: input.currency,
      scheduledAt: input.scheduledAt,
      status: "submitted",
      statusLabel: "已受理(等待商户确认档期)",
      cancelPolicy: merchant.cancelPolicy,
      fromAccountId: account.accountId,
      fromAccountLabel: account.maskedNo,
      reference: `REF${detIdFromString("EXTREF", orderId).slice(-10).toUpperCase()}`,
      wording:
        `已向「${merchant.name}」提交订单:${input.item},金额 ¥${round2(input.amount)}。` +
        `商户受理后会另行确认档期;退订或改期按商户政策办理。`,
    };
    this.world.externalOrders.push({ ...receipt, customerId: input.customerId });
    return receipt;
  }

  /** 演示辅助:事件联动快照(预留任务与外部订单,便于演示开头交代初始状态) */
  snapshotEventLinkage(customerId: string): {
    events: Array<{ title: string; occursAt: number; kindLabel: string }>;
    fundTasks: Array<{ stepId: string; mode: string; amount: number; active: boolean }>;
    externalOrders: Array<{ merchantName: string; item: string; amount: number; statusLabel: string }>;
  } {
    return {
      events: [...this.world.lifeEvents.values()]
        .filter((e) => e.customerId === customerId)
        .map((e) => ({ title: e.title, occursAt: e.occursAt, kindLabel: e.kindLabel })),
      fundTasks: [...this.world.eventFundTasks.values()]
        .filter((t) => t.customerId === customerId)
        .map((t) => ({ stepId: t.stepId, mode: t.mode, amount: t.amount, active: t.active })),
      externalOrders: this.world.externalOrders
        .filter((o) => o.customerId === customerId)
        .map((o) => ({ merchantName: o.merchantName, item: o.item, amount: o.amount, statusLabel: o.statusLabel })),
    };
  }

  /** 演示辅助:代扣协议快照(与卡片/理财同一套做法,便于演示开头交代初始状态) */
  snapshotSubscriptions(customerId: string): Array<{ merchantName: string; amount: number; cadence: string; nextDebitAt: number | null; status: string }> {
    return [...this.world.subscriptions.values()]
      .filter((s) => s.customerId === customerId)
      .map((s) => ({
        merchantName: s.merchantName,
        amount: s.amount,
        cadence: s.cadenceLabel,
        nextDebitAt: s.nextDebitAt,
        status: s.statusLabel,
      }));
  }

  /** 到达结算日的赎回单自动入账(惰性结算:每次读账本时顺手推进一次) */
  private settleMaturedRedemptions(customerId: string): void {
    for (const r of this.world.wealthRedemptions) {
      if (r.settled || r.ownerCustomerId !== customerId) continue;
      if (this.world.now >= r.estimatedArrivalAt) this.creditRedemption(r, r.productCode);
    }
  }

  /** 演示辅助:理财持仓快照 */
  snapshotWealthHoldings(customerId: string): Array<{ productName: string; shares: number; marketValue: number; profit: number }> {
    return [...this.world.wealthHoldings.values()]
      .filter((h) => h.ownerCustomerId === customerId && h.shares > 0)
      .map((h) => {
        const p = this.world.wealthProducts.get(h.productCode);
        const mv = round2(h.shares * (p?.nav ?? 1));
        return {
          productName: p?.name ?? h.productCode,
          shares: h.shares,
          marketValue: mv,
          profit: round2(mv - h.costAmount),
        };
      });
  }

  /** 演示辅助:快照落盘(可复现演示) */
  async persist(path: string): Promise<void> {
    await mkdir(dirname(path), { recursive: true });
    await writeFile(
      path,
      JSON.stringify(
        {
          balances: [...this.world.accounts.values()].map((a) => ({
            accountId: a.accountId,
            customerId: a.customerId,
            balance: a.balance,
          })),
          receipts: [...this.world.receipts.values()],
          schedules: [...this.world.schedules.values()],
          collections: [...this.world.collections.values()],
        },
        null,
        2,
      ),
      "utf8",
    );
  }

  static async load(path: string): Promise<unknown | null> {
    try {
      return JSON.parse(await readFile(path, "utf8"));
    } catch {
      return null;
    }
  }
}

// ============================================================================
// 脱敏工具 —— 敏感字段的唯一边界
// ============================================================================

function stripAccount(acc: InternalAccount): Account {
  return {
    accountId: acc.accountId,
    customerId: acc.customerId,
    maskedNo: acc.maskedNo,
    type: acc.type,
    currency: acc.currency,
    balance: acc.balance,
    availableBalance: acc.availableBalance,
    ...(acc.creditLimit != null ? { creditLimit: acc.creditLimit } : {}),
    status: acc.status,
  };
}

function stripPayee(p: InternalPayee): Payee {
  const successCount = p.successHistory.length;
  const last = successCount > 0 ? Math.max(...p.successHistory) : undefined;
  const hasSelfAccount = p.isSelfOwned;

  return {
    payeeId: p.payeeId,
    name: p.name,
    maskedAccountNo: maskAccountNo(p.accountNo),
    phone: p.phone ? maskPhoneMiddle(p.phone) : undefined,
    bankCode: p.bankCode,
    bankName: p.bankName,
    novelty: {
      isFirstTime: successCount === 0 && !hasSelfAccount,
      successCount,
      lastSuccessAt: last,
    },
    isSelfOwned: p.isSelfOwned,
    isWhitelisted: p.isWhitelisted,
    aliases: [...p.aliases],
  };
}

export function maskAccountNo(accountNo: string): string {
  const d = accountNo.replace(/\D/g, "");
  if (d.length <= 4) return "****";
  return `**** **** **** ${d.slice(-4)}`;
}

// ============================================================================
// 理财工具
// ============================================================================

/**
 * 近 6 个月最大回撤(百分比点数)。
 * 存款类没有净值回撤,记 null,展示时写「未披露」,不用文案里的「超 25%」去填。
 */
const DRAWDOWN_6M_PCT: Record<string, number | null> = {
  LC1001: 0.04,
  LC1002: 0.38,
  LC1003: 0.91,
  LC2001: 3.46,
  LC2002: 6.2,
  LC3001: 14.8,
  LC3002: 27.4,
  LC4001: null,
  LC5001: 19.1,
};
const DRAWDOWN_METHOD = "区间内复权净值从峰值到谷值的最大跌幅";

/** 目录种子 → 对外产品快照(净值日期统一取当前时间,演示可复现) */
function toPublicProduct(p: WealthProductSeed): WealthProduct {
  const navDate = p.navDate ?? Date.now();
  const pct = DRAWDOWN_6M_PCT[p.productCode];
  const maxDrawdown6m =
    pct == null
      ? null
      : {
          pct,
          windowStart: navDate - 180 * 24 * 3600 * 1000,
          windowEnd: navDate,
          method: DRAWDOWN_METHOD,
          asOf: navDate,
        };
  return {
    productCode: p.productCode,
    name: p.name,
    type: p.type,
    riskLevel: p.riskLevel,
    minAmount: p.minAmount,
    incrementAmount: p.incrementAmount,
    termDays: p.termDays,
    yield7d: p.yield7d,
    yield1y: p.yield1y,
    performanceBenchmark: p.performanceBenchmark,
    nav: p.nav,
    navDate,
    managementFeeRate: p.managementFeeRate,
    custodyFeeRate: p.custodyFeeRate,
    purchaseFeeRate: p.purchaseFeeRate,
    settlement: p.settlement,
    redeemable: p.redeemable,
    minHoldingDays: p.minHoldingDays,
    status: p.status,
    riskDisclosure: p.riskDisclosure,
    highlight: p.highlight,
    maxDrawdown6m,
  };
}

/**
 * 产品检索。
 *
 * ★ 这里与 `core/capabilities/wealth.ts` 的 searchProducts 是同一套语义 ——
 *   银行核心侧实现它,是为了让"筛选与排序在数据侧完成"这件事保持成立:
 *   能力层拿到的是**已经筛好的结果**,而不是"先拉全量再在 Agent 侧筛"。
 *   全量拉取再筛选在真实系统里是不允许的(等于开放了产品库全表读)。
 */
function searchProductSeeds(products: WealthProduct[], query: WealthProductQuery): WealthProduct[] {
  let list = products.filter((p) => p.status === "on_sale");

  if (query.keyword) {
    const k = query.keyword.trim();
    list = list.filter(
      (p) =>
        p.name.includes(k) ||
        p.highlight.includes(k) ||
        {
          cash: "现金管理类",
          fixed_income: "固定收益类",
          mixed: "混合类",
          equity: "权益类",
          deposit: "存款类",
        }[p.type].includes(k) ||
        k === p.productCode,
    );
  }
  if (query.type) list = list.filter((p) => p.type === query.type);
  if (query.maxRiskLevel) {
    const cap = Number(query.maxRiskLevel.slice(1));
    list = list.filter((p) => Number(p.riskLevel.slice(1)) <= cap);
  }
  if (query.maxMinAmount != null) list = list.filter((p) => p.minAmount <= query.maxMinAmount!);

  const yieldOf = (p: WealthProduct) => p.yield1y ?? p.yield7d ?? p.performanceBenchmark ?? 0;
  const sortBy = query.sortBy ?? "yield";
  list = [...list].sort((a, b) => {
    switch (sortBy) {
      case "risk":
        return Number(a.riskLevel.slice(1)) - Number(b.riskLevel.slice(1)) || yieldOf(b) - yieldOf(a);
      case "term":
        return (a.termDays ?? 0) - (b.termDays ?? 0) || yieldOf(b) - yieldOf(a);
      case "minAmount":
        return a.minAmount - b.minAmount || yieldOf(b) - yieldOf(a);
      default:
        return yieldOf(b) - yieldOf(a);
    }
  });

  return list.slice(0, Math.min(query.limit ?? 10, 50));
}

export function maskPhoneMiddle(phone: string): string {
  const d = phone.replace(/\D/g, "");
  if (d.length < 7) return "***";
  return `${d.slice(0, 3)}****${d.slice(-4)}`;
}

export function maskName(name: string): string {
  if (name.length <= 1) return name;
  if (name.length === 2) return name[0] + "*";
  return name[0] + "*".repeat(name.length - 2) + name[name.length - 1];
}
