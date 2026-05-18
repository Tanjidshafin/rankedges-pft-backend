/**
 * Server-side achievement evaluation (mirrors src/services/achievementService.ts).
 */

const ACHIEVEMENT_DEFINITIONS = [
  { id: 'first_steps', title: 'First Steps', description: 'Connect your first trading account.' },
  { id: 'diversified', title: 'Diversified', description: 'Connect 3 or more trading accounts.' },
  { id: 'power_trader', title: 'Power Trader', description: 'Connect 5 or more trading accounts.' },
  { id: 'profitable', title: 'Profitable Trader', description: 'Achieve $1,000+ in total profit.' },
  { id: 'high_roller', title: 'High Roller', description: 'Achieve $10,000+ in total profit.' },
  { id: 'whale', title: 'Whale', description: 'Achieve $100,000+ in total profit.' },
  { id: 'active_trader', title: 'Active Trader', description: 'Complete 100 or more trades across all accounts.' },
  { id: 'trade_machine', title: 'Trade Machine', description: 'Complete 1,000 or more trades across all accounts.' },
  { id: 'sharpshooter', title: 'Sharpshooter', description: 'Maintain a 70%+ average win rate.' },
  { id: 'precision_master', title: 'Precision Master', description: 'Maintain an 80%+ average win rate.' },
  { id: 'big_volume', title: 'Big Volume', description: 'Trade 100+ lots in total across all accounts.' },
  { id: 'volume_king', title: 'Volume King', description: 'Trade 1,000+ lots in total across all accounts.' },
  { id: 'competitor', title: 'Competitor', description: 'Participate in your first contest.' },
  { id: 'serial_competitor', title: 'Serial Competitor', description: 'Participate in 5 or more contests.' },
  { id: 'veteran_competitor', title: 'Veteran Competitor', description: 'Participate in 10 or more contests.' },
  { id: 'top_10', title: 'Top 10', description: 'Finish in the top 10 in any contest.' },
  { id: 'podium', title: 'Podium', description: 'Finish in the top 3 in any contest.' },
  { id: 'champion', title: 'Champion', description: 'Win first place in any contest.' },
  { id: 'multi_champion', title: 'Multi Champion', description: 'Win first place in 3 contests.' },
  { id: 'prize_winner', title: 'Prize Winner', description: 'Receive a paid prize payout from a contest.' },
  { id: 'watchdog', title: 'Watchdog', description: 'Have a scam alert approved by the admin team.' },
  { id: 'community_guard', title: 'Community Guard', description: 'Have 3 scam alerts approved by the admin team.' },
  { id: 'reviewer', title: 'Reviewer', description: 'Write an approved broker or contest review.' },
  { id: 'complete_profile', title: 'Complete Profile', description: 'Set a profile picture and your country.' },
  { id: 'early_adopter', title: 'Early Adopter', description: 'Joined the RankEdges community.' },
  { id: 'gladiator_1v1', title: '1v1 Gladiator', description: 'Win first place in a 1v1 contest.' },
];

const DEFINITION_BY_ID = new Map(ACHIEVEMENT_DEFINITIONS.map((d) => [d.id, d]));

function buildConnectedAccountIdSet(accounts) {
  const ids = new Set();
  for (const account of accounts) {
    for (const candidate of [account.id, account.metaapi_account_id, account.login]) {
      if (typeof candidate === 'string' && candidate.trim()) {
        ids.add(candidate.trim());
      }
    }
  }
  return ids;
}

function isUnlocked(achievementId, ctx) {
  switch (achievementId) {
    case 'first_steps':
      return ctx.tradingAccountCount >= 1;
    case 'diversified':
      return ctx.tradingAccountCount >= 3;
    case 'power_trader':
      return ctx.tradingAccountCount >= 5;
    case 'profitable':
      return ctx.totalProfit >= 1000;
    case 'high_roller':
      return ctx.totalProfit >= 10000;
    case 'whale':
      return ctx.totalProfit >= 100000;
    case 'active_trader':
      return ctx.totalTrades >= 100;
    case 'trade_machine':
      return ctx.totalTrades >= 1000;
    case 'sharpshooter':
      return ctx.avgWinRate >= 70;
    case 'precision_master':
      return ctx.avgWinRate >= 80;
    case 'big_volume':
      return ctx.totalLot >= 100;
    case 'volume_king':
      return ctx.totalLot >= 1000;
    case 'competitor':
      return ctx.contestCount >= 1;
    case 'serial_competitor':
      return ctx.contestCount >= 5;
    case 'veteran_competitor':
      return ctx.contestCount >= 10;
    case 'top_10':
      return ctx.bestRank !== null && ctx.bestRank <= 10;
    case 'podium':
      return ctx.bestRank !== null && ctx.bestRank <= 3;
    case 'champion':
      return ctx.firstPlaceCount >= 1;
    case 'multi_champion':
      return ctx.firstPlaceCount >= 3;
    case 'prize_winner':
      return ctx.hasPaidPayout;
    case 'watchdog':
      return ctx.approvedScamAlerts >= 1;
    case 'community_guard':
      return ctx.approvedScamAlerts >= 3;
    case 'reviewer':
      return ctx.writtenReviews >= 1;
    case 'complete_profile':
      return ctx.hasAvatar && ctx.hasCountry;
    case 'early_adopter':
      return true;
    case 'gladiator_1v1':
      return ctx.won1v1;
    default:
      return false;
  }
}

/**
 * @param {import('firebase-admin').firestore.Firestore} db
 * @param {Record<string, string>} collections
 */
function createAchievementEngine(db, collections) {
  const {
    users: usersCol,
    tradingAccounts: tradingAccountsCol,
    leaderboard: leaderboardCol,
    prizePayouts: prizePayoutsCol,
    scamAlerts: scamAlertsCol,
    reviews: reviewsCol,
    contestParticipations: contestParticipationsCol,
    metaApiTrades: metaApiTradesCol,
    userAchievements: userAchievementsCol,
  } = collections;

  async function sumTotalLotForUser(userId, connectedIdSet) {
    if (!connectedIdSet.size) return 0;
    const snap = await db.collection(metaApiTradesCol).where('user_id', '==', userId).get();
    let totalLot = 0;
    for (const docSnap of snap.docs) {
      const data = docSnap.data();
      const accountId = String(data.account_id || '');
      const accountLogin = data.account_login ? String(data.account_login) : '';
      if (!connectedIdSet.has(accountId) && !(accountLogin && connectedIdSet.has(accountLogin))) {
        continue;
      }
      totalLot += Number(data.volume || 0);
    }
    return totalLot;
  }

  async function fetchExtraContext(userId, leaderboardEntries) {
    const [alertsSnap, reviewsSnap, participationsSnap] = await Promise.all([
      db
        .collection(scamAlertsCol)
        .where('submitted_by', '==', userId)
        .where('status', '==', 'approved')
        .get(),
      db.collection(reviewsCol).where('user_id', '==', userId).where('status', '==', 'approved').get(),
      db.collection(contestParticipationsCol).where('user_id', '==', userId).get(),
    ]);

    const firstPlaceContestIds = new Set(
      leaderboardEntries.filter((e) => e.rank === 1).map((e) => e.contest_id),
    );

    let won1v1 = false;
    if (firstPlaceContestIds.size > 0) {
      participationsSnap.forEach((docSnap) => {
        const data = docSnap.data();
        if (firstPlaceContestIds.has(data.contest_id) && data.room_type === '1v1') {
          won1v1 = true;
        }
      });
    }

    return {
      approvedScamAlerts: alertsSnap.size,
      writtenReviews: reviewsSnap.size,
      won1v1,
    };
  }

  async function buildAchievementContext(userId) {
    const userSnap = await db.collection(usersCol).doc(userId).get();
    const userData = userSnap.exists ? userSnap.data() : {};

    const [accountsSnap, leaderboardSnap, payoutsSnap] = await Promise.all([
      db.collection(tradingAccountsCol).where('user_id', '==', userId).get(),
      db.collection(leaderboardCol).where('user_id', '==', userId).get(),
      db.collection(prizePayoutsCol).where('user_id', '==', userId).get(),
    ]);

    const accounts = accountsSnap.docs.map((docSnap) => ({ id: docSnap.id, ...docSnap.data() }));
    const connectedAccounts = accounts.filter((a) => a.status === 'connected');
    const connectedIdSet = buildConnectedAccountIdSet(connectedAccounts);

    const leaderboardEntries = leaderboardSnap.docs.map((docSnap) => {
      const data = docSnap.data();
      return { rank: Number(data.rank), contest_id: data.contest_id };
    });

    const totalProfit = accounts.reduce((sum, a) => sum + Number(a.profit || 0), 0);
    const totalTrades = accounts.reduce((sum, a) => sum + Number(a.total_trades || 0), 0);
    const avgWinRate =
      accounts.length > 0
        ? accounts.reduce((sum, a) => sum + Number(a.win_rate || 0), 0) / accounts.length
        : 0;
    const bestRank =
      leaderboardEntries.length > 0 ? Math.min(...leaderboardEntries.map((e) => e.rank)) : null;
    const firstPlaceCount = leaderboardEntries.filter((e) => e.rank === 1).length;
    const hasPaidPayout = payoutsSnap.docs.some((docSnap) => docSnap.data().status === 'paid');

    const totalLot = await sumTotalLotForUser(userId, connectedIdSet);
    const extraCtx = await fetchExtraContext(userId, leaderboardEntries);

    return {
      tradingAccountCount: accounts.length,
      totalProfit,
      totalTrades,
      avgWinRate,
      totalLot,
      contestCount: leaderboardEntries.length,
      bestRank,
      firstPlaceCount,
      hasPaidPayout,
      hasAvatar: !!userData.avatar,
      hasCountry: !!userData.country,
      ...extraCtx,
    };
  }

  async function getStoredAchievements(userId) {
    const snap = await db.collection(userAchievementsCol).doc(userId).get();
    if (!snap.exists) return [];
    const data = snap.data();
    return Array.isArray(data?.achievements) ? data.achievements : [];
  }

  /**
   * @returns {Promise<{ newlyUnlocked: string[], definitions: typeof ACHIEVEMENT_DEFINITIONS }>}
   */
  async function checkAndAwardAchievementsForUser(userId) {
    const [ctx, alreadyStored] = await Promise.all([
      buildAchievementContext(userId),
      getStoredAchievements(userId),
    ]);

    const storedIds = new Set(alreadyStored.map((a) => a.id));
    const newlyUnlocked = [];

    for (const def of ACHIEVEMENT_DEFINITIONS) {
      if (!storedIds.has(def.id) && isUnlocked(def.id, ctx)) {
        newlyUnlocked.push(def.id);
      }
    }

    if (newlyUnlocked.length === 0) {
      return { newlyUnlocked: [], definitions: ACHIEVEMENT_DEFINITIONS };
    }

    const { FieldValue, Timestamp } = require('firebase-admin/firestore');
    const now = Timestamp.now();
    const newEntries = newlyUnlocked.map((id) => ({ id, unlockedAt: now }));
    const merged = [...alreadyStored, ...newEntries];

    await db.collection(userAchievementsCol).doc(userId).set(
      { achievements: merged, updatedAt: FieldValue.serverTimestamp() },
      { merge: true },
    );

    return { newlyUnlocked, definitions: ACHIEVEMENT_DEFINITIONS };
  }

  return {
    ACHIEVEMENT_DEFINITIONS,
    DEFINITION_BY_ID,
    buildAchievementContext,
    checkAndAwardAchievementsForUser,
  };
}

module.exports = {
  ACHIEVEMENT_DEFINITIONS,
  DEFINITION_BY_ID,
  createAchievementEngine,
};
