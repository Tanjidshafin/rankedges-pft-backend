/**
 * Minimal contest start for backend cron (status transition + participant balances).
 */

function normalizeContestStatus(status) {
  const legacy = { upcoming: 'published', live: 'ongoing', ended: 'completed' };
  return legacy[status] || status;
}

function resolveGainBasis(contest) {
  if (!contest || contest.type === 'pft') return 'balance';
  return contest.gain_basis === 'equity' ? 'equity' : 'balance';
}

/**
 * @param {import('firebase-admin').firestore.Firestore} db
 */
async function startContestAdmin(db, contestId) {
  const contestRef = db.collection('contests').doc(contestId);
  const contestSnap = await contestRef.get();
  if (!contestSnap.exists) {
    throw new Error('Contest not found');
  }

  const contest = { id: contestSnap.id, ...contestSnap.data() };
  if (normalizeContestStatus(contest.status) !== 'published') {
    throw new Error('Contest must be published to start');
  }

  const partsSnap = await db
    .collection('contestParticipations')
    .where('contest_id', '==', contestId)
    .get();

  const participantCount = partsSnap.size;
  const type = contest.type || 'standard';

  if (type === '1v1' && participantCount < 2) {
    throw new Error('1v1 contest requires at least 2 participants');
  }
  if (type === '3v3' && participantCount < 6) {
    throw new Error('3v3 contest requires at least 6 participants');
  }

  const gainBasis = resolveGainBasis(contest);
  const batch = db.batch();
  const FieldValue = require('firebase-admin/firestore').FieldValue;
  const now = new Date().toISOString();

  for (const partDoc of partsSnap.docs) {
    const participation = partDoc.data();
    let balance = 10000;
    let equity = 10000;

    if (participation.testMode) {
      balance = participation.testBalance || 10000;
      equity = balance;
    } else if (participation.starting_balance > 0) {
      balance = Number(participation.starting_balance) || 10000;
      equity = Number(participation.starting_equity ?? balance) || balance;
    } else if (participation.account_id) {
      const accountSnap = await db.collection('tradingAccounts').doc(String(participation.account_id)).get();
      if (accountSnap.exists) {
        const account = accountSnap.data();
        balance = Number(account.balance ?? 0);
        equity = Number(account.equity ?? balance);
      }
    }

    const watermark = gainBasis === 'equity' ? equity : balance;

    batch.update(partDoc.ref, {
      participant_status: 'active',
      starting_balance: balance,
      starting_equity: equity,
      current_balance: balance,
      current_equity: equity,
      peak_equity: watermark,
      lowest_equity: watermark,
    });

    const lbSnap = await db
      .collection('leaderboard')
      .where('contest_id', '==', contestId)
      .where('user_id', '==', participation.user_id)
      .limit(1)
      .get();

    if (!lbSnap.empty) {
      batch.update(lbSnap.docs[0].ref, {
        starting_balance: balance,
        starting_equity: equity,
        balance,
        equity,
        peak_equity: watermark,
        lowest_equity: watermark,
        gain: 0,
        dd: 0,
        score: 0,
        participant_status: 'active',
        updatedAt: FieldValue.serverTimestamp(),
      });
    }
  }

  batch.update(contestRef, {
    status: 'ongoing',
    started_at: now,
    participants: participantCount,
    updatedAt: FieldValue.serverTimestamp(),
  });

  await batch.commit();
  return { participantCount, contest };
}

module.exports = {
  startContestAdmin,
  normalizeContestStatus,
};
