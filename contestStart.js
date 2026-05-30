/**
 * Minimal contest start for backend cron (status transition + participant balances).
 */

function normalizeContestStatus(status) {
  const legacy = { upcoming: 'published', live: 'ongoing', ended: 'completed' };
  return legacy[status] || status;
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

  const batch = db.batch();
  const now = new Date().toISOString();

  for (const partDoc of partsSnap.docs) {
    const participation = partDoc.data();
    const balance = participation.testMode
      ? participation.testBalance || 10000
      : participation.starting_balance || 10000;

    batch.update(partDoc.ref, {
      participant_status: 'active',
      starting_balance: balance,
      current_balance: balance,
      peak_equity: balance,
      lowest_equity: balance,
    });
  }

  batch.update(contestRef, {
    status: 'ongoing',
    started_at: now,
    participants: participantCount,
    updatedAt: require('firebase-admin/firestore').FieldValue.serverTimestamp(),
  });

  await batch.commit();
  return { participantCount, contest };
}

module.exports = {
  startContestAdmin,
  normalizeContestStatus,
};
