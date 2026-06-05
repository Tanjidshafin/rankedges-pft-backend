#!/usr/bin/env node
/**
 * Remove PFT ghost / untitled contests from Prize tab scope and fix batch links.
 * Usage (from backend/):
 *   node scripts/delete-untitled-contests.js --dry-run
 *   node scripts/delete-untitled-contests.js --confirm
 */

const path = require('node:path');
const admin = require('firebase-admin');
const { FieldValue } = require('firebase-admin/firestore');

require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const COLLECTIONS = {
  contests: 'contests',
  batches: 'pftBatches',
  leaderboard: 'leaderboard',
  prizePayouts: 'prizePayouts',
};

function initializeFirebaseAdmin() {
  if (admin.apps.length > 0) return;
  const serviceAccountJson = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  if (serviceAccountJson) {
    admin.initializeApp({ credential: admin.credential.cert(JSON.parse(serviceAccountJson)) });
    return;
  }
  const projectId = process.env.FIREBASE_PROJECT_ID;
  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
  const privateKey = process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n');
  if (projectId && clientEmail && privateKey) {
    admin.initializeApp({
      credential: admin.credential.cert({ projectId, clientEmail, privateKey }),
    });
    return;
  }
  throw new Error('Missing Firebase admin credentials in backend/.env');
}

function isPftContestDoc(contest) {
  if (!contest) return false;
  if (contest.completed_by === 'sync' || contest.rankings_locked_by === 'sync') return true;
  if (contest.type === 'pft') return true;
  if (contest.pft_batch_id) return true;
  if (contest.pft_batch_number != null) return true;
  if (contest.enrollment_mode === 'admin_only' && /pft/i.test(contest.name || '')) return true;
  return false;
}

function getContestAdminLabel(contest) {
  return contest.name?.trim() || contest.broker_name?.trim() || 'Untitled Contest';
}

function isPrizeTabGhost(contest) {
  const status = contest.status;
  const endedLike = status === 'ended' || status === 'completed';
  if (!endedLike) return false;
  if (isPftContestDoc(contest)) return false;
  return getContestAdminLabel(contest) === 'Untitled Contest';
}

function mapBatchStatusToContestStatus(batchStatus) {
  switch (String(batchStatus || '')) {
    case 'scheduled':
      return 'published';
    case 'active':
      return 'ongoing';
    case 'capturing':
    case 'completed':
    case 'archived':
      return 'completed';
    default:
      return 'published';
  }
}

function buildContestPayloadForPftBatch(batchId, batchData, createdBy) {
  const batchStatus = String(batchData.status || 'scheduled');
  const contestStatus = mapBatchStatusToContestStatus(batchStatus);
  const payload = {
    broker_id: 'public',
    broker_name: 'RankEdges PFT',
    creator_id: createdBy || batchData.createdBy || 'system',
    creator_type: 'trader',
    creator_name: 'RankEdges Admin',
    name: `PFT Batch ${batchData.batchNumber}`,
    type: 'pft',
    start_at: batchData.startAt,
    end_at: batchData.endAt,
    prize_pool: 0,
    rules: 'Prop Firm Tournament — admin-enrolled participants only.',
    status: contestStatus,
    scoring_mode: 'gain',
    dd_cap: 0,
    participants: Number(batchData.participantCount || 0),
    join_method: 'manual_approval',
    enrollment_mode: 'admin_only',
    pft_batch_id: batchId,
    pft_batch_number: batchData.batchNumber,
    start_mode: 'scheduled',
    availability: 'public',
    access_type: 'open',
    updatedAt: FieldValue.serverTimestamp(),
  };

  if (batchStatus === 'active') {
    payload.started_at = batchData.startAt || new Date().toISOString();
  }
  if (['capturing', 'completed', 'archived'].includes(batchStatus)) {
    payload.rankings_locked = true;
    payload.rankings_locked_at = batchData.completedAt || batchData.captureTimestamp || new Date().toISOString();
    payload.completed_at = batchData.completedAt || batchData.endAt;
  }
  return payload;
}

async function deleteContestCascade(db, contestId) {
  const [payoutSnap, leaderboardSnap] = await Promise.all([
    db.collection(COLLECTIONS.prizePayouts).where('contest_id', '==', contestId).get(),
    db.collection(COLLECTIONS.leaderboard).where('contest_id', '==', contestId).get(),
  ]);

  const batch = db.batch();
  payoutSnap.docs.forEach((doc) => batch.delete(doc.ref));
  leaderboardSnap.docs.forEach((doc) => batch.delete(doc.ref));
  batch.delete(db.collection(COLLECTIONS.contests).doc(contestId));
  await batch.commit();

  return { payouts: payoutSnap.size, leaderboard: leaderboardSnap.size };
}

async function clearBatchContestLinks(db, contestId) {
  const snap = await db.collection(COLLECTIONS.batches).where('contestId', '==', contestId).get();
  if (snap.empty) return [];

  const batches = snap.docs.map((doc) => ({ id: doc.id, ...doc.data() }));
  await Promise.all(
    snap.docs.map((doc) =>
      doc.ref.set(
        { contestId: FieldValue.delete(), updatedAt: FieldValue.serverTimestamp() },
        { merge: true },
      ),
    ),
  );
  return batches;
}

async function recreateContestForBatch(db, batchId, batchData) {
  const payload = {
    ...buildContestPayloadForPftBatch(batchId, batchData, batchData.createdBy || 'cleanup'),
    createdAt: FieldValue.serverTimestamp(),
  };
  const contestRef = await db.collection(COLLECTIONS.contests).add(payload);
  await db.collection(COLLECTIONS.batches).doc(batchId).set(
    { contestId: contestRef.id, updatedAt: FieldValue.serverTimestamp() },
    { merge: true },
  );
  return contestRef.id;
}

async function main() {
  const dryRun = process.argv.includes('--dry-run');
  const confirm = process.argv.includes('--confirm');
  if (!dryRun && !confirm) {
    console.error('Pass --dry-run to preview or --confirm to delete.');
    process.exit(1);
  }

  initializeFirebaseAdmin();
  const db = admin.firestore();

  const snap = await db.collection(COLLECTIONS.contests).get();
  const ghosts = snap.docs
    .map((doc) => ({ id: doc.id, ...doc.data() }))
    .filter(isPrizeTabGhost);

  console.log(`Found ${ghosts.length} ghost/untitled prize-tab contest(s):\n`);
  for (const c of ghosts) {
    console.log(
      `  - ${c.id} | status=${c.status} | completed_by=${c.completed_by || '—'} | participants=${c.participants ?? 0}`,
    );
  }

  if (ghosts.length === 0) {
    console.log('\nNothing to clean up.');
    process.exit(0);
  }

  if (dryRun) {
    for (const c of ghosts) {
      const batchSnap = await db.collection(COLLECTIONS.batches).where('contestId', '==', c.id).get();
      console.log(`    linked batches: ${batchSnap.docs.map((d) => d.id).join(', ') || 'none'}`);
    }
    console.log('\nDry run only — no documents changed. Re-run with --confirm to clean up.');
    process.exit(0);
  }

  console.log('\nCleaning up...');
  for (const c of ghosts) {
    const linkedBatches = await clearBatchContestLinks(db, c.id);
    const deleted = await deleteContestCascade(db, c.id);
    console.log(
      `  Removed contest ${c.id} (${deleted.payouts} payouts, ${deleted.leaderboard} leaderboard rows); unlinked ${linkedBatches.length} batch(es)`,
    );

    for (const batch of linkedBatches) {
      const newContestId = await recreateContestForBatch(db, batch.id, batch);
      console.log(`    Recreated PFT contest ${newContestId} for batch ${batch.id} (Batch ${batch.batchNumber})`);
    }
  }

  console.log('\nDone. Ghost contests removed; linked PFT batches now point at proper PFT contest docs.');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
