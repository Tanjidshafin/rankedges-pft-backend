/**
 * Privileged contest operations (Admin SDK) — used by authenticated clients when
 * Firestore rules block cross-user reads/writes.
 */

const { FieldValue } = require('firebase-admin/firestore');
const { tryAutoStartContest } = require('./contestLifecycle');
const { startContestAdmin } = require('./contestStart');
const { normalizeContestStatus } = require('./contestStart');

function shuffleArray(items) {
  const cloned = [...items];
  for (let i = cloned.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [cloned[i], cloned[j]] = [cloned[j], cloned[i]];
  }
  return cloned;
}

const INACTIVE_PARTICIPATION_STATUSES = new Set(['withdrawn', 'disqualified', 'terminated', 'completed']);

function isActiveParticipation(participation) {
  const status = participation.participant_status || 'active';
  return status === 'active';
}

async function assertContestCreatorOrAdmin(db, contestId, uid, userSnap) {
  const contestSnap = await db.collection('contests').doc(contestId).get();
  if (!contestSnap.exists) {
    throw Object.assign(new Error('Contest not found.'), { status: 404 });
  }
  const contest = contestSnap.data();
  const isAdmin = userSnap.exists && userSnap.data().role === 'admin';
  const isCreator = contest.creator_id === uid;
  if (!isAdmin && !isCreator) {
    throw Object.assign(new Error('Only the contest creator or an admin can perform this action.'), { status: 403 });
  }
  return { contest: { id: contestSnap.id, ...contest }, isAdmin };
}

async function listContestParticipations(db, contestId, uid, userSnap) {
  await assertContestCreatorOrAdmin(db, contestId, uid, userSnap);
  const snap = await db.collection('contestParticipations').where('contest_id', '==', contestId).get();
  return snap.docs.map((d) => ({ id: d.id, ...d.data() }));
}

async function assignRandomTeams(db, contestId, roomId, uid, userSnap) {
  const { contest } = await assertContestCreatorOrAdmin(db, contestId, uid, userSnap);
  if (contest.type !== '3v3' || contest.team_assignment_mode !== 'random') {
    return { ok: true, skipped: true };
  }

  const membersSnap = await db.collection('contestRoomMembers').where('room_id', '==', roomId).get();
  const members = membersSnap.docs.map((d) => ({ id: d.id, ...d.data() }));
  if (members.length < 6) {
    return { ok: true, skipped: true };
  }

  const unassigned = members.filter((m) => !m.team);
  if (unassigned.length === 0) {
    return { ok: true, skipped: true };
  }

  const batch = db.batch();
  shuffleArray(members).forEach((member, index) => {
    const team = index < 3 ? 'A' : 'B';
    batch.update(db.collection('contestRoomMembers').doc(member.id), {
      team,
      updatedAt: FieldValue.serverTimestamp(),
    });
  });
  await batch.commit();
  return { ok: true };
}

async function tryAutoStartContestPrivileged(db, contestId, notifications) {
  const started = await tryAutoStartContest(
    db,
    contestId,
    async (id) => {
      const result = await startContestAdmin(db, id);
      return { participantCount: result.participantCount };
    },
    notifications,
  );
  return { started: Boolean(started) };
}

async function lookupUserByEmail(db, email) {
  const normalized = String(email || '').trim().toLowerCase();
  if (!normalized) {
    return { uid: null, email: '' };
  }
  const snap = await db.collection('users').where('email', '==', normalized).limit(1).get();
  if (snap.empty) {
    return { uid: null, email: normalized };
  }
  const doc = snap.docs[0];
  return { uid: doc.id, email: normalized };
}

async function reopenContestRoomIfNeeded(db, roomId) {
  const roomSnap = await db.collection('contestRooms').doc(roomId).get();
  if (!roomSnap.exists) return;
  const room = roomSnap.data();
  if (room.capacity == null) return;
  const membersSnap = await db.collection('contestRoomMembers').where('room_id', '==', roomId).get();
  if (membersSnap.size < room.capacity && room.status === 'full') {
    await db.collection('contestRooms').doc(roomId).set({ status: 'open', updatedAt: FieldValue.serverTimestamp() }, { merge: true });
  }
}

/**
 * Remove a participant or their leaderboard rows (regular contests only).
 * @param {import('firebase-admin/firestore').Firestore} db
 * @param {string} contestId
 * @param {string} targetUserId
 * @param {string} actorUid
 * @param {import('firebase-admin/firestore').DocumentSnapshot} userSnap
 * @param {{ mode?: 'full' | 'leaderboard_only', reason?: string, updateContestRankingsServer?: (id: string) => Promise<void> }} options
 */
async function removeContestParticipantPrivileged(db, contestId, targetUserId, actorUid, userSnap, options = {}) {
  const { mode = 'full', reason = '', updateContestRankingsServer } = options;
  const { contest } = await assertContestCreatorOrAdmin(db, contestId, actorUid, userSnap);

  if (contest.type === 'pft') {
    throw Object.assign(new Error('PFT batches do not support participant removal.'), { status: 400 });
  }
  const normalizedStatus = normalizeContestStatus(contest.status);
  if (normalizedStatus === 'completed') {
    throw Object.assign(new Error('Cannot modify participants after the contest has completed.'), { status: 400 });
  }
  if (contest.rankings_locked) {
    throw Object.assign(new Error('Rankings are locked for this contest.'), { status: 400 });
  }

  const [participationsSnap, leaderboardSnap] = await Promise.all([
    db.collection('contestParticipations').where('contest_id', '==', contestId).where('user_id', '==', targetUserId).get(),
    db.collection('leaderboard').where('contest_id', '==', contestId).where('user_id', '==', targetUserId).get(),
  ]);

  const participations = participationsSnap.docs.map((d) => ({ id: d.id, ...d.data() }));
  const activeParticipations = participations.filter(isActiveParticipation);

  const lbBatch = db.batch();
  leaderboardSnap.docs.forEach((docSnap) => lbBatch.delete(docSnap.ref));
  await lbBatch.commit();

  if (mode === 'leaderboard_only') {
    if (leaderboardSnap.empty && activeParticipations.length === 0) {
      throw Object.assign(new Error('No leaderboard entry or active participation found for this user.'), { status: 404 });
    }
    if (typeof updateContestRankingsServer === 'function') {
      await updateContestRankingsServer(contestId);
    }
    return { ok: true, mode };
  }

  if (activeParticipations.length === 0 && leaderboardSnap.empty) {
    throw Object.assign(new Error('No active participation found for this user.'), { status: 404 });
  }

  const now = new Date().toISOString();
  const partBatch = db.batch();
  participations.forEach((p) => {
    if (!isActiveParticipation(p)) return;
    partBatch.update(db.collection('contestParticipations').doc(p.id), {
      participant_status: 'withdrawn',
      withdrawn_at: now,
      withdrawn_reason: reason.trim() || 'Removed by administrator',
      withdrawn_by: 'admin',
      room_id: FieldValue.delete(),
      room_type: FieldValue.delete(),
      updatedAt: FieldValue.serverTimestamp(),
    });
  });
  await partBatch.commit();

  const roomMembersSnap = await db
    .collection('contestRoomMembers')
    .where('contest_id', '==', contestId)
    .where('user_id', '==', targetUserId)
    .get();
  for (const memberDoc of roomMembersSnap.docs) {
    const roomId = memberDoc.data().room_id;
    await memberDoc.ref.delete();
    if (roomId) {
      await reopenContestRoomIfNeeded(db, roomId);
    }
  }

  if (activeParticipations.length > 0) {
    const nextParticipants = Math.max(0, Number(contest.participants || 0) - 1);
    await db.collection('contests').doc(contestId).set(
      { participants: nextParticipants, updatedAt: FieldValue.serverTimestamp() },
      { merge: true },
    );
  }

  if (typeof updateContestRankingsServer === 'function') {
    await updateContestRankingsServer(contestId);
  }

  if (options.notifications) {
    const contestName = contest.name || 'Contest';
    const link = `/contests/${contestId}`;
    if (mode === 'leaderboard_only') {
      await options.notifications.createNotification({
        userId: targetUserId,
        type: 'contest_leaderboard_removed',
        title: `Leaderboard update: ${contestName}`,
        message: reason.trim() || 'Removed from leaderboard by an administrator.',
        link,
      });
    } else {
      await options.notifications.createNotification({
        userId: targetUserId,
        type: 'contest_withdrawn',
        title: `Removed from contest: ${contestName}`,
        message: reason.trim() || 'An administrator removed you from this contest.',
        link,
      });
    }
  }

  return { ok: true, mode };
}

module.exports = {
  listContestParticipations,
  assignRandomTeams,
  tryAutoStartContestPrivileged,
  lookupUserByEmail,
  assertContestCreatorOrAdmin,
  removeContestParticipantPrivileged,
};
