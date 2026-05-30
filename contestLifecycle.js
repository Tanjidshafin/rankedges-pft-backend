/**
 * Contest lifecycle cron — auto-start published contests by schedule or participant threshold.
 */

const CONTEST_LIFECYCLE_INTERVAL_MS = 5 * 60 * 1000;

function normalizeContestStatus(status) {
  const legacy = { upcoming: 'published', live: 'ongoing', ended: 'completed' };
  return legacy[status] || status;
}

function includesMinParticipants(mode) {
  return mode === 'min_participants' || mode === 'whichever_first';
}

function shouldStartByParticipantCount(contest, count) {
  if (normalizeContestStatus(contest.status) !== 'published') return false;
  if (!includesMinParticipants(contest.start_mode)) return false;
  const min = contest.min_participants_to_start;
  if (!min || min < 1) return false;
  return count >= min;
}

function shouldStartBySchedule(contest) {
  if (normalizeContestStatus(contest.status) !== 'published') return false;
  if (contest.start_mode === 'min_participants') return false;
  const startAt = new Date(contest.start_at);
  return !Number.isNaN(startAt.getTime()) && startAt.getTime() <= Date.now();
}

function collectNotifyUserIds(participations, creatorId) {
  const ids = participations.map((p) => p.user_id).filter(Boolean);
  if (creatorId) ids.push(creatorId);
  return [...new Set(ids)];
}

/**
 * @param {import('firebase-admin').firestore.Firestore} db
 * @param {string} contestId
 * @param {() => Promise<{ participantCount: number, contest: object }>} startContestFn
 * @param {{ createBroadcastNotification: Function, createNotification?: Function }} notifications
 */
async function tryAutoStartContest(db, contestId, startContestFn, notifications) {
  const contestSnap = await db.collection('contests').doc(contestId).get();
  if (!contestSnap.exists) return false;
  const contest = { id: contestSnap.id, ...contestSnap.data() };

  const partsSnap = await db.collection('contestParticipations').where('contest_id', '==', contestId).get();
  const participations = partsSnap.docs.map((d) => ({ id: d.id, ...d.data() }));
  const count = participations.length;

  const byMin = shouldStartByParticipantCount(contest, count);
  const bySchedule = shouldStartBySchedule(contest);

  if (!byMin && !bySchedule) {
    const min = contest.min_participants_to_start;
    if (
      includesMinParticipants(contest.start_mode) &&
      min &&
      min > 0 &&
      count >= Math.max(1, Math.floor(min * 0.8)) &&
      count < min &&
      !contest.participant_start_announced
    ) {
      const userIds = collectNotifyUserIds(participations, contest.creator_id);
      if (userIds.length > 0 && notifications?.createBroadcastNotification) {
        await notifications.createBroadcastNotification(
          userIds,
          'contest_starting_soon',
          `Almost ready: ${contest.name || 'Contest'}`,
          `${count} of ${min} participants joined. The contest starts automatically when the minimum is reached.`,
          `/contests/${contestId}`,
        );
      }
      await db.collection('contests').doc(contestId).update({
        participant_start_announced: true,
      });
    }
    return false;
  }

  const { participantCount } = await startContestFn(contestId);
  const userIds = collectNotifyUserIds(participations, contest.creator_id);
  if (userIds.length > 0 && notifications?.createBroadcastNotification) {
    const reason = byMin ? 'min_participants' : 'scheduled';
    const message =
      reason === 'min_participants'
        ? `"${contest.name || 'Contest'}" reached ${participantCount} participants and is now live!`
        : `"${contest.name || 'Contest'}" has started on schedule with ${participantCount} participants.`;
    await notifications.createBroadcastNotification(
      userIds,
      'contest_started',
      `Contest is live: ${contest.name || 'Contest'}`,
      message,
      `/contests/${contestId}`,
    );
  }

  return true;
}

async function runContestLifecycleCheck(db, startContestFn, notifications) {
  const snap = await db.collection('contests').get();
  const result = { started: 0, skipped: 0, errors: [] };

  for (const docSnap of snap.docs) {
    const contest = { id: docSnap.id, ...docSnap.data() };
    if (normalizeContestStatus(contest.status) !== 'published') {
      result.skipped++;
      continue;
    }
    try {
      const started = await tryAutoStartContest(db, docSnap.id, startContestFn, notifications);
      if (started) result.started++;
      else result.skipped++;
    } catch (err) {
      result.skipped++;
      result.errors.push(`${contest.name || docSnap.id}: ${err.message || err}`);
    }
  }

  return result;
}

function scheduleContestLifecycleCron(db, startContestFn, notifications, logFn = console.log) {
  if (process.env.CONTEST_LIFECYCLE_CRON_ENABLED !== 'true') {
    logFn('[contest-lifecycle] Cron disabled (set CONTEST_LIFECYCLE_CRON_ENABLED=true)');
    return null;
  }

  logFn('[contest-lifecycle] Scheduling every 5 minutes');

  const tick = async () => {
    try {
      const result = await runContestLifecycleCheck(db, startContestFn, notifications);
      logFn(
        `[contest-lifecycle] started=${result.started} skipped=${result.skipped} errors=${result.errors.length}`,
      );
    } catch (err) {
      logFn('[contest-lifecycle] Error:', err);
    }
  };

  tick();
  return setInterval(tick, CONTEST_LIFECYCLE_INTERVAL_MS);
}

module.exports = {
  runContestLifecycleCheck,
  scheduleContestLifecycleCron,
  tryAutoStartContest,
};
