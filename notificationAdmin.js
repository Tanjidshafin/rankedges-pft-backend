/**
 * Admin SDK notifications (mirrors src/utils/notificationPreferenceMap.ts).
 * Keep preference keys in sync with the client.
 */

const DEFAULT_PREFERENCES = {
  enabled: true,
  articles: true,
  contests: true,
  pushEnabled: false,
  rankChanges: true,
  supportMessages: true,
  contestPayments: true,
  contestJoinRequests: true,
  contestInvites: true,
  contestReviews: true,
  reviews: true,
  reviewReplies: true,
  reportStatus: true,
  scamAlerts: true,
  brokerApplications: true,
  brokerDocuments: true,
  brokerPayments: true,
  brokerAdded: true,
  alertSubmitted: true,
  supportTickets: true,
  contestCompleted: true,
  prizeWon: true,
  prizeDistributed: true,
  prizeProofUploaded: true,
  prizeVerified: true,
  achievements: true,
};

/** @type {Record<string, keyof typeof DEFAULT_PREFERENCES>} */
const notificationTypeToPreferenceKey = {
  article: 'articles',
  contest: 'contests',
  contest_payment: 'contestPayments',
  contest_review: 'contestReviews',
  contest_join_request: 'contestJoinRequests',
  contest_invite: 'contestInvites',
  review: 'reviews',
  review_reply: 'reviewReplies',
  report_status: 'reportStatus',
  scam_alert_status: 'scamAlerts',
  broker_added: 'brokerAdded',
  alert_submitted: 'alertSubmitted',
  rank_change: 'rankChanges',
  support_ticket: 'supportTickets',
  support_message: 'supportMessages',
  broker_application: 'brokerApplications',
  broker_document: 'brokerDocuments',
  broker_payment: 'brokerPayments',
  contest_completed: 'contestCompleted',
  prize_won: 'prizeWon',
  prize_distributed: 'prizeDistributed',
  prize_proof_uploaded: 'prizeProofUploaded',
  prize_verified: 'prizeVerified',
  achievement_unlocked: 'achievements',
};

/**
 * @param {typeof DEFAULT_PREFERENCES} preferences
 * @param {string} notificationType
 */
function shouldReceiveNotificationType(preferences, notificationType) {
  if (preferences.enabled === false) {
    return false;
  }

  const preferenceKey = notificationTypeToPreferenceKey[notificationType];
  if (preferenceKey === undefined) {
    return true;
  }

  return preferences[preferenceKey] !== false;
}

/**
 * @param {import('firebase-admin').firestore.Firestore} db
 */
function createNotificationAdmin(db, collections) {
  const { users: usersCol, notifications: notificationsCol } = collections;

  async function getNotificationPreferences(userId) {
    try {
      const prefSnap = await db
        .collection(usersCol)
        .doc(userId)
        .collection('settings')
        .doc('notifications')
        .get();
      if (prefSnap.exists) {
        return { ...DEFAULT_PREFERENCES, ...prefSnap.data() };
      }
      return { ...DEFAULT_PREFERENCES };
    } catch {
      return { ...DEFAULT_PREFERENCES };
    }
  }

  async function shouldSendNotification(userId, notificationType) {
    const preferences = await getNotificationPreferences(userId);
    return shouldReceiveNotificationType(preferences, notificationType);
  }

  /**
   * @param {{ userId: string, type: string, title: string, message: string, link?: string }} params
   * @returns {Promise<string|null>} notification doc id or null if skipped
   */
  async function createNotification(params) {
    const shouldSend = await shouldSendNotification(params.userId, params.type);
    if (!shouldSend) return null;

    const { FieldValue } = require('firebase-admin/firestore');
    const docRef = await db.collection(notificationsCol).add({
      userId: params.userId,
      type: params.type,
      title: params.title,
      message: params.message,
      link: params.link || null,
      seen: false,
      createdAt: FieldValue.serverTimestamp(),
    });
    return docRef.id;
  }

  return {
    createNotification,
    shouldSendNotification,
  };
}

module.exports = {
  createNotificationAdmin,
};
