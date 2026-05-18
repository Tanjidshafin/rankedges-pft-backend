/**
 * Admin SDK notifications (mirrors src/services/notificationService.ts).
 */

const DEFAULT_PREFERENCES = {
  enabled: true,
  achievements: true,
};

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
    if (preferences.enabled === false) return false;
    if (notificationType === 'achievement_unlocked' && preferences.achievements === false) {
      return false;
    }
    return true;
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
