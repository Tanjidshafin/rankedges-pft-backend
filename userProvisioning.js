/**
 * Admin-provisioned user creation and sign-in verification.
 */

const NOT_ALLOWED_MESSAGE =
  'You are not allowed to create an account on this platform. Contact an administrator.';

const UID_MISMATCH_MESSAGE =
  'This email is registered for email and password sign-in. Please use your email and password to log in.';

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function asTrimmedString(value) {
  return String(value || '').trim();
}

function validateCreateUserInput(input) {
  const name = asTrimmedString(input.name);
  const country = asTrimmedString(input.country);
  const phone = asTrimmedString(input.phone);
  const email = normalizeEmail(input.email);
  const password = String(input.password || '');
  const phoneCountry = asTrimmedString(input.phoneCountry).toUpperCase();

  if (!name) {
    const error = new Error('Full name is required.');
    error.status = 400;
    throw error;
  }
  if (!country) {
    const error = new Error('Country is required.');
    error.status = 400;
    throw error;
  }
  if (!phone) {
    const error = new Error('Phone number is required.');
    error.status = 400;
    throw error;
  }
  if (!email || !email.includes('@')) {
    const error = new Error('A valid email address is required.');
    error.status = 400;
    throw error;
  }
  if (!password || password.length < 6) {
    const error = new Error('Password must be at least 6 characters.');
    error.status = 400;
    throw error;
  }

  return { name, country, phone, email, password, phoneCountry };
}

async function provisionedUserByEmail(db, email, usersCollection = 'users') {
  const normalized = normalizeEmail(email);
  if (!normalized) {
    return null;
  }
  const snap = await db.collection(usersCollection).where('email', '==', normalized).limit(1).get();
  if (snap.empty) {
    return null;
  }
  const doc = snap.docs[0];
  return { uid: doc.id, data: doc.data() };
}

async function createProvisionedUser(admin, db, input, adminUid, options = {}) {
  const { usersCollection = 'users', FieldValue } = options;
  const { name, country, phone, email, password, phoneCountry } = validateCreateUserInput(input);

  const existing = await provisionedUserByEmail(db, email, usersCollection);
  if (existing) {
    const error = new Error('A user with this email already exists.');
    error.status = 409;
    throw error;
  }

  try {
    await admin.auth().getUserByEmail(email);
    const error = new Error('A user with this email already exists in authentication.');
    error.status = 409;
    throw error;
  } catch (authError) {
    if (authError.code !== 'auth/user-not-found') {
      if (authError.status) throw authError;
      const error = new Error(authError.message || 'Failed to verify email availability.');
      error.status = 500;
      throw error;
    }
  }

  let authUser;
  try {
    authUser = await admin.auth().createUser({
      email,
      password,
      displayName: name,
      emailVerified: false,
    });
  } catch (createError) {
    const error = new Error(createError.message || 'Failed to create authentication user.');
    error.status = createError.code === 'auth/email-already-exists' ? 409 : 500;
    throw error;
  }

  const profile = {
    uid: authUser.uid,
    email,
    name,
    country,
    phone,
    ...(phoneCountry ? { phoneCountry } : {}),
    role: 'trader',
    roleConfirmed: true,
    createdBy: adminUid,
    createdAt: FieldValue.serverTimestamp(),
  };

  try {
    await db.collection(usersCollection).doc(authUser.uid).set(profile);
  } catch (firestoreError) {
    try {
      await admin.auth().deleteUser(authUser.uid);
    } catch {
      // Best-effort rollback.
    }
    const error = new Error(firestoreError.message || 'Failed to create user profile.');
    error.status = 500;
    throw error;
  }

  return { uid: authUser.uid, email };
}

async function deleteProvisionedUser(admin, db, targetUserId, actorUid, options = {}) {
  const { usersCollection = 'users', actorProfile = null } = options;
  const userId = String(targetUserId || '').trim();
  const actorId = String(actorUid || '').trim();

  if (!userId) {
    const error = new Error('User ID is required.');
    error.status = 400;
    throw error;
  }

  if (userId === actorId) {
    const error = new Error('You cannot delete your own account.');
    error.status = 400;
    throw error;
  }

  const userSnap = await db.collection(usersCollection).doc(userId).get();
  if (!userSnap.exists) {
    const error = new Error('User not found.');
    error.status = 404;
    throw error;
  }

  const userData = userSnap.data() || {};
  const targetIsSuperAdmin = userData.role === 'admin' && userData.adminTier === 'super';
  const actorIsSuperAdmin = actorProfile?.role === 'admin' && actorProfile?.adminTier === 'super';

  if (targetIsSuperAdmin && !actorIsSuperAdmin) {
    const error = new Error('Only a super-admin can delete another super-admin.');
    error.status = 403;
    throw error;
  }

  if (targetIsSuperAdmin) {
    const superAdminsSnap = await db
      .collection(usersCollection)
      .where('role', '==', 'admin')
      .where('adminTier', '==', 'super')
      .get();
    if (superAdminsSnap.size <= 1) {
      const error = new Error('Cannot delete the last super-admin account.');
      error.status = 400;
      throw error;
    }
  }

  await db.collection(usersCollection).doc(userId).delete();

  try {
    await admin.auth().deleteUser(userId);
  } catch (authError) {
    if (authError.code !== 'auth/user-not-found') {
      const error = new Error(authError.message || 'Failed to delete authentication user.');
      error.status = 500;
      throw error;
    }
  }

  return { uid: userId, deleted: true };
}

async function verifyProvisionedSession(admin, db, tokenUser, options = {}) {
  const { usersCollection = 'users' } = options;
  const authUid = String(tokenUser?.uid || '').trim();
  const email = normalizeEmail(tokenUser?.email);

  if (!authUid || !email) {
    const error = new Error(NOT_ALLOWED_MESSAGE);
    error.status = 403;
    throw error;
  }

  const provisioned = await provisionedUserByEmail(db, email, usersCollection);

  const rejectSession = async (message) => {
    try {
      await admin.auth().deleteUser(authUid);
    } catch (deleteError) {
      if (deleteError.code !== 'auth/user-not-found') {
        console.warn('[verifyProvisionedSession] Failed to delete rogue auth user:', deleteError.message);
      }
    }
    const error = new Error(message);
    error.status = 403;
    throw error;
  };

  if (!provisioned) {
    await rejectSession(NOT_ALLOWED_MESSAGE);
  }

  if (provisioned.uid !== authUid) {
    await rejectSession(UID_MISMATCH_MESSAGE);
  }

  return {
    uid: provisioned.uid,
    email,
    provisioned: true,
  };
}

module.exports = {
  NOT_ALLOWED_MESSAGE,
  UID_MISMATCH_MESSAGE,
  normalizeEmail,
  provisionedUserByEmail,
  createProvisionedUser,
  deleteProvisionedUser,
  verifyProvisionedSession,
};
