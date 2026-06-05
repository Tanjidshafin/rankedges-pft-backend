/**
 * Verify MetaStats remapping for an account by login.
 * Reads stored snapshot raw metrics and compares old vs new daily/monthly gain mapping.
 *
 * Usage: node scripts/verify-metastats-remap.js [login] [--apply]
 */
require('dotenv').config();
const admin = require('firebase-admin');
const {
  mapMetaStatsToAccountMetrics,
  unwrapMetaStatsMetricsBody,
  ratioToPercentDisplay,
} = require('../metaApiMetaStats');

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
  admin.initializeApp();
}

function oldDailyGain(raw) {
  return ratioToPercentDisplay(raw.dailyGain);
}

function oldMonthlyGain(raw) {
  return ratioToPercentDisplay(raw.monthlyGain);
}

async function main() {
  const args = process.argv.slice(2);
  const login = args.find((a) => !a.startsWith('--')) || '169955';
  const apply = args.includes('--apply');

  initializeFirebaseAdmin();
  const db = admin.firestore();

  const accountsSnap = await db
    .collection('tradingAccounts')
    .where('login', '==', String(login))
    .limit(5)
    .get();

  if (accountsSnap.empty) {
    console.error(`No tradingAccounts found for login ${login}`);
    process.exit(1);
  }

  for (const accountDoc of accountsSnap.docs) {
    const account = accountDoc.data();
    const accountId = accountDoc.id;
    console.log(`\n=== Account ${accountId} (login ${account.login}) ===`);
    console.log('Stored metaapi_daily_gain:', account.metaapi_daily_gain);
    console.log('Stored metaapi_monthly_gain:', account.metaapi_monthly_gain);
    console.log('Stored profit:', account.profit);
    console.log('Stored metaapi_deposits:', account.metaapi_deposits);

    const snapshotDoc = await db.collection('metaApiAccountSnapshots').doc(accountId).get();
    if (!snapshotDoc.exists) {
      console.warn('No metaApiAccountSnapshots doc — run a sync first.');
      continue;
    }

    const snapshot = snapshotDoc.data();
    const rawBody = snapshot.meta_stats_metrics_raw;
    const raw = unwrapMetaStatsMetricsBody(rawBody);
    if (!raw) {
      console.warn('Snapshot missing meta_stats_metrics_raw.metrics');
      continue;
    }

    console.log('\nRaw MetaStats API values:');
    console.log('  dailyGain:', raw.dailyGain);
    console.log('  monthlyGain:', raw.monthlyGain);

    const latestGrowth = Array.isArray(raw.dailyGrowth)
      ? [...raw.dailyGrowth].sort((a, b) => String(b.date).localeCompare(String(a.date)))[0]
      : null;
    if (latestGrowth) {
      console.log('  latest dailyGrowth date:', latestGrowth.date);
      console.log('  latest dailyGrowth totalGains:', latestGrowth.totalGains);
      console.log('  latest dailyGrowth gains:', latestGrowth.gains);
    }

    const remapped = mapMetaStatsToAccountMetrics({ metrics: raw });
    console.log('\nMapping comparison:');
    console.log('  OLD daily gain (ratioToPercentDisplay):', oldDailyGain(raw));
    console.log('  NEW daily gain (compoundRateToPercent):', remapped.metaapi_daily_gain);
    console.log('  OLD monthly gain:', oldMonthlyGain(raw));
    console.log('  NEW monthly gain:', remapped.metaapi_monthly_gain);

    if (apply) {
      await db.collection('tradingAccounts').doc(accountId).set(
        {
          metaapi_daily_gain: remapped.metaapi_daily_gain,
          metaapi_monthly_gain: remapped.metaapi_monthly_gain,
          metaapi_abs_gain: remapped.metaapi_abs_gain,
          gain: remapped.gain,
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        },
        { merge: true },
      );
      console.log('\nApplied remapped daily/monthly gain to tradingAccounts.');
    }
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
