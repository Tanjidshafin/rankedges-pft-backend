const { describe, it, mock } = require('node:test');
const assert = require('node:assert/strict');
const { notifyContestRankChanges } = require('./contestRankNotifications');

describe('notifyContestRankChanges', () => {
  const contest = { id: 'c1', name: 'Spring Cup', slug: 'spring-cup' };

  it('notifies users who move into top 3', async () => {
    const created = [];
    const notificationAdmin = {
      createNotification: mock.fn(async (params) => {
        created.push(params);
        return 'n1';
      }),
    };

    const previousRanks = new Map([['u1', 5]]);
    const afterEntries = [{ user_id: 'u1', rank: 2, participant_status: 'active' }];

    await notifyContestRankChanges(notificationAdmin, contest, previousRanks, afterEntries);

    assert.equal(notificationAdmin.createNotification.mock.calls.length, 1);
    assert.deepEqual(created[0], {
      userId: 'u1',
      type: 'rank_change',
      title: 'You moved up to Rank #2!',
      message: 'Congratulations! You\'re now ranked #2 in "Spring Cup". Keep up the great trading!',
      link: '/contests/spring-cup',
    });
  });

  it('skips when rank did not improve within top 3', async () => {
    const notificationAdmin = {
      createNotification: mock.fn(async () => 'n1'),
    };
    const previousRanks = new Map([['u1', 2]]);
    const afterEntries = [{ user_id: 'u1', rank: 3, participant_status: 'active' }];

    await notifyContestRankChanges(notificationAdmin, contest, previousRanks, afterEntries);

    assert.equal(notificationAdmin.createNotification.mock.calls.length, 0);
  });
});
