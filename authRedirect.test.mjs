import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  AUTH_REDIRECT_QUERY_KEY,
  buildAuthUrl,
  resolvePostAuthPath,
  sanitizeAuthRedirectPath,
  withAuthRedirect,
} from '../src/lib/authRedirect.ts';

describe('authRedirect', () => {
  it('sanitizes valid internal paths', () => {
    assert.equal(sanitizeAuthRedirectPath('/contests/abc'), '/contests/abc');
    assert.equal(sanitizeAuthRedirectPath('%2Fcontests%2Fabc'), '/contests/abc');
    assert.equal(sanitizeAuthRedirectPath('/contests/abc?tab=live'), '/contests/abc?tab=live');
  });

  it('rejects open redirects and auth loop paths', () => {
    assert.equal(sanitizeAuthRedirectPath('//evil.com'), null);
    assert.equal(sanitizeAuthRedirectPath('https://evil.com'), null);
    assert.equal(sanitizeAuthRedirectPath('/auth'), null);
    assert.equal(sanitizeAuthRedirectPath('/register'), null);
    assert.equal(sanitizeAuthRedirectPath('/auth?redirect=%2F'), null);
  });

  it('builds auth urls with encoded redirect', () => {
    const url = buildAuthUrl('/auth', { pathname: '/contests/1', search: '?x=1', hash: '' });
    assert.equal(url, `/auth?${AUTH_REDIRECT_QUERY_KEY}=${encodeURIComponent('/contests/1?x=1')}`);
  });

  it('preserves redirect when switching auth pages', () => {
    const params = new URLSearchParams();
    params.set(AUTH_REDIRECT_QUERY_KEY, '/dashboard');
    assert.equal(
      withAuthRedirect('/register', params),
      `/register?${AUTH_REDIRECT_QUERY_KEY}=${encodeURIComponent('/dashboard')}`,
    );
  });

  it('resolves post-auth path with dashboard fallback', () => {
    const params = new URLSearchParams();
    params.set(AUTH_REDIRECT_QUERY_KEY, encodeURIComponent('/leaderboard'));
    assert.equal(resolvePostAuthPath(params), '/leaderboard');
    assert.equal(resolvePostAuthPath(new URLSearchParams()), '/dashboard');
  });
});
