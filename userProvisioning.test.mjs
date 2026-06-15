import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeEmail,
  NOT_ALLOWED_MESSAGE,
} from '../backend/userProvisioning.js';

describe('userProvisioning', () => {
  it('normalizes email to lowercase', () => {
    assert.equal(normalizeEmail('  John@Example.COM '), 'john@example.com');
  });

  it('exports not-allowed message for unprovisioned sign-in', () => {
    assert.match(NOT_ALLOWED_MESSAGE, /not allowed to create an account/i);
  });
});
