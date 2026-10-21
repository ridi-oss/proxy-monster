import { expect, it } from 'vitest';
import { ccChoice } from './request-timeline';

const ashlee = { principal: 'ashlee@x.test', email: 'ashlee@x.test', name: 'Ashlee Park' };
const lee = { principal: 'lee@x.test', email: 'lee@x.test', name: 'Lee Kim' };

it('adds the highlighted suggestion, or an exact principal or email over it', () => {
  const found = { q: 'lee', rows: [ashlee, lee] };
  expect(ccChoice('lee', found, [], 0).chosen).toBe('ashlee@x.test');
  expect(ccChoice('lee@x.test', { ...found, q: 'lee@x.test' }, [], 0).chosen).toBe('lee@x.test');
});

it('ignores suggestions found for an earlier query', () => {
  const r = ccChoice('bob@x.test', { q: 'lee', rows: [ashlee, lee] }, [], 0);
  expect(r.options).toEqual([]);
  expect(r.chosen).toBe('bob@x.test');
});

it('skips people already on the request', () => {
  expect(ccChoice('lee', { q: 'lee', rows: [ashlee, lee] }, ['ashlee@x.test'], 0).chosen).toBe('lee@x.test');
});
