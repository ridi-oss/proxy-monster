import { renderToStaticMarkup } from 'react-dom/server';
import { expect, it } from 'vitest';
import { PersonName } from './person-name';

const text = (el: React.ReactElement) => renderToStaticMarkup(el).replace(/<[^>]+>/g, '');

it('shows the directory name with the email, a Slack-only author by Slack name, and the bare principal otherwise', () => {
  const people = { 'a@x.test': { name: 'Alice Kim', email: 'a@x.test' }, 'b@x.test': { email: 'b@x.test' } };
  expect(text(<PersonName principal="a@x.test" people={people} />)).toBe('Alice Kim a@x.test');
  expect(text(<PersonName principal="b@x.test" people={people} />)).toBe('b@x.test');
  expect(text(<PersonName principal="slack:Pat" people={people} />)).toBe('Pat');
});
