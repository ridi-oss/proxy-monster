import { renderToStaticMarkup } from 'react-dom/server'
import { expect, it } from 'vitest'
import { Linkified } from './request-timeline'

it('links each http(s) URL in a comment, leaving trailing punctuation and other schemes as text', () => {
  const html = renderToStaticMarkup(
    <p>
      <Linkified text="see https://x.test/a?b=1&c=2. or (http://y.test/p) not javascript:alert(1)" />
    </p>,
  )
  expect(html).toBe(
    '<p>see <a href="https://x.test/a?b=1&amp;c=2" target="_blank" rel="noopener noreferrer" class="underline">https://x.test/a?b=1&amp;c=2</a>. ' +
      'or (<a href="http://y.test/p" target="_blank" rel="noopener noreferrer" class="underline">http://y.test/p</a>) not javascript:alert(1)</p>',
  )
})
