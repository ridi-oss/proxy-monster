import { renderToStaticMarkup } from 'react-dom/server'
import { NextIntlClientProvider } from 'next-intl'
import { expect, it } from 'vitest'
import en from '../../../messages/en/connect.json'
import { ConnectAgent } from './connect-agent'

const info = {
  instanceName: 'hr-pmon',
  instanceDescription: 'HR and payroll data',
  mcpUrl: 'https://hr-pmon.example.com/mcp',
  installName: 'pmon-hr-pmon',
}

function render(): string {
  return renderToStaticMarkup(
    <NextIntlClientProvider locale="en" messages={{ Connect: en }}>
      <ConnectAgent info={info} />
    </NextIntlClientProvider>,
  )
}

it('renders one paste-to-agent block from the API values and the unsupported note', () => {
  const html = render()
  expect(html).toContain('Paste this to your agent')
  expect(html).toContain('named pmon-hr-pmon with the URL https://hr-pmon.example.com/mcp')
  expect(html).toContain('/mcp, pick pmon-hr-pmon, and choose Authenticate')
  expect(html).toContain('claude.ai, Claude Desktop, and ChatGPT')
  expect(html).not.toContain('claude mcp add')
  expect(html).not.toContain('codex mcp add')
})

it('shows the description on the page but leaves it out of the pasted text', () => {
  const html = render()
  const pasted = html.slice(html.indexOf('<pre'), html.indexOf('</pre>'))
  expect(html).toContain('HR and payroll data')
  expect(pasted).toContain('pmon-hr-pmon')
  expect(pasted).not.toContain('HR and payroll data')
})

it('puts no credential in any block', () => {
  expect(render()).not.toMatch(/bearer|token=|password=|--header|-H /i)
})
