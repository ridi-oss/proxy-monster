// pmon-auto-approver-agent: cp-go starts one per review and speaks newline-delimited JSON over stdio.
//   cp-go -> agent  {"type":"review", ...ReviewInput}            first line
//   agent -> cp-go  {"type":"tool","id":"1","name":...,"args":...}
//   cp-go -> agent  {"type":"tool_result","id":"1","result":...} or {..., "error":"..."}
//   agent -> cp-go  {"type":"verdict", ...Verdict}               last line; then the process exits
import { builtinModels } from '@earendil-works/pi-ai/providers/all';
import { createInterface } from 'node:readline';
import { review, type ReviewInput } from './review.ts';

const send = (message: unknown) => process.stdout.write(JSON.stringify(message) + '\n');
// process.exit drops whatever stdout has not flushed, which would cut a long verdict short.
const sendLast = (message: unknown) =>
  new Promise<void>((resolve) => process.stdout.write(JSON.stringify(message) + '\n', () => resolve()));

const lines = createInterface({ input: process.stdin })[Symbol.asyncIterator]();
const next = async () => {
  const line = await lines.next();
  if (line.done) throw new Error('cp-go closed stdin');
  return JSON.parse(line.value);
};

let toolId = 0;
const callTool = async (name: string, args: unknown) => {
  const id = String(++toolId);
  send({ type: 'tool', id, name, args });
  const reply = await next();
  if (reply.type !== 'tool_result' || reply.id !== id) throw new Error('unexpected reply from cp-go');
  if (reply.error) throw new Error(reply.error);
  return reply.result;
};

try {
  const input = (await next()) as ReviewInput & { type: string };
  if (input.type !== 'review') throw new Error('the first message must be a review');
  await sendLast({ type: 'verdict', ...(await review(input, builtinModels(), callTool)) });
} catch (error) {
  await sendLast({ type: 'error', message: error instanceof Error ? error.message : String(error) });
}
process.exit(0);
