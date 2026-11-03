import { describe, expect, it } from 'vitest';
import { formatConditions, parseConditions } from './conditions';

describe('workload binding conditions', () => {
  it('parses one claim per line with comma-separated values', () => {
    expect(
      parseConditions('principal_tags.kubernetes-namespace=batch\n\n aws_account = 111122223333 , 444455556666 \n'),
    ).toEqual({
      'principal_tags.kubernetes-namespace': ['batch'],
      aws_account: ['111122223333', '444455556666'],
    });
  });

  it('keeps an equals sign inside a value', () => {
    expect(parseConditions('ref=refs/heads/a=b')).toEqual({ ref: ['refs/heads/a=b'] });
  });

  it('rejects a line without a claim or a value', () => {
    expect(parseConditions('=batch')).toBeNull();
    expect(parseConditions('repository=')).toBeNull();
    expect(parseConditions('repository')).toBeNull();
  });

  it('round-trips through format', () => {
    const conditions = { repository: ['acme/shop'], environment: ['production', 'staging-*'] };
    expect(parseConditions(formatConditions(conditions))).toEqual(conditions);
    expect(parseConditions('')).toEqual({});
  });
});
