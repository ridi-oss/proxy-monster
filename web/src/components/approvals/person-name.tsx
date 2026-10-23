import type { Person } from '@/lib/api/types';

const SLACK_PREFIX = 'slack:';

/** A principal as its directory name and email; a Slack author with no user as their Slack name. */
export function PersonName({ principal, people }: { principal: string; people?: Record<string, Person> }) {
  if (principal.startsWith(SLACK_PREFIX)) {
    return <span className="text-foreground font-medium">{principal.slice(SLACK_PREFIX.length)}</span>;
  }
  const person = people?.[principal];
  if (!person?.name) return <span className="text-foreground font-medium">{principal}</span>;
  const email = person.email ?? principal;
  return (
    <span>
      <span className="text-foreground font-medium">{person.name}</span>
      {email !== person.name && <span className="text-muted-foreground font-normal"> {email}</span>}
    </span>
  );
}
