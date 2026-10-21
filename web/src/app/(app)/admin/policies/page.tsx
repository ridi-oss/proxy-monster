// /admin/policies — role CRUD. The sibling routes under this parent expose
// assignments, mask functions, and Cedar policy authoring.

import { RolesTab } from '@/components/policies/roles-tab';

export default function PoliciesPage() {
  return <RolesTab />;
}
