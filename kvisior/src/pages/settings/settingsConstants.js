export const SECTIONS = [
  { id: 'group',        label: 'Group',            desc: 'Manage user groups and access' },
  { id: 'tokens',       label: 'Tokens',           desc: 'API tokens for programmatic access' },
  { id: 'users',        label: 'User Permissions', desc: 'Users and their effective roles' },
  { id: 'integrations', label: 'Integrations',     desc: 'External system connectors' },
];

export const ROLE_OPTIONS = [
  { value: 'admin', label: 'Admin — full access' },
  { value: 'ro',    label: 'Read-Only — read only, no create/edit/delete' },
];

export const TOKEN_TTL_OPTIONS = [
  { value: '',       label: 'Never expires' },
  { value: '720h',   label: '30 days' },
  { value: '2160h',  label: '90 days' },
  { value: '8760h',  label: '1 year' },
];

export const INTEGRATION_DEFS = [
  {
    kind: 'jira',
    label: 'Jira',
    desc: 'Open an issue in the configured project for every anomaly. Title is "Attention: <kind>"; description carries event details.',
    fields: [
      { key: 'url',       label: 'Jira URL',     placeholder: 'https://your-org.atlassian.net', required: true },
      { key: 'email',     label: 'Email (Cloud only)', placeholder: 'you@example.com' },
      { key: 'token',     label: 'API token / PAT', placeholder: 'paste token', secret: true, required: true },
      { key: 'project',   label: 'Project key',  placeholder: 'SEC',                       required: true },
      { key: 'issue_type',label: 'Issue type',   placeholder: 'Task' },
    ],
  },
  {
    kind: 'mattermost',
    label: 'Mattermost',
    desc: 'Send alerts to a Mattermost channel through an incoming webhook.',
    fields: [
      { key: 'webhook_url', label: 'Webhook URL', placeholder: 'https://mm.example.com/hooks/xxxx', secret: true, required: true },
      { key: 'channel',     label: 'Channel override', placeholder: 'sec-alerts' },
      { key: 'username',    label: 'Bot username',     placeholder: 'kvisior8' },
    ],
  },
  {
    kind: 'discord',
    label: 'Discord',
    desc: 'Send alerts to a Discord channel through an incoming webhook.',
    fields: [
      { key: 'webhook_url', label: 'Webhook URL', placeholder: 'https://discord.com/api/webhooks/…', secret: true, required: true },
      { key: 'username',    label: 'Bot username', placeholder: 'Wolfee-Watcher' },
    ],
  },
  {
    kind: 'harbor',
    label: 'Harbor',
    desc: 'Registry credentials used by the scanner to pull images for Grype.',
    fields: [
      { key: 'url',      label: 'Harbor URL',       placeholder: 'https://harbor.example.com', required: true },
      { key: 'username', label: 'Robot / user name', placeholder: 'robot$kvisior' },
      { key: 'token',    label: 'Token / password', placeholder: 'paste token', secret: true, required: true },
    ],
  },
];
