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
    group: 'alerts',
    icon: 'ticket',
    toggle: 'Open a Jira issue for every anomaly',
    summary: c => [c.project, c.issue_type].filter(Boolean).join(' · '),
    label: 'Jira',
    desc: 'Opens an issue titled "Attention: <kind>" with the event details.',
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
    group: 'alerts',
    icon: 'message-square',
    toggle: 'Post alerts to Mattermost',
    summary: c => (c.channel ? `#${c.channel}` : ''),
    label: 'Mattermost',
    desc: 'Incoming webhook to a Mattermost channel.',
    fields: [
      { key: 'webhook_url', label: 'Webhook URL', placeholder: 'https://mm.example.com/hooks/xxxx', secret: true, required: true },
      { key: 'channel',     label: 'Channel override', placeholder: 'sec-alerts' },
      { key: 'username',    label: 'Bot username',     placeholder: 'kvisior8' },
    ],
  },
  {
    kind: 'discord',
    group: 'alerts',
    icon: 'message-circle',
    toggle: 'Post alerts to Discord',
    summary: c => c.username || '',
    label: 'Discord',
    desc: 'Incoming webhook to a Discord channel.',
    fields: [
      { key: 'webhook_url', label: 'Webhook URL', placeholder: 'https://discord.com/api/webhooks/…', secret: true, required: true },
      { key: 'username',    label: 'Bot username', placeholder: 'Wolfee-Watcher' },
    ],
  },
  {
    kind: 'harbor',
    group: 'registry',
    icon: 'package',
    toggle: 'Use these credentials when pulling images',
    summary: c => (c.url ? c.url.replace(/^https?:\/\//, '') : ''),
    label: 'Harbor',
    desc: 'Registry credentials the scanner uses to pull images for Trivy.',
    fields: [
      { key: 'url',      label: 'Harbor URL',       placeholder: 'https://harbor.example.com', required: true },
      { key: 'username', label: 'Robot / user name', placeholder: 'robot$kvisior' },
      { key: 'token',    label: 'Token / password', placeholder: 'paste token', secret: true, required: true },
    ],
  },
];
