const SERVICES = [
  { name: 'redis',    port: 6379, icon: '🗄',  label: 'Redis'         },
  { name: 'postgres', port: 5432, icon: '🐘',  label: 'PostgreSQL'    },
  { name: 'elastic',  port: 9200, icon: '🔍',  label: 'Elasticsearch' },
  { name: 'dns',      port: 5353, icon: '🌐',  label: 'DNS'           },
  { name: 'mysql',    port: 3306, icon: '🐬',  label: 'MySQL'         },
  { name: 'ssh',      port: 22,   icon: '🔐',  label: 'SSH'           },
  { name: 'ftp',      port: 21,   icon: '📁',  label: 'FTP'           },
  { name: 'http',     port: 80,   icon: '🌍',  label: 'HTTP'          },
  { name: 'smtp',     port: 25,   icon: '✉️',  label: 'SMTP'          },
];

const DEFAULT_NS = 'wolfee-watcher';

export { SERVICES, DEFAULT_NS };
