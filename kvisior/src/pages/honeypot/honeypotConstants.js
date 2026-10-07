const SERVICES = [
  { name: 'redis',    port: 6379, icon: 'database',  label: 'Redis'         },
  { name: 'postgres', port: 5432, icon: 'database',  label: 'PostgreSQL'    },
  { name: 'elastic',  port: 9200, icon: 'search',  label: 'Elasticsearch' },
  { name: 'dns',      port: 5353, icon: 'globe',  label: 'DNS'           },
  { name: 'mysql',    port: 3306, icon: 'database',  label: 'MySQL'         },
  { name: 'ssh',      port: 22,   icon: 'lock',  label: 'SSH'           },
  { name: 'ftp',      port: 21,   icon: 'folder',  label: 'FTP'           },
  { name: 'http',     port: 80,   icon: 'globe',  label: 'HTTP'          },
  { name: 'smtp',     port: 25,   icon: 'mail',  label: 'SMTP'          },
];

const DEFAULT_NS = 'wolfee-watcher';

export { SERVICES, DEFAULT_NS };
