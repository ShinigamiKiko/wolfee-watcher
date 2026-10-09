const SERVICES = [
  { name: 'postgres', port: 5432, icon: 'database', label: 'PostgreSQL',    kind: 'StatefulSet', defaultName: 'postgres',      image: 'postgres:16.4' },
  { name: 'mysql',    port: 3306, icon: 'database', label: 'MySQL',         kind: 'StatefulSet', defaultName: 'mysql',         image: 'mysql:8.0.39' },
  { name: 'redis',    port: 6379, icon: 'database', label: 'Redis',         kind: 'StatefulSet', defaultName: 'redis',         image: 'redis:7.2.5' },
  { name: 'elastic',  port: 9200, icon: 'search',   label: 'Elasticsearch', kind: 'StatefulSet', defaultName: 'elasticsearch', image: 'elasticsearch:8.15.0' },
  { name: 'dns',      port: 53,   icon: 'globe',    label: 'DNS',           kind: 'Deployment',  defaultName: 'coredns-cache', image: 'coredns:1.11.3' },
  { name: 'ssh',      port: 22,   icon: 'lock',     label: 'SSH',           kind: 'Deployment',  defaultName: 'bastion',       image: 'openssh-server:9.7' },
  { name: 'http',     port: 80,   icon: 'globe',    label: 'HTTP',          kind: 'Deployment',  defaultName: 'internal-api',  image: 'nginx:1.27.1' },
  { name: 'ftp',      port: 21,   icon: 'folder',   label: 'FTP',           kind: 'Deployment',  defaultName: 'ftp',           image: 'vsftpd:3.0.5' },
  { name: 'smtp',     port: 25,   icon: 'mail',     label: 'SMTP',          kind: 'Deployment',  defaultName: 'mail-relay',    image: 'postfix:3.9.0' },
];

const DEFAULT_NS = 'wolfee-watcher';

const STATE_LABEL = {
  ok:       { text: 'Healthy',  tone: 'ok' },
  missing:  { text: 'Missing',  tone: 'danger' },
  replaced: { text: 'Replaced', tone: 'warn' },
};

export { SERVICES, DEFAULT_NS, STATE_LABEL };
