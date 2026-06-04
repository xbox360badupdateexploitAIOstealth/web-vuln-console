// backend/dorkEngine.js
// Generates Google, GitHub, and Shodan dork queries for a given target domain.
// Returns structured dorks with titles, URLs, and descriptions.

const GOOGLE_BASE = 'https://www.google.com/search?q=';
const GITHUB_BASE = 'https://github.com/search?type=code&q=';

function enc(s) {
  return encodeURIComponent(s);
}

function googleUrl(query) {
  return `${GOOGLE_BASE}${enc(query)}`;
}

function githubUrl(query) {
  return `${GITHUB_BASE}${enc(query)}`;
}

const GOOGLE_TEMPLATES = [
  { title: '.env file exposure',           query: (d) => `site:${d} ext:env`,                        severity: 'critical' },
  { title: 'AWS keys in .env',             query: (d) => `site:${d} "AWS_SECRET_ACCESS_KEY"`,         severity: 'critical' },
  { title: 'Database URL exposed',         query: (d) => `site:${d} "DATABASE_URL"`,                 severity: 'critical' },
  { title: 'DB password exposed',          query: (d) => `site:${d} "DB_PASSWORD"`,                  severity: 'critical' },
  { title: 'JWT secret exposed',           query: (d) => `site:${d} "JWT_SECRET"`,                   severity: 'critical' },
  { title: 'OpenAI API key',               query: (d) => `site:${d} "OPENAI_API_KEY"`,               severity: 'critical' },
  { title: 'Stripe secret key',            query: (d) => `site:${d} "STRIPE_SECRET"`,                severity: 'critical' },
  { title: 'GitHub token exposed',         query: (d) => `site:${d} "GITHUB_TOKEN"`,                 severity: 'critical' },
  { title: 'Config PHP exposed',           query: (d) => `site:${d} ext:php intitle:"config"`,       severity: 'high' },
  { title: 'PHP backup files',             query: (d) => `site:${d} ext:bak "config"`,               severity: 'high' },
  { title: 'Git repo exposure',            query: (d) => `site:${d} "[core]" "repositoryformatversion"`, severity: 'high' },
  { title: 'SQL dump exposure',            query: (d) => `site:${d} ext:sql "INSERT INTO"`,           severity: 'critical' },
  { title: 'Directory listing',            query: (d) => `site:${d} intitle:"Index of /"`,            severity: 'high' },
  { title: 'Backup directory',             query: (d) => `site:${d} intitle:"Index of /backup"`,      severity: 'high' },
  { title: 'Admin panel',                  query: (d) => `site:${d} inurl:admin`,                    severity: 'medium' },
  { title: 'Login pages',                  query: (d) => `site:${d} inurl:login`,                    severity: 'low' },
  { title: 'phpinfo exposed',              query: (d) => `site:${d} inurl:phpinfo.php`,               severity: 'high' },
  { title: 'Log files exposed',            query: (d) => `site:${d} ext:log`,                        severity: 'medium' },
  { title: 'WordPress config backup',      query: (d) => `site:${d} "wp-config.php.bak"`,            severity: 'critical' },
  { title: 'Exposed credentials in YAML',  query: (d) => `site:${d} ext:yml "password"`,             severity: 'high' },
];

const GITHUB_TEMPLATES = [
  { title: 'AWS keys in repo',         query: (d) => `"${d}" "AWS_SECRET_ACCESS_KEY"`, severity: 'critical' },
  { title: 'DB password in repo',      query: (d) => `"${d}" "DB_PASSWORD"`,           severity: 'critical' },
  { title: '.env file in repo',        query: (d) => `"${d}" filename:.env`,            severity: 'critical' },
  { title: 'Private key in repo',      query: (d) => `"${d}" "BEGIN RSA PRIVATE KEY"`, severity: 'critical' },
  { title: 'Config files in repo',     query: (d) => `"${d}" filename:config.php`,     severity: 'high' },
  { title: 'API keys in repo',         query: (d) => `"${d}" "api_key" OR "apiKey"`,  severity: 'high' },
];

function generateDorks(domain) {
  const clean = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '');

  const googleDorks = GOOGLE_TEMPLATES.map((t) => ({
    type: 'google',
    severity: t.severity,
    title: t.title,
    rawQuery: t.query(clean),
    url: googleUrl(t.query(clean)),
  }));

  const githubDorks = GITHUB_TEMPLATES.map((t) => ({
    type: 'github',
    severity: t.severity,
    title: t.title,
    rawQuery: t.query(clean),
    url: githubUrl(t.query(clean)),
  }));

  return { domain: clean, google: googleDorks, github: githubDorks };
}

module.exports = { generateDorks };
