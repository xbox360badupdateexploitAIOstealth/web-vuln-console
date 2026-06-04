// backend/dorkEngine.js
// Generates Google, GitHub, Shodan, and GreyNoise dork queries for a target domain.
// 35 Google + 16 GitHub + 6 Shodan templates.

'use strict';

const GOOGLE_BASE  = 'https://www.google.com/search?q=';
const GITHUB_BASE  = 'https://github.com/search?type=code&q=';
const SHODAN_BASE  = 'https://www.shodan.io/search?query=';

const enc = encodeURIComponent;

const GOOGLE_TEMPLATES = [
  // ─── Credentials / Secrets ───────────────────────────────────────────────
  { title: '.env file exposure',            q: (d) => `site:${d} ext:env`,                                      sev: 'critical' },
  { title: 'AWS_SECRET_ACCESS_KEY',         q: (d) => `site:${d} "AWS_SECRET_ACCESS_KEY"`,                     sev: 'critical' },
  { title: 'AWS_ACCESS_KEY_ID',             q: (d) => `site:${d} "AWS_ACCESS_KEY_ID"`,                         sev: 'critical' },
  { title: 'DATABASE_URL',                  q: (d) => `site:${d} "DATABASE_URL"`,                             sev: 'critical' },
  { title: 'DB_PASSWORD',                   q: (d) => `site:${d} "DB_PASSWORD"`,                              sev: 'critical' },
  { title: 'REDIS_URL',                     q: (d) => `site:${d} "REDIS_URL"`,                                sev: 'high'     },
  { title: 'JWT_SECRET',                    q: (d) => `site:${d} "JWT_SECRET"`,                               sev: 'critical' },
  { title: 'OPENAI_API_KEY',                q: (d) => `site:${d} "OPENAI_API_KEY" OR "OPENAI_KEY"`,           sev: 'critical' },
  { title: 'HuggingFace API token',         q: (d) => `site:${d} "HUGGINGFACE_API_KEY" OR "HUGGINGFACEHUB_API_TOKEN"`, sev: 'critical' },
  { title: 'Replicate API token',           q: (d) => `site:${d} "REPLICATE_API_TOKEN"`,                      sev: 'critical' },
  { title: 'Stripe secret key',             q: (d) => `site:${d} "STRIPE_SECRET" OR "sk_live_"`,              sev: 'critical' },
  { title: 'GitHub personal access token',  q: (d) => `site:${d} "GITHUB_TOKEN" OR "ghp_"`,                   sev: 'critical' },
  { title: 'Twilio auth token',             q: (d) => `site:${d} "TWILIO_AUTH_TOKEN"`,                        sev: 'critical' },
  { title: 'SendGrid API key',              q: (d) => `site:${d} "SENDGRID_API_KEY" OR "SG."`,                sev: 'critical' },
  { title: 'Firebase config exposed',       q: (d) => `site:${d} "firebaseConfig" "apiKey"`,                  sev: 'high'     },
  { title: 'Google API key',               q: (d) => `site:${d} "AIza" OR "GOOGLE_API_KEY"`,                  sev: 'high'     },
  // ─── Files / Configs ─────────────────────────────────────────────────────
  { title: 'config.php exposed',            q: (d) => `site:${d} ext:php intitle:"config"`,                  sev: 'high'     },
  { title: 'PHP backup files',              q: (d) => `site:${d} ext:bak "config"`,                           sev: 'high'     },
  { title: 'WordPress config backup',       q: (d) => `site:${d} "wp-config.php.bak"`,                        sev: 'critical' },
  { title: 'SQL dump exposed',              q: (d) => `site:${d} ext:sql "INSERT INTO"`,                      sev: 'critical' },
  { title: 'YAML credentials',             q: (d) => `site:${d} ext:yml "password"`,                          sev: 'high'     },
  { title: 'XML credentials',              q: (d) => `site:${d} ext:xml "password"`,                          sev: 'medium'   },
  { title: '.htpasswd exposed',             q: (d) => `site:${d} intitle:"index of" ".htpasswd"`,             sev: 'critical' },
  { title: 'Log files exposed',             q: (d) => `site:${d} ext:log`,                                    sev: 'medium'   },
  { title: '.bak files exposed',            q: (d) => `site:${d} ext:bak OR ext:old OR ext:orig`,             sev: 'high'     },
  // ─── Directories / Admin ─────────────────────────────────────────────────
  { title: 'Directory listing',             q: (d) => `site:${d} intitle:"Index of /"`,                       sev: 'high'     },
  { title: 'Backup directory listing',      q: (d) => `site:${d} intitle:"Index of /backup"`,                 sev: 'high'     },
  { title: 'Admin panel',                   q: (d) => `site:${d} inurl:admin`,                               sev: 'medium'   },
  { title: 'Login pages',                   q: (d) => `site:${d} inurl:login`,                               sev: 'low'      },
  { title: 'phpinfo exposed',               q: (d) => `site:${d} inurl:phpinfo.php`,                         sev: 'high'     },
  // ─── VCS / Metadata ──────────────────────────────────────────────────────
  { title: 'Git repo config exposed',       q: (d) => `site:${d} "[core]" "repositoryformatversion"`,         sev: 'high'     },
  { title: 'SVN entries exposed',           q: (d) => `site:${d} inurl:".svn/entries"`,                      sev: 'medium'   },
  { title: '.DS_Store file',               q: (d) => `site:${d} ".DS_Store"`,                                sev: 'medium'   },
  // ─── Error / Debug ────────────────────────────────────────────────────────
  { title: 'Stack trace in page',           q: (d) => `site:${d} "stack trace" OR "Traceback" "line"`,        sev: 'medium'   },
  { title: 'Laravel debug page',            q: (d) => `site:${d} "Whoops! There was an error"`,               sev: 'medium'   },
];

const GITHUB_TEMPLATES = [
  { title: 'AWS keys in repo',              q: (d) => `"${d}" "AWS_SECRET_ACCESS_KEY"`,                      sev: 'critical' },
  { title: 'DB_PASSWORD in repo',           q: (d) => `"${d}" "DB_PASSWORD"`,                                sev: 'critical' },
  { title: '.env file in repo',             q: (d) => `"${d}" filename:.env`,                                sev: 'critical' },
  { title: 'Private key in repo',           q: (d) => `"${d}" "BEGIN RSA PRIVATE KEY"`,                      sev: 'critical' },
  { title: 'Private EC key in repo',        q: (d) => `"${d}" "BEGIN EC PRIVATE KEY"`,                       sev: 'critical' },
  { title: 'config.php in repo',            q: (d) => `"${d}" filename:config.php`,                          sev: 'high'     },
  { title: 'API key in repo',               q: (d) => `"${d}" "api_key" OR "apiKey" OR "api_secret"`,        sev: 'high'     },
  { title: 'JWT secret in repo',            q: (d) => `"${d}" "JWT_SECRET" OR "jwt_secret"`,                 sev: 'critical' },
  { title: 'Stripe key in repo',            q: (d) => `"${d}" "sk_live_" OR "STRIPE_SECRET"`,                sev: 'critical' },
  { title: 'Firebase config in repo',       q: (d) => `"${d}" "firebaseConfig" filename:*.js`,               sev: 'high'     },
  { title: 'Database connection string',    q: (d) => `"${d}" "mongodb://" OR "postgres://" OR "mysql://"`,  sev: 'critical' },
  { title: 'Slack webhook in repo',         q: (d) => `"${d}" "hooks.slack.com/services"`,                   sev: 'high'     },
  { title: 'OAuth client secret',           q: (d) => `"${d}" "client_secret" OR "OAUTH_SECRET"`,            sev: 'critical' },
  { title: 'Hardcoded password',            q: (d) => `"${d}" "password =" OR "passwd =" NOT example`,       sev: 'high'     },
  { title: 'SendGrid key in repo',          q: (d) => `"${d}" "SENDGRID_API_KEY" OR "SG."`,                  sev: 'critical' },
  { title: 'Admin credentials',             q: (d) => `"${d}" "admin" "password" filename:*.env OR filename:*.cfg`, sev: 'critical' },
];

const SHODAN_TEMPLATES = [
  { title: 'Open HTTP on domain/org',       q: (d) => `hostname:${d} http`,                                  sev: 'info'     },
  { title: 'Open HTTPS',                    q: (d) => `hostname:${d} port:443`,                              sev: 'info'     },
  { title: 'Open MongoDB (no auth)',        q: (d) => `hostname:${d} port:27017 "MongoDB"`,                  sev: 'critical' },
  { title: 'Open Elasticsearch',            q: (d) => `hostname:${d} port:9200 "elasticsearch"`,             sev: 'critical' },
  { title: 'Open Redis (no auth)',          q: (d) => `hostname:${d} port:6379 "Redis"`,                     sev: 'critical' },
  { title: 'Exposed MySQL',                q: (d) => `hostname:${d} port:3306`,                              sev: 'high'     },
];

function generateDorks(domain) {
  const clean = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').toLowerCase();

  return {
    domain: clean,
    google: GOOGLE_TEMPLATES.map((t) => ({
      type: 'google', severity: t.sev, title: t.title,
      rawQuery: t.q(clean),
      url: `${GOOGLE_BASE}${enc(t.q(clean))}`,
    })),
    github: GITHUB_TEMPLATES.map((t) => ({
      type: 'github', severity: t.sev, title: t.title,
      rawQuery: t.q(clean),
      url: `${GITHUB_BASE}${enc(t.q(clean))}`,
    })),
    shodan: SHODAN_TEMPLATES.map((t) => ({
      type: 'shodan', severity: t.sev, title: t.title,
      rawQuery: t.q(clean),
      url: `${SHODAN_BASE}${enc(t.q(clean))}`,
    })),
  };
}

module.exports = { generateDorks };
