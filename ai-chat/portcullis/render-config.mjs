// Portcullis ai-chat: renders LibreChat's librechat.yaml from the Hub's
// ai-providers.json (contract §3.2 "ai-providers.json", §15.12).
//
//   node render-config.mjs <ai-providers.json> <librechat.base.yaml> <librechat.yaml>
//
// Runs in the config service (the LibreChat image, working directory /app)
// before api starts, at every start: LibreChat reads its configuration only
// at start, and a provider change restarts the project. It fails closed:
// the previous librechat.yaml is removed first, and a file that doesn't
// match the contract exactly (unknown or missing fields, a kind this
// template doesn't render, a variable name that isn't the provider's own)
// a file for another instance (PORTCULLIS_INSTANCE), or a result
// LibreChat's own schema refuses exits non-zero, so compose never starts
// api on a stale or half-understood configuration; before exiting it
// writes a configuration with no provider and every lock (fallback), in
// case api is started by hand. api's entrypoint refuses to start without a
// non-empty configuration file (LibreChat would run on its defaults).
//
// Secrets: the file only names variables (env); every key is written as a
// "${VAR}" reference LibreChat expands from the api service's environment
// (the Hub's override adds them there, never here). This process never
// sees a secret value.
//
// Kinds (LibreChat v0.8.8):
//   openai_compatible, litellm  -> endpoints.custom[] (OpenAI-compatible)
//   openai                      -> endpoints.custom[], https://api.openai.com/v1
//   google                      -> endpoints.custom[], Google's OpenAI-compatible API
//   anthropic                   -> endpoints.custom[] with provider: anthropic
//                                  (LibreChat's native Messages API client)
//   azure_openai                -> endpoints.azureOpenAI.groups[]
// LibreChat's built-in OpenAI / Anthropic / Google / Bedrock endpoints read
// their key only from fixed variables (OPENAI_API_KEY, ANTHROPIC_API_KEY,
// GOOGLE_KEY, BEDROCK_AWS_*), never from a ${VAR} reference, and show no
// admin label; custom endpoints take apiKey: "${VAR}" and show the label.
// bedrock has no such path (SigV4 access keys), so it isn't rendered.

import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(path.join(process.cwd(), 'package.json'));
const yaml = require('js-yaml');
const { configSchema, EModelEndpoint } = require('librechat-data-provider');

export const WELCOME = 'No model provider configured; ask your administrator';
export const REFUSED_WELCOME = 'The AI page\'s model configuration was refused; ask your administrator';

// kind -> how many per instance (manifest ai.chat.provider_kinds), its
// secret fields, whether the key may be absent, models.fetch, default URL.
export const KINDS = {
  openai_compatible: { many: true, secrets: ['key'], keyOptional: true, fetch: true, fields: ['base_url'], needsURL: true },
  litellm: { many: true, secrets: ['key'], fetch: true, fields: ['base_url'], needsURL: true },
  azure_openai: { many: true, secrets: ['key'], fields: ['base_url', 'instance_name', 'api_version', 'deployments'] },
  anthropic: { many: false, secrets: ['key'], fields: ['base_url'], url: 'https://api.anthropic.com', provider: 'anthropic' },
  openai: { many: false, secrets: ['key'], fetch: true, fields: ['base_url'], url: 'https://api.openai.com/v1' },
  google: { many: false, secrets: ['key'], fields: ['base_url'], url: 'https://generativelanguage.googleapis.com/v1beta/openai' },
};

const ENTRY_KEYS = ['name', 'label', 'kind', 'base_url', 'region', 'instance_name', 'api_version',
  'deployments', 'models', 'credentials', 'env'];
const NAME_RE = /^[a-z][a-z0-9-]{0,30}$/;
const INSTANCE_RE = /^[a-z0-9]+(-[a-z0-9]+)*$/;
const AZURE_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9-]{0,62}$/;
const AZURE_VERSION_RE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}(-preview)?$/;
const AZURE_DEPLOY_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
const CONTROL_RE = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/;
const MAX_PROVIDERS = 64;

class Refused extends Error {}
const refuse = (msg) => { throw new Refused(msg); };

const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const exactKeys = (v, keys, where) => {
  if (!isObject(v)) refuse(`${where}: must be an object`);
  const got = Object.keys(v).sort();
  const want = [...keys].sort();
  const extra = got.filter((k) => !want.includes(k));
  const missing = want.filter((k) => !got.includes(k));
  if (extra.length) refuse(`${where}: unknown field(s) ${extra.join(', ')}`);
  if (missing.length) refuse(`${where}: missing field(s) ${missing.join(', ')}`);
};
// One line of text, no LibreChat placeholder syntax: LibreChat expands
// ${VAR} (its own environment) and {{LIBRECHAT_*}} in several fields, so a
// value carrying one could pull another provider's key into a URL.
const text = (v, where, { min = 0, max = 2048 } = {}) => {
  if (typeof v !== 'string') refuse(`${where}: must be a string`);
  const n = [...v].length;
  if (n < min || n > max) refuse(`${where}: ${min}–${max} characters`);
  if (CONTROL_RE.test(v)) refuse(`${where}: one line without control characters`);
  if (v.includes('${') || v.includes('{{')) refuse(`${where}: may not contain "\${" or "{{"`);
  return v;
};
const httpURL = (v, where) => {
  text(v, where, { min: 1 });
  let u;
  try { u = new URL(v); } catch { refuse(`${where}: not a URL`); }
  if ((u.protocol !== 'https:' && u.protocol !== 'http:') || !u.hostname || u.username || u.password || u.search || u.hash || v.includes('$')) {
    refuse(`${where}: an http or https URL without user, password, query, fragment or $`);
  }
  return v;
};
export const providerVar = (name, field) =>
  `PORTCULLIS_AI_PROVIDER_${name.toUpperCase().replace(/-/g, '_')}_${field.toUpperCase().replace(/-/g, '_')}`;

// validate checks the whole document against contract §3.2; it returns the
// providers, unchanged.
export function validate(doc, instance) {
  exactKeys(doc, ['version', 'instance', 'providers'], 'ai-providers.json');
  if (doc.version !== 1) refuse(`ai-providers.json: version ${JSON.stringify(doc.version)}: only 1 is known`);
  if (typeof doc.instance !== 'string' || !INSTANCE_RE.test(doc.instance)) refuse('ai-providers.json: instance must be an instance id');
  if (typeof instance !== 'string' || !INSTANCE_RE.test(instance)) refuse('PORTCULLIS_INSTANCE must be this instance\'s id');
  if (doc.instance !== instance) refuse(`ai-providers.json is for instance ${doc.instance}, not ${instance}`);
  if (!Array.isArray(doc.providers)) refuse('ai-providers.json: providers must be a list');
  if (doc.providers.length > MAX_PROVIDERS) refuse(`ai-providers.json: at most ${MAX_PROVIDERS} providers`);
  const names = new Set();
  const perKind = {};
  let prev = '';
  for (const [i, p] of doc.providers.entries()) {
    const where = `providers[${i}]`;
    exactKeys(p, ENTRY_KEYS, where);
    if (typeof p.name !== 'string' || !NAME_RE.test(p.name)) refuse(`${where}: name must match ${NAME_RE}`);
    const at = `provider ${p.name}`;
    if (names.has(p.name)) refuse(`${at}: listed twice`);
    if (p.name < prev) refuse(`${at}: providers must be sorted by name`);
    names.add(p.name);
    prev = p.name;
    text(p.label, `${at}: label`, { min: 1, max: 64 });
    if (p.label.trim() !== p.label) refuse(`${at}: label has leading or trailing spaces`);
    const kind = KINDS[p.kind];
    if (!kind) refuse(`${at}: kind ${JSON.stringify(p.kind)} is not one this template renders (${Object.keys(KINDS).join(', ')})`);
    perKind[p.kind] = (perKind[p.kind] || 0) + 1;
    if (!kind.many && perKind[p.kind] > 1) refuse(`${at}: at most one ${p.kind} provider per instance`);
    for (const f of ['base_url', 'region', 'instance_name', 'api_version']) {
      text(p[f], `${at}: ${f}`);
      if (p[f] !== '' && !kind.fields.includes(f)) refuse(`${at}: ${f} is not a field of kind ${p.kind}`);
    }
    if (p.base_url !== '') httpURL(p.base_url, `${at}: base_url`);
    if (kind.needsURL && p.base_url === '') refuse(`${at}: kind ${p.kind} needs base_url`);
    if (!isObject(p.deployments)) refuse(`${at}: deployments must be an object`);
    const deps = Object.entries(p.deployments);
    if (deps.length && !kind.fields.includes('deployments')) refuse(`${at}: deployments is not a field of kind ${p.kind}`);
    for (const [d, m] of deps) {
      if (!AZURE_DEPLOY_RE.test(d)) refuse(`${at}: deployment ${JSON.stringify(d)} is not a deployment name`);
      text(m, `${at}: deployment ${d}'s model`, { min: 1, max: 128 });
    }
    if (p.kind === 'azure_openai') {
      if (p.instance_name === '' && p.base_url === '') refuse(`${at}: azure_openai needs instance_name or base_url`);
      if (p.instance_name !== '' && !AZURE_NAME_RE.test(p.instance_name)) refuse(`${at}: instance_name is not an Azure resource name`);
      if (!AZURE_VERSION_RE.test(p.api_version)) refuse(`${at}: api_version must be a date such as 2024-10-21`);
      if (!deps.length) refuse(`${at}: azure_openai needs at least one deployment`);
    }
    exactKeys(p.models, ['fetch', 'list'], `${at}: models`);
    if (typeof p.models.fetch !== 'boolean') refuse(`${at}: models.fetch must be true or false`);
    if (p.models.fetch && !kind.fetch) refuse(`${at}: models.fetch is not allowed for kind ${p.kind}`);
    if (!Array.isArray(p.models.list) || p.models.list.length > 200) refuse(`${at}: models.list must be a list of at most 200`);
    const seen = new Set();
    for (const m of p.models.list) {
      text(m, `${at}: models.list`, { min: 1, max: 128 });
      if (m.trim() !== m) refuse(`${at}: models.list: ${JSON.stringify(m)} has leading or trailing spaces`);
      if (seen.has(m)) refuse(`${at}: models.list: ${JSON.stringify(m)} is listed twice`);
      seen.add(m);
    }
    if (p.credentials !== 'admin' && p.credentials !== 'per_person') refuse(`${at}: credentials must be admin or per_person`);
    if (!isObject(p.env)) refuse(`${at}: env must be an object`);
    for (const [field, v] of Object.entries(p.env)) {
      if (!kind.secrets.includes(field)) refuse(`${at}: env.${field} is not a secret field of kind ${p.kind}`);
      if (v !== providerVar(p.name, field)) refuse(`${at}: env.${field} must be ${providerVar(p.name, field)}`);
    }
    if (p.credentials === 'per_person' && Object.keys(p.env).length) refuse(`${at}: a per_person provider has no admin secret (env must be {})`);
    if (p.credentials === 'per_person' && p.kind === 'azure_openai') {
      refuse(`${at}: LibreChat can't take a person's own key for an Azure OpenAI deployment group; set credentials to admin`);
    }
  }
  return doc.providers;
}

const RESERVED_NAMES = new Set(Object.values(EModelEndpoint).map((n) => n.toLowerCase()));

// render builds the configuration from the base document and the providers,
// then writes the locks (lock, below).
// warn receives the providers left out (and why).
export function render(base, providers, domain, warn = () => {}, welcome = WELCOME) {
  if (!DOMAIN_RE.test(domain)) refuse(`PORTCULLIS_DOMAIN ${JSON.stringify(domain)} is not a domain name`);
  const conf = structuredClone(base);
  const usable = [];
  for (const p of providers) {
    const kind = KINDS[p.kind];
    if (p.credentials === 'admin' && !p.env.key && !kind.keyOptional) {
      warn(`provider ${p.name}: left out until the administrator sets its key`);
      continue;
    }
    const models = p.kind === 'azure_openai' ? Object.values(p.deployments) : p.models.list;
    if (!models.length && !p.models.fetch) {
      warn(`provider ${p.name}: left out: no model listed and models.fetch is off`);
      continue;
    }
    usable.push(p);
  }

  // Endpoint names: the admin's label (what people see in the selector).
  // A label equal to another one or to a built-in endpoint gets " (<name>)".
  const custom = usable.filter((p) => p.kind !== 'azure_openai');
  const count = new Map();
  for (const p of custom) count.set(p.label.toLowerCase(), (count.get(p.label.toLowerCase()) || 0) + 1);
  const taken = new Set();
  const endpoints = {};
  const customs = [];
  for (const p of custom) {
    const kind = KINDS[p.kind];
    const l = p.label.toLowerCase();
    const name = count.get(l) > 1 || RESERVED_NAMES.has(l) ? `${p.label} (${p.name})` : p.label;
    if (taken.has(name.toLowerCase())) refuse(`provider ${p.name}: its endpoint name ${JSON.stringify(name)} is taken; change one of the labels`);
    taken.add(name.toLowerCase());
    let apiKey;
    if (p.credentials === 'per_person') apiKey = 'user_provided';
    else if (p.env.key) apiKey = '${' + p.env.key + '}';
    else apiKey = 'none'; // an OpenAI-compatible server without a key (e.g. Ollama); LibreChat needs a value
    const list = p.models.list.length ? [...p.models.list] : [`(the model list of ${p.label} could not be loaded)`];
    const e = {
      name,
      apiKey,
      baseURL: p.base_url || kind.url,
      models: { default: list, fetch: p.models.fetch },
      modelDisplayLabel: p.label,
    };
    if (kind.provider) e.provider = kind.provider;
    customs.push(e);
  }
  if (customs.length) endpoints.custom = customs;

  const azure = usable.filter((p) => p.kind === 'azure_openai');
  if (azure.length) {
    const modelOwner = new Map();
    const groups = azure.map((p) => {
      const models = Object.create(null);
      for (const [deployment, model] of Object.entries(p.deployments)) {
        if (modelOwner.has(model)) {
          refuse(`provider ${p.name}: model ${JSON.stringify(model)} is also deployed by ${modelOwner.get(model)}; ` +
            'LibreChat needs every Azure model name once across the instance');
        }
        modelOwner.set(model, `${p.name} (${deployment})`);
        models[model] = { deploymentName: deployment, version: p.api_version };
      }
      const g = {
        group: p.name,
        apiKey: '${' + p.env.key + '}',
        // LibreChat requires an instance name; with base_url only, the
        // resource is the URL's first host label (base_url wins for requests).
        instanceName: p.instance_name || new URL(p.base_url).hostname.split('.')[0],
        version: p.api_version,
        models,
      };
      if (p.base_url) g.baseURL = p.base_url;
      return g;
    });
    endpoints.azureOpenAI = { groups };
  }
  return lock(conf, endpoints, domain, !customs.length && !azure.length ? welcome : '');
}

// The locks, written whatever the providers are: nothing a person does in
// LibreChat makes the server fetch a URL they chose. api sits on
// portcullis-proxy (every app, Traefik, the gate) and its project network.
//   - Agents keep only capabilities that fetch nothing: no actions (OpenAPI
//     calls to any URL), web_search (people's own search / scraper URLs),
//     execute_code (LibreChat's remote code API), file_search (RAG API),
//     ocr (an OCR API). "tools" stays: it carries the MCP tools.
//   - actions.allowedDomains: an empty list means "any public host" in
//     v0.8.8, so it names one host that never resolves (RFC 2606 .invalid).
//   - includedTools: only the calculator among LibreChat's built-in tools
//     (the others call third-party APIs, Stable Diffusion and Azure AI
//     Search at a URL the person enters).
//   - autoSubmitFromUrl off: a link can't send a prompt (and so start tool
//     calls as the person) just by being opened;
//   - shared links off (create / share / public), and ALLOW_SHARED_LINKS_PUBLIC
//     is false in compose: a conversation holds what the person's apps
//     returned;
//   - web search off in the interface; people can't add MCP servers, and
//     MCP may only reach the gate and Keycloak (a non-empty allowlist also
//     lets LibreChat reach them on private addresses, e.g. through Traefik).
export const AGENT_CAPABILITIES = ['deferred_tools', 'artifacts', 'subagents', 'context', 'skills', 'memory',
  'ask_user_question', 'tools', 'chain'];
export const CLOSED_ACTION_DOMAINS = ['actions.invalid'];
export const INCLUDED_TOOLS = ['calculator'];

function lock(conf, endpoints, domain, welcome) {
  conf.endpoints = { ...endpoints, agents: { capabilities: [...AGENT_CAPABILITIES] } };
  conf.actions = { allowedDomains: [...CLOSED_ACTION_DOMAINS] };
  conf.includedTools = [...INCLUDED_TOOLS];
  delete conf.filteredTools;
  conf.mcpSettings = { allowedDomains: [`mcp.${domain}`, `auth.${domain}`] };
  conf.interface = {
    ...(conf.interface || {}),
    webSearch: false,
    autoSubmitFromUrl: false,
    sharedLinks: { create: false, share: false, public: false },
    mcpServers: { use: true, create: false, share: false, public: false },
  };
  if (welcome) conf.interface.customWelcome = welcome;
  else delete conf.interface.customWelcome;
  return conf;
}

function check(conf) {
  const r = configSchema.strict().safeParse(conf);
  if (!r.success) {
    refuse('LibreChat refuses the rendered configuration: ' +
      r.error.errors.map((e) => `${e.path.join('.')}: ${e.message}`).join('; '));
  }
}

function writeConf(conf, outPath, header) {
  check(conf);
  const out = yaml.dump(conf, { noRefs: true, lineWidth: -1, quotingType: '"' });
  const tmp = path.join(path.dirname(outPath), `.${path.basename(outPath)}.tmp`);
  fs.writeFileSync(tmp, header + out, { mode: 0o644 });
  fs.chmodSync(tmp, 0o644);
  fs.renameSync(tmp, outPath);
}

function loadBase(basePath) {
  const base = yaml.load(fs.readFileSync(basePath, 'utf8'), { schema: yaml.CORE_SCHEMA });
  if (!isObject(base)) refuse(`${basePath}: not a YAML mapping`);
  return base;
}

// fallback: after a refusal, a configuration with no provider and every
// lock, so a LibreChat started by hand (docker start) still runs locked and
// sends nothing anywhere. The run still exits 1, so compose never starts
// api after it. If even this can't be written, there is no file, and api's
// entrypoint refuses to start.
function fallback(basePath, outPath) {
  try {
    const conf = render(loadBase(basePath), [], process.env.PORTCULLIS_DOMAIN || '', () => {}, REFUSED_WELCOME);
    writeConf(conf, outPath, '# Written by render-config.mjs after it refused ai-providers.json: no provider. Do not edit.\n');
    console.error(`render-config: wrote a configuration with no provider and every lock to ${outPath}`);
  } catch (e) {
    fs.rmSync(outPath, { force: true });
    console.error(`render-config: no fallback configuration either: ${e instanceof Refused ? e.message : e}`);
  }
}

function main(argv) {
  const [providersPath, basePath, outPath] = argv;
  if (!providersPath || !basePath || !outPath) {
    refuse('usage: render-config.mjs <ai-providers.json> <librechat.base.yaml> <librechat.yaml>');
  }
  fs.rmSync(outPath, { force: true });
  try {
    run(providersPath, basePath, outPath);
  } catch (e) {
    fallback(basePath, outPath);
    throw e;
  }
}

function run(providersPath, basePath, outPath) {
  let doc;
  try {
    doc = JSON.parse(fs.readFileSync(providersPath, 'utf8'));
  } catch (e) {
    refuse(`${providersPath}: ${e.code === 'ENOENT' ? 'missing (the Hub delivers it)' : 'not JSON'}`);
  }
  const providers = validate(doc, process.env.PORTCULLIS_INSTANCE);
  const conf = render(loadBase(basePath), providers, process.env.PORTCULLIS_DOMAIN || '',
    (m) => console.error(`render-config: ${m}`));
  writeConf(conf, outPath, '# Rendered by render-config.mjs from ai-providers.json at start. Do not edit.\n');
  const n = (conf.endpoints?.custom?.length || 0) + (conf.endpoints?.azureOpenAI?.groups.length || 0);
  console.log(`render-config: ${outPath}: ${n} model endpoint(s) for instance ${doc.instance}`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    main(process.argv.slice(2));
  } catch (e) {
    console.error(`render-config: refused: ${e instanceof Refused ? e.message : e.stack || e}`);
    process.exit(1);
  }
}
