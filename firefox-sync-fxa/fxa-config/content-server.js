// Vendored unmodified (everything below this header) from porelli/firefox-sync
// 7216405, config/fxa/content-server.js
// (https://github.com/porelli/firefox-sync/blob/721640567d614586fdc47443e01169cdb1d24ead/config/fxa/content-server.js), GPL-3.0.
// Prepares the content server, run from its directory before it starts:
// - writes the settings that can only come from a config file (the session
//   cookie secret) to the file named by $1
// - the accounts web pages are built with Mozilla's CDN in every asset URL
//   (https://cdn.accounts.firefox.com/settings/prod/...): point them to this
//   deployment ($PUBLIC_URL), which serves the same files, otherwise the pages
//   stay blank (the CDN only has Mozilla's current build) or load from Mozilla
const fs = require('fs');
const path = require('path');

fs.writeFileSync(
  process.argv[2],
  JSON.stringify({ client_sessions: { secret: process.env.CONTENT_SESSION_SECRET } }, null, 2)
);

const CDN = 'https://cdn.accounts.firefox.com';
const publicUrl = process.env.PUBLIC_URL.replace(/\/$/, '');
let rewritten = 0;
(function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const file = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(file);
    } else if (/\.(html|js|css|json|map)$/.test(entry.name)) {
      const content = fs.readFileSync(file, 'utf-8');
      if (content.includes(CDN)) {
        fs.writeFileSync(file, content.split(CDN).join(publicUrl));
        rewritten++;
      }
    }
  }
})('dist/settings/prod');
console.log(`Pointed ${rewritten} settings files from ${CDN} to ${publicUrl}`);
