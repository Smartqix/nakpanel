// Builds a self-contained design artifact, not application code.
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '../../..');
const font = fs.readFileSync(path.join(root, 'internal/control/web/static/fonts/inter-variable.woff2')).toString('base64');
const sprite = fs.readFileSync(path.join(root, 'internal/control/web/static/icons.svg'), 'utf8')
  .replace('<svg xmlns=', '<svg class="icon-sprite" aria-hidden="true" xmlns=');
const source = fs.readFileSync(path.join(__dirname, 'mockup.template.html'), 'utf8');
fs.writeFileSync(path.join(__dirname, 'mockup.html'), source.replace('/* FONT_DATA */', font).replace('<!-- ICON_SPRITE -->', sprite));
console.log('Built self-contained notification mockup.');

const frames = [
  ['desktop-preview.jpg', 'Desktop preview', '1440 x 1000'],
  ['mobile-preview.jpg', 'Mobile preview', '390 x 844'],
  ['desktop-inbox.jpg', 'Desktop inbox', '1440 x 1000'],
  ['mobile-inbox.jpg', 'Mobile inbox', '390 x 844'],
];
if (frames.every(([file]) => fs.existsSync(path.join(__dirname, file)))) {
  const cards = frames.map(([file, title, size]) => {
    const image = fs.readFileSync(path.join(__dirname, file)).toString('base64');
    return `<section><h2>${title}</h2><p>${size}</p><img alt="${title}" src="data:image/jpeg;base64,${image}"></section>`;
  }).join('');
  fs.writeFileSync(path.join(__dirname, 'review.html'), `<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Nakpanel Notification Mockups</title><style>
*{box-sizing:border-box;letter-spacing:0}body{margin:0;background:#f5f7fa;color:#202936;font:14px/1.5 system-ui,sans-serif}header{padding:28px 24px;background:white;border-bottom:1px solid #e0e5ed}h1{font-size:24px;margin:0 0 8px}header p{margin:0 0 12px;color:#526176}a{color:#245ce8}main{padding:24px;display:grid;grid-template-columns:minmax(0,1fr) 390px;gap:28px;align-items:start}h2{font-size:16px;margin:0}section p{font-size:12px;margin:4px 0 12px;color:#526176}img{display:block;width:100%;height:auto;border:1px solid #e0e5ed;border-radius:6px}@media(max-width:900px){main{grid-template-columns:minmax(0,1fr)}section:nth-child(even){max-width:390px}}
</style><header><h1>Compact Notifications</h1><p>Desktop and mobile design review. Fictional data, no live API calls or persistent changes.</p><a href="mockup.html?view=preview">Open interactive mockup</a> &middot; <a href="mockup.html?view=inbox">Open full inbox</a></header><main>${cards}</main></html>`);
  console.log('Built screenshot review gallery.');
}
