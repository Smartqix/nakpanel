const assert = require('node:assert/strict');
const {isIP} = require('node:net');

// Production QA keeps normal certificate verification and DNS. A disposable
// guest override is explicit and restricted to test-domain resolution.
module.exports = function qualificationBrowserConfig(env) {
  const guestIP = env.NAKPANEL_QA_GUEST_IP || '';
  if (guestIP) assert.equal(isIP(guestIP), 4, 'explicit guest IPv4 required');
  const ignoreHTTPSErrors = env.NAKPANEL_QA_IGNORE_HTTPS_ERRORS === '1';
  assert(!ignoreHTTPSErrors || guestIP, 'lab HTTPS override requires explicit guest IP');
  return {
    launch: {channel: 'chrome', headless: true, args: guestIP ? [`--host-resolver-rules=MAP *.test ${guestIP},EXCLUDE localhost`] : []},
    context: {ignoreHTTPSErrors},
  };
};
