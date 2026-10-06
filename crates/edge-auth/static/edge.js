// Passkey ceremonies for mcp-edge owner pages. No third-party code.
(function () {
  'use strict';

  function b64uToBuf(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    var bin = atob(s);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }

  function bufToB64u(buf) {
    var bytes = new Uint8Array(buf);
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  async function post(url, body) {
    var res = await fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    var data = null;
    try { data = await res.json(); } catch (e) { data = null; }
    if (!res.ok) throw new Error((data && data.error) || ('HTTP ' + res.status));
    return data;
  }

  async function register(enrollCode) {
    var opts = await post('/owner/register/start', enrollCode ? { enroll_code: enrollCode } : {});
    var pk = opts.publicKey;
    pk.challenge = b64uToBuf(pk.challenge);
    pk.user.id = b64uToBuf(pk.user.id);
    if (pk.excludeCredentials) {
      pk.excludeCredentials = pk.excludeCredentials.map(function (c) {
        return { type: c.type, id: b64uToBuf(c.id) };
      });
    }
    var cred = await navigator.credentials.create({ publicKey: pk });
    await post('/owner/register/finish', {
      id: cred.id,
      rawId: bufToB64u(cred.rawId),
      type: cred.type,
      extensions: {},
      response: {
        attestationObject: bufToB64u(cred.response.attestationObject),
        clientDataJSON: bufToB64u(cred.response.clientDataJSON),
        transports: null
      }
    });
  }

  async function login(tx) {
    var opts = await post('/owner/login/start', tx ? { tx: tx } : {});
    var pk = opts.publicKey;
    pk.challenge = b64uToBuf(pk.challenge);
    if (pk.allowCredentials) {
      pk.allowCredentials = pk.allowCredentials.map(function (c) {
        return { type: c.type, id: b64uToBuf(c.id) };
      });
    }
    var cred = await navigator.credentials.get({ publicKey: pk });
    var r = cred.response;
    await post('/owner/login/finish', {
      id: cred.id,
      rawId: bufToB64u(cred.rawId),
      type: cred.type,
      extensions: {},
      response: {
        authenticatorData: bufToB64u(r.authenticatorData),
        clientDataJSON: bufToB64u(r.clientDataJSON),
        signature: bufToB64u(r.signature),
        userHandle: r.userHandle ? bufToB64u(r.userHandle) : null
      }
    });
  }

  function status(text) {
    var el = document.getElementById('status');
    if (el) el.textContent = text;
  }

  // Origin consent: poll the request state every 2 s while the app owner
  // decides, then reload (the page shows the outcome); submit the final
  // redirect form once approved. Without JS the page has Check/Return buttons.
  function pollConsent(el) {
    var tx = el.getAttribute('data-poll');
    var timer = setInterval(async function () {
      try {
        var res = await fetch('/consent/status?tx=' + encodeURIComponent(tx), {
          credentials: 'same-origin',
          cache: 'no-store'
        });
        if (!res.ok) { clearInterval(timer); location.reload(); return; }
        var data = await res.json();
        if (data.state !== 'sent') { clearInterval(timer); location.reload(); }
      } catch (e) { /* keep polling */ }
    }, 2000);
  }

  document.addEventListener('DOMContentLoaded', function () {
    var poll = document.querySelector('[data-poll]');
    if (poll) pollConsent(poll);
    var auto = document.querySelector('form[data-autosubmit]');
    if (auto) auto.submit();
    document.querySelectorAll('[data-action]').forEach(function (btn) {
      btn.addEventListener('click', async function () {
        btn.disabled = true;
        status('Waiting for your passkey...');
        try {
          var action = btn.getAttribute('data-action');
          if (action === 'login') {
            await login(btn.getAttribute('data-tx'));
            location.reload();
          } else if (action === 'enroll') {
            var input = document.getElementById('enroll-code');
            await register(input ? input.value : '');
            if (input) input.value = '';
            status('Passkey registered. You can now sign in at /owner.');
          } else if (action === 'add-passkey') {
            await register(null);
            status('Passkey added.');
          }
        } catch (err) {
          status('Failed: ' + (err && err.message ? err.message : 'unknown error'));
        } finally {
          btn.disabled = false;
        }
      });
    });
  });
})();
