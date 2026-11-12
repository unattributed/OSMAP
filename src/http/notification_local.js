(() => {
  'use strict';
  const panel = document.getElementById('osmap-notification-browser');
  if (!panel) return;
  const status = document.getElementById('notification-browser-status');
  const desktopEnable = document.getElementById('notification-desktop-enable');
  const desktopDisable = document.getElementById('notification-desktop-disable');
  const soundEnable = document.getElementById('notification-sound-enable');
  const soundDisable = document.getElementById('notification-sound-disable');
  const keys = ['new_mail', 'mentions', 'openpgp', 'submission', 'sound', 'desktop'];
  const kinds = new Set(['session_issued', 'session_revoked', 'password_changed', 'totp_changed',
    'recovery_requested', 'recovery_completed', 'recovery_contact_requested', 'recovery_contact_changed', 'public_key_imported',
    'public_key_removed', 'personal_key_imported', 'personal_key_unlocked', 'personal_key_locked',
    'policy_changed', 'new_mail', 'mention', 'submission_accepted', 'submission_unknown', 'scheduled_blocked', 'scheduled_saved', 'scheduled_cancelled']);
  let scope = null;
  let choices = null;
  let revision = null;
  let baseline = false;
  let stopped = false;
  let seen = new Set();
  let controller = null;
  let timer = null;
  let inflight = false;
  let audio = null;
  let local = {desktop: false, sound: false};
  let storageAvailable = true;
  let sourcesAvailable = true;
  let lastMessage = status.textContent;

  function say(text) {
    lastMessage = text;
    status.textContent = text + (sourcesAvailable ? '' : ' New mail or scheduled updates could not be refreshed; retained notices are shown.');
  }
  function storageKey() { return 'osmap.notification.browser.v1.' + scope; }
  function saveLocal() {
    try { localStorage.setItem(storageKey(), JSON.stringify(local)); }
    catch (_) { storageAvailable = false; }
  }
  function loadLocal() {
    local = {desktop: false, sound: false};
    try {
      const raw = localStorage.getItem(storageKey());
      if (!raw) return;
      const value = JSON.parse(raw);
      if (exact(value, ['desktop', 'sound']) && typeof value.desktop === 'boolean' && typeof value.sound === 'boolean') {
        local = value;
      }
    } catch (_) { storageAvailable = false; }
  }
  function exact(value, names) {
    return value !== null && typeof value === 'object' && !Array.isArray(value) &&
      Object.keys(value).length === names.length && names.every(name => Object.prototype.hasOwnProperty.call(value, name));
  }
  function valid(value) {
    if (!exact(value, ['version', 'scope', 'preference_revision', 'choices', 'events', 'status', 'sources_available']) ||
        value.version !== 1 || value.status !== 'ok' || typeof value.scope !== 'string' || !/^[0-9a-f]{64}$/.test(value.scope) ||
        typeof value.sources_available !== 'boolean' ||
        !Number.isSafeInteger(value.preference_revision) || value.preference_revision < 0 ||
        !exact(value.choices, keys) || !keys.every(name => typeof value.choices[name] === 'boolean') ||
        !Array.isArray(value.events) || value.events.length > 200) return false;
    const ids = new Set();
    return value.events.every(event => {
      if (!exact(event, ['event_id', 'kind', 'occurred_at', 'read']) || typeof event.read !== 'boolean' ||
          typeof event.event_id !== 'string' || !/^[0-9a-f]{32}$/.test(event.event_id) || !kinds.has(event.kind) ||
          !Number.isSafeInteger(event.occurred_at) || event.occurred_at < 0 || ids.has(event.event_id)) return false;
      ids.add(event.event_id);
      return true;
    });
  }
  function closeAudio() {
    if (audio) audio.close().catch(() => {});
    audio = null;
  }
  function stop(text, forget) {
    stopped = true;
    clearTimeout(timer);
    if (controller) controller.abort();
    closeAudio();
    if (forget && scope) {
      try { localStorage.removeItem(storageKey()); } catch (_) {}
    }
    for (const button of [desktopEnable, desktopDisable, soundEnable, soundDisable]) button.disabled = true;
    if (text) say(text);
  }
  function availability() {
    desktopEnable.disabled = stopped || !scope || !choices.desktop;
    desktopDisable.disabled = stopped || !scope;
    soundEnable.disabled = stopped || !scope || !choices.sound;
    soundDisable.disabled = stopped || !scope;
    if (!choices.desktop && !choices.sound) {
      say('Browser delivery is off in your saved account preferences. Enable a channel above and save before enabling this browser.');
    } else if (!storageAvailable) {
      say('Browser preference storage is unavailable. Your explicit choices last only on this open page.');
    } else {
      const desktopState = !local.desktop ? 'off here' : (!('Notification' in window) ? 'unsupported here' :
        (Notification.permission === 'granted' ? 'enabled here with permission' : 'permission not granted'));
      say('Browser choices loaded. Desktop: ' + desktopState +
        '. Sound: ' + (local.sound ? 'click Enable sound to activate on this page' : 'off here') +
        '. No existing notices were announced.');
    }
  }
  desktopEnable.addEventListener('click', async event => {
    if (!event.isTrusted || stopped || !scope || !choices.desktop) return;
    if (!window.isSecureContext || !('Notification' in window)) {
      say('Desktop notifications are unsupported in this browser or context. The in-app inbox remains available.');
      return;
    }
    try {
      const permission = await Notification.requestPermission();
      if (stopped || document.hidden || !choices.desktop) return;
      local.desktop = permission === 'granted';
      saveLocal();
      say(local.desktop ? 'Desktop notices enabled for this account in this browser. Your platform controls whether requests are displayed.' :
        'Desktop permission was not granted. Nothing was enabled; the in-app inbox remains available.');
    } catch (_) { say('Desktop permission could not be requested. Nothing was enabled.'); }
  });
  desktopDisable.addEventListener('click', () => {
    if (stopped || !scope) return;
    local.desktop = false; saveLocal(); say('Desktop notices disabled for this account in this browser.');
  });
  soundEnable.addEventListener('click', async event => {
    if (!event.isTrusted || stopped || !scope || !choices.sound) return;
    const Audio = window.AudioContext || window.webkitAudioContext;
    if (!Audio) { say('Sound is unsupported in this browser. The in-app inbox remains available.'); return; }
    try {
      if (!audio) audio = new Audio();
      await audio.resume();
      if (stopped || document.hidden) { closeAudio(); return; }
      local.sound = audio.state === 'running'; saveLocal();
      say(local.sound ? 'Sound activated for new notices on this page. Device volume and output control whether it is heard.' :
        'The browser did not activate audio. Sound remains unavailable on this page.');
    } catch (_) { closeAudio(); say('Audio could not be activated. No sound was requested.'); }
  });
  soundDisable.addEventListener('click', () => {
    if (stopped || !scope) return;
    local.sound = false; saveLocal(); closeAudio(); say('Sound disabled for this account in this browser.');
  });
  function announce() {
    if (stopped || document.hidden) return;
    const outcomes = [];
    if (choices.desktop && local.desktop) {
      if (!('Notification' in window) || Notification.permission !== 'granted') {
        outcomes.push('Desktop permission is unavailable; no desktop request was made.');
      } else {
        try {
          const notice = new Notification('OSMAP', {body: 'A new account notification is available. Open OSMAP notifications to review it.', tag: 'osmap-account-notification'});
          notice.onclick = () => { notice.close(); window.focus(); };
          outcomes.push('Desktop notification requested. Your platform controls its display.');
        } catch (_) { outcomes.push('The desktop notification request failed.'); }
      }
    }
    if (choices.sound && local.sound) {
      if (!audio || audio.state !== 'running') {
        outcomes.push('Click Enable sound to activate audio on this page.');
      } else {
        try {
          const oscillator = audio.createOscillator();
          const gain = audio.createGain();
          oscillator.frequency.value = 660;
          gain.gain.setValueAtTime(0.08, audio.currentTime);
          gain.gain.exponentialRampToValueAtTime(0.001, audio.currentTime + 0.15);
          oscillator.connect(gain); gain.connect(audio.destination);
          oscillator.onended = () => { oscillator.disconnect(); gain.disconnect(); };
          oscillator.start(); oscillator.stop(audio.currentTime + 0.15);
          outcomes.push('Audio requested. Device output controls whether it is heard.');
        } catch (_) { outcomes.push('The audio request failed.'); }
      }
    }
    if (outcomes.length) say(outcomes.join(' '));
  }
  async function poll() {
    if (stopped || document.hidden || inflight) return;
    inflight = true;
    controller = new AbortController();
    const current = controller;
    const timeout = setTimeout(() => current.abort(), 5000);
    try {
      const response = await fetch('/notifications/updates', {
        method: 'GET', credentials: 'same-origin', redirect: 'error', cache: 'no-store',
        headers: {Accept: 'application/json'}, signal: current.signal
      });
      if (stopped || document.hidden) return;
      if (response.status === 401 || response.status === 403) {
        stop('Authorization ended. Browser delivery stopped; sign in and open Notifications again.', true); return;
      }
      if (response.redirected || new URL(response.url).origin !== location.origin || new URL(response.url).pathname !== '/notifications/updates') {
        stop('The account response changed. Browser delivery stopped.', true); return;
      }
      if (!response.ok) { say('Notification updates are unavailable. No new browser alert was requested.'); return; }
      const value = await response.json();
      if (stopped || document.hidden) return;
      if (!valid(value)) { stop('Notification update data was not accepted. Browser delivery stopped.', false); return; }
      if (scope !== null && scope !== value.scope) { stop('The signed-in account changed. Browser delivery stopped.', true); return; }
      sourcesAvailable = value.sources_available;
      say(lastMessage);
      const first = scope === null;
      if (first) { scope = value.scope; loadLocal(); }
      const changed = revision !== null && revision !== value.preference_revision;
      choices = value.choices;
      revision = value.preference_revision;
      const rebaseline = !baseline;
      const fresh = baseline && !changed && value.events.some(event => !event.read && !seen.has(event.event_id));
      for (const event of value.events) seen.add(event.event_id);
      const retained = new Set(value.events.map(event => event.event_id));
      for (const id of seen) {
        if (seen.size <= 1000) break;
        if (!retained.has(id)) seen.delete(id);
      }
      baseline = true;
      if (first || changed || rebaseline) availability();
      if (fresh) announce();
    } catch (error) {
      if (!stopped && !document.hidden) {
        if (error.name === 'AbortError') say('Notification updates timed out. No new browser alert was requested.');
        else stop('Notification connection ended or redirected. Browser delivery stopped; reload Notifications to reconnect.', false);
      }
    } finally {
      clearTimeout(timeout);
      if (controller === current) controller = null;
      inflight = false;
      if (!stopped && !document.hidden) {
        clearTimeout(timer);
        timer = setTimeout(poll, 30000);
      }
    }
  }
  document.addEventListener('visibilitychange', () => {
    clearTimeout(timer);
    if (document.hidden) {
      baseline = false;
      if (controller) controller.abort();
      closeAudio();
      say('Browser delivery paused while this page is hidden. Sound needs activation again when you return.');
    } else if (!stopped) {
      // Resuming also establishes a baseline; hidden-page backlog is not announced.
      baseline = false;
      timer = setTimeout(poll, 30000);
    }
  });
  document.addEventListener('submit', event => {
    if (event.target instanceof HTMLFormElement && new URL(event.target.action, location.href).pathname === '/logout') {
      stop('Signed out. Browser notification choices cleared.', true);
    }
  }, true);
  window.addEventListener('pagehide', () => stop(null, false));
  window.addEventListener('pageshow', event => {
    if (event.persisted) stop('This restored page is paused. Reload Notifications to reconnect; no alert was requested.', false);
  });
  if (!document.hidden) poll();
})();
