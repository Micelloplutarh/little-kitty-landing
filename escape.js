/**
 * escape.js — побег из встроенных браузеров (Instagram / TikTok / Facebook → Safari / Chrome)
 *
 * Один файл вместо связки kitty: inapp-escape-early.js + redirect-config.js +
 * inapp-escape-go.js + inapp-redirect.js.
 *
 * Как работает:
 *  - обычный браузер → скрипт молчит;
 *  - встроенный браузер → лендинг скрывается (html.ie-inapp) и идёт автопобег
 *    с повторами на 0 / 350 / 900 мс. На iOS схема уходит декларативным meta refresh:
 *    скриптовый location.href на кастомной схеме в приложениях Meta молча режется;
 *  - первый тап по странице (не по ссылке) — повторный побег по жесту
 *    (Instagram iOS 417+ пропускает схемы только по жесту);
 *  - через 2,5 с, если побег не сработал, — лендинг показывается обратно и
 *    снизу появляется плашка «Open in Safari» с кнопкой (побег по жесту),
 *    чтобы человек не застрял на пустом экране; на время побега виден фон страницы;
 *  - Instagram iOS 417+ — лендинг не скрывается, плашка показывается сразу
 *    (автопобег там режется, ждать 2,5 с незачем);
 *  - ?no-redirect=1 — отключить всё, ?debug=1 — лог шагов в консоль;
 *  - ?esc=1 — метка Android-фолбэка (Chrome не открылся): побег не повторяется,
 *    чтобы страница не зациклилась;
 *  - побег ведёт на текущий адрес (путь и UTM сохраняются), оставшиеся попытки
 *    отменяются, как только страница скрылась.
 *
 * Подключение: <script src="escape.js"></script> синхронно в <head>.
 * Открыть произвольный URL во внешнем браузере из кода страницы:
 *   window.__ESCAPE__.openInBrowser(url)
 *
 * v1.2 — 2026-10-02
 */
(function () {
  'use strict';

  var w = window;
  var d = document;

  var qs = w.location.search || '';
  // esc=1 — сюда вернул Android-фолбэк (Chrome не открылся): повторный побег зациклит страницу.
  var DISABLED = /[?&](no-redirect|esc)=1/.test(qs);
  var DEBUG = /[?&]debug=1/.test(qs);

  function log() {
    if (!DEBUG) return;
    try {
      w.console.log.apply(w.console, ['[escape]'].concat([].slice.call(arguments)));
    } catch (e) { }
  }

  // ── Детект по User-Agent ──
  var ua = navigator.userAgent || '';
  var isIOS = /iPhone|iPad|iPod/i.test(ua);
  var isAndroid = /Android/i.test(ua);
  var isIG = /Instagram|IABMV/i.test(ua);
  var isBarcelona = /Barcelona/i.test(ua); // Threads
  var isFB = /FBAN|FBAV|FB_IAB|FB4A|FBIOS|Messenger/i.test(ua);
  var isTT = /TikTok|musical_ly|BytedanceWebview/i.test(ua);
  var hasTelegramBridge = !!(w.TelegramWebviewProxy || (w.Telegram && w.Telegram.WebApp));
  var isIOSWebView =
    isIOS && /AppleWebKit/i.test(ua) && !/Safari/i.test(ua) && !/CriOS|FxiOS|EdgiOS|OPiOS/i.test(ua);

  var IN_APP =
    isIG || isFB || isTT || isBarcelona ||
    /Snapchat|WeChat|Line|Pinterest|Twitter/i.test(ua) ||
    hasTelegramBridge ||
    (isAndroid && /; wv\)/i.test(ua)) ||
    isIOSWebView;

  var api = {
    inApp: IN_APP,
    canEscape: IN_APP && !DISABLED,
    debug: DEBUG,
    openInBrowser: function () {
      return false;
    },
  };
  w.__ESCAPE__ = api;

  if (!IN_APP) {
    log('обычный браузер — побег не нужен');
    return;
  }
  if (DISABLED) {
    log('?no-redirect=1 — побег выключен');
    return;
  }

  log('in-app', {
    ios: isIOS,
    android: isAndroid,
    ig: isIG,
    barcelona: isBarcelona,
    fb: isFB,
    tt: isTT,
    ua: ua,
  });

  // Instagram iOS 417+ пропускает схемы только по жесту: автопобег там почти наверняка
  // не сработает, поэтому лендинг не прячем и плашку показываем сразу.
  var igVer = parseInt((ua.match(/Instagram (\d+)/) || [])[1], 10) || 0;
  var GESTURE_ONLY = isIOS && isIG && igVer >= 417;

  // Скрываем лендинг на время побега; если он не сработает — вернём через 2,5 с.
  // Фон не трогаем: на время побега виден фон самой страницы, без белой вспышки.
  var html = d.documentElement;
  if (!GESTURE_ONLY) html.className = (html.className + ' ie-inapp').trim();

  var css = d.createElement('style');
  css.id = 'escape-css';
  css.textContent =
    'html.ie-inapp .screen{display:none!important}' +
    '#escape-banner{position:fixed;left:0;right:0;bottom:0;z-index:2147483646;' +
    'padding:12px 14px calc(12px + env(safe-area-inset-bottom));' +
    'background:#111;color:#fff;font:600 14px/1.35 system-ui,-apple-system,sans-serif;' +
    'box-shadow:0 -4px 24px rgba(0,0,0,.35)}' +
    '#escape-banner div{max-width:560px;margin:0 auto;display:flex;gap:10px;align-items:center}' +
    '#escape-banner span{flex:1;text-align:left}' +
    '#escape-banner button{flex:none;border:0;border-radius:8px;padding:10px 16px;' +
    'background:#fff;color:#111;font-weight:700;cursor:pointer}';
  d.head.appendChild(css);

  var origin = w.location.origin || w.location.protocol + '//' + w.location.host;

  // Текущий адрес целиком — с путём и UTM-метками.
  function pageHref() {
    return w.location.href;
  }

  function noProto(u) {
    return u.replace(/^https?:\/\//i, '');
  }

  // Метка esc=1 перед #якорем: по ней вернувшаяся страница не запустит побег снова.
  function withMark(u) {
    var i = u.indexOf('#');
    var base = i < 0 ? u : u.slice(0, i);
    var hash = i < 0 ? '' : u.slice(i);
    return base + (base.indexOf('?') < 0 ? '?' : '&') + 'esc=1' + hash;
  }

  // Список схем-кандидатов: первая — основная, остальные — запасные.
  function schemes(url) {
    var enc = encodeURIComponent(url);
    var np = noProto(url);
    if (isAndroid) {
      // Метим только свою страницу; чужой URL (CTA) отдаём как есть.
      var fb = url.indexOf(origin.replace(/^http:/, 'https:')) === 0 ? withMark(url) : url;
      // #якорь в intent:// недопустим — после # идёт #Intent;…
      return [
        'intent://' + noProto(url.split('#')[0]) +
        '#Intent;scheme=https;package=com.android.chrome;S.browser_fallback_url=' +
        encodeURIComponent(fb) + ';end',
      ];
    }
    if (isIG) return ['instagram://extbrowser/?url=' + enc, 'x-safari-https://' + np];
    if (isBarcelona) return ['barcelona://extbrowser/?url=' + enc, 'x-safari-https://' + np];
    if (isFB) {
      return [
        'x-safari-https://' + np,
        'barcelona://extbrowser/?url=' + enc,
        'googlechrome://navigate?url=' + enc,
      ];
    }
    return ['x-safari-https://' + np, 'googlechrome://navigate?url=' + enc];
  }

  function nav(s, withOpen) {
    log((withOpen ? 'gesture' : 'auto'), '→', s.slice(0, 90));
    if (isAndroid) {
      try {
        w.location.href = s;
      } catch (e) { }
      return;
    }
    // iOS: декларативный meta refresh — скриптовый переход на кастомной схеме Meta режет.
    var m = d.createElement('meta');
    m.setAttribute('http-equiv', 'refresh');
    m.setAttribute('content', '0;url=' + s);
    (d.head || html).appendChild(m);
    if (withOpen) {
      try {
        w.open(s, '_blank');
      } catch (e) { }
    }
  }

  var AUTO_DELAYS = [0, 350, 900];
  var GESTURE_DELAYS = [0, 60, 150];

  // Отложенные попытки. Ушли во внешний браузер (страница скрыта) — гасим остальные,
  // иначе при возврате в приложение замороженные таймеры откроют браузер повторно.
  var timers = [];

  function cancelPending() {
    if (timers.length) log('страница скрыта — отменяю попыток: ' + timers.length);
    timers.forEach(function (t) {
      w.clearTimeout(t);
    });
    timers = [];
  }

  d.addEventListener('visibilitychange', function () {
    if (d.hidden) cancelPending();
  });
  w.addEventListener('pagehide', cancelPending);

  function attempt(s, gesture) {
    if (d.hidden) return;
    nav(s, gesture);
  }

  function run(url, gesture) {
    url = String(url || pageHref()).replace(/^http:/, 'https:');
    var list = schemes(url);
    log('run', { gesture: !!gesture, url: url, schemes: list.length });
    cancelPending();
    if (gesture) {
      // По жесту — каждая схема один раз, первая синхронно, пока жест действует.
      list.forEach(function (s, i) {
        if (i === 0) return attempt(s, true);
        timers.push(w.setTimeout(function () {
          attempt(s, true);
        }, GESTURE_DELAYS[Math.min(i, GESTURE_DELAYS.length - 1)]));
      });
      return;
    }
    AUTO_DELAYS.forEach(function (delay, i) {
      timers.push(w.setTimeout(function () {
        attempt(list[Math.min(i, list.length - 1)], false);
      }, delay));
    });
  }

  api.openInBrowser = function (url) {
    if (!url) return false;
    run(url, true);
    return true;
  };
  w.__ESCAPE__ = api;

  // ── Автопобег ──
  run(pageHref(), false);

  // ── Побег по жесту (первый тап не по ссылке) ──
  var gestureFired = false;

  // Ссылки (CTA) и кнопка плашки запускают побег сами — второй run не нужен.
  function hasOwnHandler(node) {
    while (node && node !== d) {
      if (node.tagName === 'A' || node.id === 'escape-banner') return true;
      node = node.parentNode;
    }
    return false;
  }

  function onGesture(e) {
    if (gestureFired) return;
    if (hasOwnHandler(e.target)) return;
    gestureFired = true;
    log('тап — побег по жесту');
    run(pageHref(), true);
  }

  d.addEventListener('touchend', onGesture, { capture: true, passive: true, once: true });
  d.addEventListener('click', onGesture, { capture: true, passive: true, once: true });

  // ── Фолбэк: 2,5 с — всё ещё внутри? Показываем лендинг + плашку ──
  function showBanner() {
    if (d.getElementById('escape-banner')) return;
    var bar = d.createElement('div');
    bar.id = 'escape-banner';
    bar.setAttribute('role', 'dialog');
    bar.innerHTML =
      '<div><span>Open in Safari for the best experience</span>' +
      '<button type="button">Continue</button></div>';
    (d.body || html).appendChild(bar);
    bar.querySelector('button').addEventListener('click', function (e) {
      if (e.cancelable) e.preventDefault();
      run(pageHref(), true);
    });
  }

  if (GESTURE_ONLY) {
    log('Instagram iOS ' + igVer + ' — побег только по жесту, плашка сразу');
    if (d.body) showBanner();
    else d.addEventListener('DOMContentLoaded', showBanner);
    return;
  }

  w.setTimeout(function () {
    if (d.hidden) {
      log('страница скрыта — побег сработал, фолбэк не нужен');
      return;
    }
    log('2,5 с: всё ещё внутри — показываем лендинг и плашку');
    html.className = html.className.replace(/\bie-inapp\b/g, '').trim();
    showBanner();
  }, 2500);
})();
