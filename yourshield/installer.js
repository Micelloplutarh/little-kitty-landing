(function () {
    'use strict';
    var themeSelect = document.getElementById('theme_mode');
    if (themeSelect) {
        themeSelect.value = document.documentElement.dataset.theme || 'auto';
        themeSelect.addEventListener('change', function () {
            if (themeSelect.value === 'auto') delete document.documentElement.dataset.theme;
            else document.documentElement.dataset.theme = themeSelect.value;
            try { localStorage.setItem('ys_installer_theme', themeSelect.value); } catch (e) {}
        });
    }
    var form = document.getElementById('install-form');
    if (form) {
        var panels = Array.from(form.querySelectorAll('[data-wizard-step]'));
        var next = form.querySelector('[data-next]');
        var back = form.querySelector('[data-back]');
        var markers = document.querySelectorAll('[data-step-marker]');
        function showStep(step, focus) {
            panels.forEach(function (panel) { panel.hidden = panel.dataset.wizardStep !== String(step); });
            markers.forEach(function (marker) {
                if (marker.dataset.stepMarker === String(step)) marker.setAttribute('aria-current', 'step');
                else marker.removeAttribute('aria-current');
            });
            if (focus) {
                var heading = form.querySelector('[data-wizard-step="' + step + '"] h1, [data-wizard-step="' + step + '"] h2');
                if (heading) heading.focus();
            }
        }
        function reveal(field) {
            var panel = field.closest('[data-wizard-step]');
            if (panel) showStep(panel.dataset.wizardStep, false);
            var parent = field.parentElement;
            while (parent && parent !== form) {
                if (parent.tagName === 'DETAILS') parent.open = true;
                if (parent.hidden) parent.hidden = false;
                parent = parent.parentElement;
            }
        }
        document.documentElement.classList.add('js');
        next.parentElement.hidden = false;
        back.hidden = false;
        showStep(1, false);
        next.addEventListener('click', function () {
            var fields = panels[0].querySelectorAll('input, select');
            for (var i = 0; i < fields.length; i++) {
                if (!fields[i].checkValidity()) { fields[i].reportValidity(); return; }
            }
            showStep(2, true);
        });
        back.addEventListener('click', function () { showStep(1, true); });
        form.addEventListener('invalid', function (event) { reveal(event.target); }, true);
        function updateConditionalFields() {
            form.querySelectorAll('[data-visible-when]').forEach(function (field) {
                var condition = field.dataset.visibleWhen.split(':');
                var control = document.getElementById(condition[0]);
                field.hidden = !!control && condition[1].split(',').indexOf(control.value) === -1;
            });
        }
        form.addEventListener('change', updateConditionalFields);
        updateConditionalFields();
        document.querySelectorAll('.error-summary a[href^="#"]').forEach(function (link) {
            link.addEventListener('click', function (event) {
                var field = document.getElementById(link.hash.slice(1));
                if (field) { event.preventDefault(); reveal(field); field.focus(); }
            });
        });
        form.addEventListener('submit', function (event) {
            if (form.dataset.submitting === '1') { event.preventDefault(); return; }
            form.dataset.submitting = '1';
            var button = event.submitter || form.querySelector('[value="install"]');
            if (button) {
                button.setAttribute('aria-disabled', 'true');
                button.textContent = button.dataset.busy || button.textContent;
            }
            form.setAttribute('aria-busy', 'true');
        });
    }
    var errorSummary = document.getElementById('error-summary');
    if (errorSummary) errorSummary.focus();
    window.addEventListener('pageshow', function (event) {
        if (event.persisted) window.location.reload();
    });
})();
