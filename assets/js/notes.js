(function () {
    'use strict';

    var content = document.querySelector('.notes-article #content');
    if (!content) {
        return;
    }

    /* Heading permalinks */
    content.querySelectorAll('h2[id], h3[id], h4[id]').forEach(function (heading) {
        var anchor = document.createElement('a');
        anchor.className = 'heading-anchor';
        anchor.href = '#' + heading.id;
        anchor.setAttribute('aria-label', 'Link to this section');
        anchor.setAttribute('data-pagefind-ignore', '');
        anchor.textContent = '#';
        heading.appendChild(anchor);
    });

    /* Copy buttons */
    var copyBlocks = [];
    content.querySelectorAll('.highlight').forEach(function (block) {
        copyBlocks.push(block);
    });
    content.querySelectorAll('pre').forEach(function (pre) {
        if (!pre.closest('.highlight')) {
            copyBlocks.push(pre);
        }
    });

    copyBlocks.forEach(function (block) {
        var codeElement = block.querySelector('code') || block;
        var code = codeElement.innerText;
        var button = document.createElement('button');
        button.type = 'button';
        button.className = 'notes-copy';
        button.textContent = 'copy';
        button.setAttribute('aria-label', 'Copy code block');
        button.setAttribute('data-pagefind-ignore', '');

        button.addEventListener('click', function () {
            var done = function () {
                button.textContent = 'copied';
                window.setTimeout(function () {
                    button.textContent = 'copy';
                }, 1500);
            };

            if (navigator.clipboard && window.isSecureContext) {
                navigator.clipboard.writeText(code).then(done).catch(function () {});
                return;
            }

            var textarea = document.createElement('textarea');
            textarea.value = code;
            textarea.setAttribute('readonly', '');
            textarea.style.position = 'absolute';
            textarea.style.left = '-9999px';
            document.body.appendChild(textarea);
            textarea.select();
            try {
                document.execCommand('copy');
                done();
            } finally {
                document.body.removeChild(textarea);
            }
        });

        if (block.tagName === 'PRE') {
            var wrapper = document.createElement('div');
            wrapper.className = 'notes-code-wrap';
            block.parentNode.insertBefore(wrapper, block);
            wrapper.appendChild(block);
            wrapper.appendChild(button);
        } else {
            block.appendChild(button);
        }
    });

    /* Keyboard access for horizontally scrollable code blocks */
    content.querySelectorAll('.chroma, pre, pre code').forEach(function (block) {
        var style = window.getComputedStyle(block);
        var scrolls = style.overflowX === 'auto' || style.overflowX === 'scroll';
        if (scrolls && block.scrollWidth > block.clientWidth + 1) {
            block.tabIndex = 0;
        }
    });

    /* Accessible, persistent checklist state */
    var storageKey = 'srl-notes-checklist:' + window.location.pathname;
    var saved = {};
    try {
        saved = JSON.parse(window.localStorage.getItem(storageKey) || '{}');
    } catch (error) {
        saved = {};
    }

    content.querySelectorAll('input[type="checkbox"]').forEach(function (box, index) {
        var item = box.closest('li');
        if (item) {
            var label = item.textContent.replace(/\s+/g, ' ').trim();
            if (label) {
                box.setAttribute('aria-label', label.slice(0, 180));
            }
        }

        var key = 'task-' + index;
        box.id = box.id || 'notes-' + key;
        if (saved[key]) {
            box.checked = true;
        }

        box.addEventListener('change', function () {
            saved[key] = box.checked;
            try {
                window.localStorage.setItem(storageKey, JSON.stringify(saved));
            } catch (error) {
                /* Storage can be unavailable in strict privacy modes. */
            }
        });
    });
})();
