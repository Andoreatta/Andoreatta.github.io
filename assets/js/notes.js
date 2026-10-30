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
        var button = document.createElement('button');
        button.type = 'button';
        button.className = 'notes-copy';
        button.textContent = 'copy';
        button.setAttribute('aria-label', 'Copy code block');
        button.setAttribute('data-pagefind-ignore', '');

        button.addEventListener('click', function () {
            var code = codeElement.innerText;
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

/* Placeholder bar (rendered only on pages with `phVars = true`).
   Chroma splits some tokens across spans — `\\<ATTACKER>\share` becomes three
   spans — so placeholders are normalised into one .ph span first. Substitution
   then only ever assigns textContent, never innerHTML. */
(function () {
    'use strict';

    var form = document.querySelector('.ph-vars');
    if (!form) {
        return;
    }

    var STORAGE_KEY = 'srl-ph-vars';
    var NAMES = ['IP', 'ATTACKER', 'LPORT', 'DOMAIN', 'DC', 'USER', 'PASS', 'WORDLIST', 'DIRLIST', 'VHOSTLIST', 'USERS', 'PORTS'];
    var TOKEN = new RegExp('<(' + NAMES.join('|') + ')>');
    var inputs = {};
    var spans = [];

    form.querySelectorAll('input[data-ph]').forEach(function (input) {
        inputs[input.getAttribute('data-ph')] = input;
    });

    function blocks() {
        return Array.prototype.slice.call(
            document.querySelectorAll('.notes-article .content pre')
        );
    }

    function findMatch(root) {
        var walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null);
        var nodes = [];
        var node;

        while ((node = walker.nextNode())) {
            if (node.parentNode && node.parentNode.closest && node.parentNode.closest('.ph')) {
                continue;
            }
            nodes.push(node);
        }
        if (!nodes.length) {
            return null;
        }

        var text = '';
        nodes.forEach(function (n) {
            text += n.nodeValue;
        });

        var found = TOKEN.exec(text);
        if (!found) {
            return null;
        }

        var start = found.index;
        var end = start + found[0].length;
        var first = null;
        var last = null;
        var acc = 0;

        for (var i = 0; i < nodes.length; i++) {
            var length = nodes[i].nodeValue.length;
            if (!first && start < acc + length) {
                first = { node: nodes[i], offset: start - acc };
            }
            if (end <= acc + length) {
                last = { node: nodes[i], offset: end - acc };
                break;
            }
            acc += length;
        }

        if (!first || !last) {
            return null;
        }

        return { name: found[1], start: first, end: last };
    }

    function wrap(match) {
        var range = document.createRange();
        var span = document.createElement('span');
        var fragment;

        range.setStart(match.start.node, match.start.offset);
        range.setEnd(match.end.node, match.end.offset);
        fragment = range.extractContents();

        span.className = 'ph';
        span.setAttribute('data-ph', match.name);
        span.setAttribute('data-orig', '<' + match.name + '>');
        span.appendChild(fragment);
        range.insertNode(span);
        spans.push(span);
    }

    blocks().forEach(function (block) {
        var match;
        var guard = 0;

        while ((match = findMatch(block)) && guard < 5000) {
            guard += 1;
            wrap(match);
        }
    });

    function apply() {
        spans.forEach(function (span) {
            var input = inputs[span.getAttribute('data-ph')];
            var value = input ? input.value.trim() : '';
            var text = value || span.getAttribute('data-orig');

            if (span.textContent !== text) {
                span.textContent = text;
            }
        });
    }

    function save() {
        var data = {};

        Object.keys(inputs).forEach(function (name) {
            var value;

            if (name === 'PASS') {
                return;
            }
            value = inputs[name].value.trim();
            if (value) {
                data[name] = value;
            }
        });

        try {
            if (Object.keys(data).length) {
                window.sessionStorage.setItem(STORAGE_KEY, JSON.stringify(data));
            } else {
                window.sessionStorage.removeItem(STORAGE_KEY);
            }
        } catch (error) {
            /* Strict privacy modes can block storage; the form still works. */
        }
    }

    function load() {
        var data;

        try {
            data = JSON.parse(window.sessionStorage.getItem(STORAGE_KEY) || '{}');
        } catch (error) {
            return;
        }

        Object.keys(inputs).forEach(function (name) {
            if (name === 'PASS' || typeof data[name] !== 'string') {
                return;
            }
            inputs[name].value = data[name];
        });
    }

    form.addEventListener('input', function () {
        apply();
        save();
    });

    form.addEventListener('submit', function (event) {
        event.preventDefault();
    });

    Array.prototype.forEach.call(form.querySelectorAll('[data-ph-clear]'), function (button) {
        button.addEventListener('click', function () {
            Object.keys(inputs).forEach(function (name) {
                inputs[name].value = '';
            });
            try {
                window.sessionStorage.removeItem(STORAGE_KEY);
            } catch (error) {
                /* ignore */
            }
            apply();
        });
    });

    load();
    apply();
})();
