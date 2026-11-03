"""PAT-1000: guard against duplicate top-level `function NAME(...)`
declarations anywhere in templates/console.html's single shared-scope
<script> block.

Why this exists: JS function *declarations* hoist and share one global
scope for the whole ~16.5k-line template (no modules, no bundler, no
per-section closures). If the same name is declared twice at top level, the
later declaration silently wins for every call site — including call sites
that were written against the *other* function's signature/behaviour. This
is exactly what happened here: the device-detail Agent Logs loader
(`function _logsLoad()`, no args, renders into #dd-logs-table) and the
global Logs-page loader (`function _logsLoad(force)`, paginated console log
viewer) were both declared as `_logsLoad` at top level. The global one
declares later in the file, so it always won; every call from
`_logsActivate`/`_logsRequest` reached the wrong function with
`force === undefined`, and the device-detail table never populated. No
exception, no console error -- it just silently rendered nothing.

The fix (this ticket) renames the device-detail loader to `_ddLogsLoad` and
repoints its two call sites. This file is the regression guard: it parses
the real, current `templates/console.html`, extracts every top-level
`function NAME(` DECLARATION in the inline script blocks (nested/indented
function declarations and `var x = function(){}` expressions are
deliberately NOT counted -- see `_top_level_function_declarations` below),
and fails if any name is declared more than once at top level.

Tokenizer notes (why this isn't a naive regex):
  - Must not be fooled by comments, string/template-literal contents, or
    regex literals that happen to contain `{`, `}`, quotes, or `/` (the
    file has all of these -- e.g. `.replace(/"/g, '""')` and
    `` `.../${_eaTenantId}...` `` near the PAT-1000 duplicate itself).
  - Must not flag `(function NAME() { ... })()` (a named IIFE) as a
    top-level declaration -- a named function EXPRESSION's name binds only
    in its own scope, never the enclosing one, so it can't collide with
    anything. `_initMobileNav` in this file is exactly this shape.
  - Must handle `async function NAME(...)` the same as `function NAME(...)`
    -- there are 7 of these in console.html today (adminFetch,
    adminFetchBlob, _eaLoad, _eaLoadMore, _eaFetch, _eaExportCSV,
    _napDecide), and none of them should be treated as unnamed/skipped.
  - Self-checks its own brace bookkeeping (`final_depth == 0`) so a future
    JS construct this tokenizer doesn't understand fails loudly instead of
    silently under-counting.

Validated (2026-07-28) against the current file: extracts exactly 620
top-level declarations (613 `function` + 7 `async function`, matching a
plain `grep -c '^function '` / `grep -c '^async function '` count), balanced
brace depth, and -- before the PAT-1000 rename -- exactly one duplicate:
`_logsLoad` (x2). No OTHER pre-existing duplicate top-level declaration was
found in the file at that time.
"""
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Explicit, commented allow-list for duplicate top-level names that are
# known to exist and are OUT OF SCOPE for the ticket that added this guard.
# Empty today -- PAT-1000's audit of the current file found no duplicate
# other than `_logsLoad` (which this same ticket fixes). If a future finding
# needs to land here, each entry must be paired with a Linear ticket number
# in a comment; do not add entries just to make this test pass silently.
_KNOWN_PRE_EXISTING_DUPLICATE_NAMES = {}  # e.g. {"_someName": "PAT-XXXX"}
# How many declarations each allowed name is known to have. Exceeding this
# fails even if the name is allow-listed.
_KNOWN_PRE_EXISTING_DUPLICATE_COUNTS = {}  # e.g. {"_someName": 2}

_KEYWORDS_BEFORE_REGEX = {
    "return", "typeof", "instanceof", "in", "of", "new", "delete", "void",
    "throw", "case", "do", "else", "yield", "await",
}
_OPERATOR_REGEX_CONTEXT = set("([{,;:=!&|?+-*%^~<>")


def _extract_inline_script_blocks(html_text):
    """Return the text of every inline <script>...</script> block, skipping
    any <script src="..."> that has no inline body to parse."""
    blocks = []
    for m in re.finditer(r"<script\b([^>]*)>(.*?)</script>", html_text, re.DOTALL | re.IGNORECASE):
        attrs = m.group(1)
        if re.search(r"\bsrc\s*=", attrs, re.IGNORECASE):
            continue
        blocks.append(m.group(2))
    return blocks


def _strip_jinja(text):
    """Blank out Jinja {{ ... }}/{% ... %} tokens so stray braces in server-
    side template expressions can't perturb the JS brace-depth count."""
    text = re.sub(r"\{\{.*?\}\}", "JINJAEXPR", text, flags=re.DOTALL)
    text = re.sub(r"\{%.*?%\}", "", text, flags=re.DOTALL)
    return text


def _skip_line_comment(s, i, n):
    j = s.find("\n", i)
    return n if j == -1 else j


def _skip_block_comment(s, i, n):
    j = s.find("*/", i + 2)
    return n if j == -1 else j + 2


def _skip_string(s, i, n, quote):
    """s[i] == quote. Returns the index just past the closing quote."""
    i += 1
    while i < n:
        if s[i] == "\\":
            i += 2
            continue
        if s[i] == quote:
            return i + 1
        i += 1
    return n


def _looks_like_regex_start(last_significant, last_word):
    if last_significant == "":
        return True
    if last_significant in _OPERATOR_REGEX_CONTEXT:
        return True
    if last_word in _KEYWORDS_BEFORE_REGEX:
        return True
    return False


def _try_skip_regex(s, i, n, last_significant, last_word):
    """s[i] == '/'. If the preceding-token context says this looks like a
    regex-literal start (rather than division), scan past it and return the
    index just past the closing '/' + flags. Otherwise return None so the
    caller treats '/' as an ordinary character (division)."""
    if not _looks_like_regex_start(last_significant, last_word):
        return None
    j = i + 1
    in_class = False
    while j < n:
        ch = s[j]
        if ch == "\\":
            j += 2
            continue
        if ch == "\n":
            return None  # real regex literals can't contain a raw newline
        if ch == "[":
            in_class = True
        elif ch == "]":
            in_class = False
        elif ch == "/" and not in_class:
            k = j + 1
            while k < n and s[k].isalpha():
                k += 1
            return k
        j += 1
    return None


def _skip_template_literal(s, i, n):
    """s[i] == '`'. Returns the index just past the matching closing
    backtick, correctly skipping nested `${ ... }` substitutions (which may
    themselves contain strings/nested templates/regex/comments/braces, but
    whose braces must NOT leak into the caller's brace-depth count -- a
    template substitution can only hold an expression, never a top-level
    function declaration)."""
    i += 1
    while i < n:
        c = s[i]
        if c == "\\":
            i += 2
            continue
        if c == "`":
            return i + 1
        if c == "$" and i + 1 < n and s[i + 1] == "{":
            i = _skip_template_substitution(s, i + 2, n)
            continue
        i += 1
    return n


def _skip_template_substitution(s, i, n):
    """Called with i positioned just after the `${`'s opening `{`. Scans the
    expression, honouring nested strings/templates/regex/comments/braces,
    and returns the index just past the matching closing `}`."""
    local_depth = 1
    last_significant = ""
    last_word = ""
    while i < n:
        c = s[i]
        if c == "/" and i + 1 < n and s[i + 1] == "/":
            i = _skip_line_comment(s, i, n)
            continue
        if c == "/" and i + 1 < n and s[i + 1] == "*":
            i = _skip_block_comment(s, i, n)
            continue
        if c in ('"', "'"):
            i = _skip_string(s, i, n, c)
            last_significant = c
            continue
        if c == "`":
            i = _skip_template_literal(s, i, n)
            last_significant = "`"
            continue
        if c == "/":
            new_i = _try_skip_regex(s, i, n, last_significant, last_word)
            if new_i is not None:
                i = new_i
                last_significant = "/"
                continue
        if c == "{":
            local_depth += 1
            last_significant = c
            i += 1
            continue
        if c == "}":
            local_depth -= 1
            i += 1
            if local_depth == 0:
                return i
            last_significant = c
            continue
        if c.isspace():
            i += 1
            continue
        if c.isalpha() or c in "_$":
            j = i
            while j < n and (s[j].isalnum() or s[j] in "_$"):
                j += 1
            last_word = s[i:j]
            last_significant = last_word[-1]
            i = j
            continue
        last_significant = c
        i += 1
    return n


def _top_level_function_declarations(script_text):
    """Tokenize a JS source well enough to find `function NAME(...)` and
    `async function NAME(...)` DECLARATION statements (not expressions like
    `var x = function(){}`, not named IIFEs, not anything inside a template
    substitution) that sit at real top-level brace-depth 0.

    Returns (list of (name, char_offset), final_brace_depth). The caller
    should assert final_brace_depth == 0 as a sanity check on the parse --
    a nonzero value means this tokenizer lost track of something and its
    result list should not be trusted.
    """
    s = script_text
    n = len(s)
    i = 0
    depth = 0
    last_significant = ""
    last_word = ""
    results = []

    while i < n:
        c = s[i]

        if c == "/" and i + 1 < n and s[i + 1] == "/":
            i = _skip_line_comment(s, i, n)
            continue
        if c == "/" and i + 1 < n and s[i + 1] == "*":
            i = _skip_block_comment(s, i, n)
            continue
        if c in ('"', "'"):
            i = _skip_string(s, i, n, c)
            last_significant = c
            continue
        if c == "`":
            i = _skip_template_literal(s, i, n)
            last_significant = "`"
            continue
        if c == "/":
            new_i = _try_skip_regex(s, i, n, last_significant, last_word)
            if new_i is not None:
                i = new_i
                last_significant = "/"
                continue
            # else: falls through, treated as a plain division-operator char

        if c == "{":
            depth += 1
            last_significant = c
            i += 1
            continue
        if c == "}":
            depth -= 1
            last_significant = c
            i += 1
            continue
        if c.isspace():
            i += 1
            continue

        if c.isalpha() or c in "_$":
            j = i
            while j < n and (s[j].isalnum() or s[j] in "_$"):
                j += 1
            word = s[i:j]
            if word == "function" and depth == 0:
                # Whitelist, not blacklist: a top-level function DECLARATION
                # can only start a new statement, so the previous
                # significant token must be a statement boundary --
                # start-of-script, `;`, or `}` (closing the prior
                # block/function/IIFE). This is checked against
                # `last_significant`, the tokenizer's own tracked state --
                # NOT a raw backward text scan, which could land inside a
                # skipped comment and misfire (e.g. a comment ending in a
                # literal '.' would look like `.function`, a method).
                #
                # This correctly excludes `= function` (assignment
                # expression), `.function` (method), `(function NAME(){})()`
                # (named IIFE -- its name binds only in its own scope), and
                # `, function` (argument).
                if last_significant in ("", ";", "}"):
                    k = j
                    while k < n and s[k].isspace():
                        k += 1
                    m = re.match(r"[A-Za-z_$][A-Za-z0-9_$]*", s[k:])
                    if m and s[k + m.end():].lstrip().startswith("("):
                        results.append((m.group(0), k))
            if word == "async":
                # `async function NAME(...)` is one declaration unit -- peek
                # past whitespace; if `function` follows, treat `async` as
                # transparent (don't let it shadow the real preceding token
                # the whitelist check above needs). Otherwise record `async`
                # normally (it's being used as an ordinary identifier).
                k = j
                while k < n and s[k].isspace():
                    k += 1
                if s[k:k + 8] == "function" and (
                    k + 8 == n or not (s[k + 8].isalnum() or s[k + 8] in "_$")
                ):
                    i = j
                    continue
            last_word = word
            last_significant = word[-1]
            i = j
            continue

        last_significant = c
        i += 1

    return results, depth


# KNOWN LIMITS of this extractor, established by adversarial review. It is a
# heuristic tokenizer, not a JS parser, and is deliberately kept simple:
#
#   * Annex B block-level function declarations are NOT treated as top-level.
#     In a non-strict classic script, `if (x) { function f(){} }` can update an
#     outer `f` binding at runtime, so a clash of that shape is a FALSE
#     NEGATIVE here. Accepted: the codebase does not use block-scoped function
#     declarations, and catching them needs real scope analysis.
#   * A regex literal appearing directly after `)` is not recognised, so
#     `if (false) /x; function ghost(){}/.test("")` would FALSE POSITIVE.
#     Accepted: no such construct exists in this file, and a false positive is
#     a loud CI failure rather than a silent miss.
#
# Both directions were checked against the real file, which is clean under this
# extractor. If either shape ever appears, fix the tokenizer rather than
# widening the allow-list.
def find_duplicate_top_level_functions(html_text):
    """Return {name: [offsets]} for every top-level function name declared
    more than once across all inline <script> blocks in html_text, plus the
    total count of declarations found and the list of blocks whose brace
    depth didn't balance to 0 (a parse-trust signal)."""
    from collections import defaultdict

    by_name = defaultdict(list)
    total = 0
    unbalanced_blocks = []
    for idx, block in enumerate(_extract_inline_script_blocks(html_text)):
        block = _strip_jinja(block)
        names, final_depth = _top_level_function_declarations(block)
        if final_depth != 0:
            unbalanced_blocks.append((idx, final_depth))
        for name, offset in names:
            by_name[name].append(offset)
            total += 1
    dupes = {name: offsets for name, offsets in by_name.items() if len(offsets) > 1}
    return dupes, total, unbalanced_blocks


class TestNoDuplicateTopLevelFunctionDeclarations:
    def test_tokenizer_trusts_its_own_brace_bookkeeping(self):
        html = (REPO / "templates" / "console.html").read_text()
        _dupes, _total, unbalanced = find_duplicate_top_level_functions(html)
        assert unbalanced == [], (
            "the duplicate-declaration tokenizer lost track of brace depth in "
            f"script block(s) {unbalanced!r} -- likely a JS construct it "
            "doesn't understand (new regex/template-literal shape); its "
            "results can't be trusted until that's fixed"
        )

    def test_tokenizer_finds_a_healthy_number_of_declarations(self):
        # A silent regression in the extractor (e.g. it starts matching
        # nothing) would make the "no duplicates" assertion below pass
        # vacuously. Pin a floor well below the current count (620) so a
        # real drop is caught but ordinary future additions aren't.
        html = (REPO / "templates" / "console.html").read_text()
        _dupes, total, _unbalanced = find_duplicate_top_level_functions(html)
        assert total > 400, (
            f"only found {total} top-level function declarations -- expected "
            "several hundred; the extractor may be silently failing to parse "
            "the script block"
        )

    def test_no_duplicate_top_level_function_declarations(self):
        html = (REPO / "templates" / "console.html").read_text()
        dupes, _total, _unbalanced = find_duplicate_top_level_functions(html)

        # Suppress by (name, count), not name alone. Allowing a name outright
        # would let a THIRD colliding declaration of an already-known duplicate
        # slip through silently — the allow-list would quietly widen itself,
        # which is precisely the failure mode it exists to prevent.
        unexpected = {
            name: offsets
            for name, offsets in dupes.items()
            if _KNOWN_PRE_EXISTING_DUPLICATE_NAMES.get(name) is None
            or len(offsets) > _KNOWN_PRE_EXISTING_DUPLICATE_COUNTS.get(name, 2)
        }
        assert not unexpected, (
            "templates/console.html declares the same top-level function name "
            "more than once -- function declarations hoist, so the LATER one "
            "silently wins for every caller, including callers written "
            "against the earlier one's signature (this is exactly the "
            "PAT-1000 `_logsLoad` bug). Rename one of each colliding pair, or "
            "add it to _KNOWN_PRE_EXISTING_DUPLICATE_NAMES with a ticket "
            f"reference if it's a deliberate, tracked exception: {unexpected!r}"
        )

    def test_known_pre_existing_duplicates_list_is_still_accurate(self):
        # If an entry is ever added to the allow-list, make sure it's still
        # actually duplicated (otherwise the allow-list is stale and should
        # be removed) -- and still not accidentally covering something new.
        if not _KNOWN_PRE_EXISTING_DUPLICATE_NAMES:
            return
        html = (REPO / "templates" / "console.html").read_text()
        dupes, _total, _unbalanced = find_duplicate_top_level_functions(html)
        for name in _KNOWN_PRE_EXISTING_DUPLICATE_NAMES:
            assert name in dupes, (
                f"{name!r} is in _KNOWN_PRE_EXISTING_DUPLICATE_NAMES but is no "
                "longer duplicated in console.html -- remove it from the "
                "allow-list"
            )
