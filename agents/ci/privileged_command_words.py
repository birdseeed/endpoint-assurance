"""Find every command word in a bash script, for the PAT-2398 static guard.

Test instrumentation only. Never imported or packaged by endpoint scripts.

A root-run installer must not let the caller's PATH choose a tool, so every
command word has to be a shell builtin, a function the script defines, or a
fixed absolute system path. Checking that needs the command words themselves:
the first word of every simple command, wherever it sits (function bodies,
pipelines, && and || chains, case arms, subshells, command substitutions nested
in words, quotes, assignments and here-strings).

This is not a general shell parser. It understands the constructs the macOS
installer scripts use and raises ShellScanError on anything else (backticks,
process substitution, `function`, an unterminated quote or here-document),
because a construct the scanner cannot read is one the guard cannot vouch for.
"""
import re

KEYWORDS_BEFORE_COMMAND = {"if", "then", "elif", "else", "do", "while", "until", "!", "{"}
KEYWORDS_CLOSING = {"fi", "done", "}"}
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\[[^\]]*\])?\+?=")
ARRAY_OPEN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\+?=$")
NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")
SPECIAL_PARAMETERS = "#?!$@*-0123456789"


class ShellScanError(Exception):
    """The script uses a construct this scanner does not understand."""


class Command:
    """One simple command: its command word, arguments and here-documents."""

    def __init__(self, line, word, arguments, heredocs):
        self.line, self.word, self.arguments, self.heredocs = line, word, arguments, heredocs

    def __repr__(self):
        return "Command(line %d: %s)" % (self.line, " ".join([self.word] + self.arguments))


class Heredoc:
    def __init__(self, delimiter, literal, strip_tabs):
        self.delimiter, self.literal, self.strip_tabs = delimiter, literal, strip_tabs
        self.body = None


class _Lexer:
    """Characters to tokens. Command substitutions become their own regions."""

    def __init__(self, text):
        self.text, self.pos = text, 0
        self.regions = []
        self.pending = []

    def line(self, pos=None):
        return self.text.count("\n", 0, self.pos if pos is None else pos) + 1

    def fail(self, message):
        raise ShellScanError("line %d: %s" % (self.line(), message))

    def peek(self, offset=0):
        index = self.pos + offset
        return self.text[index] if index < len(self.text) else ""

    # -- regions -------------------------------------------------------------
    def region(self, closer):
        """Tokens up to EOF, or up to the unmatched ')' ending a substitution."""
        tokens, depth = [], 0
        while True:
            char = self.peek()
            if not char:
                if closer:
                    self.fail("unterminated command substitution")
                if self.pending:
                    self.fail("unterminated here-document")
                return tokens
            if char in " \t":
                self.pos += 1
            elif char == "\\" and self.peek(1) == "\n":
                self.pos += 2
            elif char == "\n":
                self.pos += 1
                tokens.append(("NEWLINE", "\n", self.line() - 1))
                self.read_heredoc_bodies()
            elif char == "#":
                while self.peek() and self.peek() != "\n":
                    self.pos += 1
            elif char == ";":
                width = 2 if self.peek(1) == ";" else 1
                tokens.append(("OP", self.text[self.pos:self.pos + width], self.line()))
                self.pos += width
            elif char == "&":
                if self.peek(1) == ">":
                    self.fail("unsupported redirection &>")
                width = 2 if self.peek(1) == "&" else 1
                tokens.append(("OP", self.text[self.pos:self.pos + width], self.line()))
                self.pos += width
            elif char == "|":
                if self.peek(1) == "&":
                    self.fail("unsupported pipe |&")
                width = 2 if self.peek(1) == "|" else 1
                tokens.append(("OP", self.text[self.pos:self.pos + width], self.line()))
                self.pos += width
            elif char == "(":
                depth += 1
                tokens.append(("OP", "(", self.line()))
                self.pos += 1
            elif char == ")":
                if closer and depth == 0:
                    self.pos += 1
                    return tokens
                depth = max(0, depth - 1)
                tokens.append(("OP", ")", self.line()))
                self.pos += 1
            elif char in "<>":
                self.redirection(tokens)
            else:
                start = self.pos
                digits = 0
                while self.peek(digits).isdigit():
                    digits += 1
                if digits and self.peek(digits) and self.peek(digits) in "<>":
                    self.pos += digits
                    self.redirection(tokens)
                    continue
                line = self.line()
                word = self.word()
                if NAME.match(word) and self.text.startswith("()", self.pos):
                    self.pos += 2
                    tokens.append(("FUNCTION", word, line))
                else:
                    if self.pos == start:
                        self.fail("cannot read a word at %r" % self.peek())
                    tokens.append(("WORD", word, line))

    def redirection(self, tokens):
        if self.peek() == "<" and self.peek(1) == "(" or self.peek() == ">" and self.peek(1) == "(":
            self.fail("unsupported process substitution")
        if self.text.startswith("<<<", self.pos):
            self.pos += 3
            self.skip_blanks()
            self.word()
            return
        if self.text.startswith("<<", self.pos):
            self.pos += 2
            strip_tabs = self.peek() == "-"
            if strip_tabs:
                self.pos += 1
            self.skip_blanks()
            raw = self.word()
            if not raw:
                self.fail("here-document without a delimiter")
            literal = any(mark in raw for mark in "'\"\\")
            heredoc = Heredoc(re.sub(r"['\"\\]", "", raw), literal, strip_tabs)
            self.pending.append(heredoc)
            tokens.append(("HEREDOC", heredoc, self.line()))
            return
        while self.peek() and self.peek() in "<>|":
            self.pos += 1
        if self.peek() == "&":
            self.pos += 1
        self.skip_blanks()
        if not self.word():
            self.fail("redirection without a target")

    def skip_blanks(self):
        while self.peek() and self.peek() in " \t":
            self.pos += 1

    def read_heredoc_bodies(self):
        for heredoc in self.pending:
            lines = []
            while True:
                if self.pos >= len(self.text):
                    self.fail("unterminated here-document " + heredoc.delimiter)
                end = self.text.find("\n", self.pos)
                end = len(self.text) if end < 0 else end
                line = self.text[self.pos:end]
                self.pos = min(len(self.text), end + 1)
                if (line.lstrip("\t") if heredoc.strip_tabs else line) == heredoc.delimiter:
                    break
                lines.append(line)
            heredoc.body = "\n".join(lines)
        self.pending = []

    # -- words ---------------------------------------------------------------
    def word(self):
        start = self.pos
        while True:
            char = self.peek()
            if not char or char in " \t\n;&|()<>":
                if char == "(" and ARRAY_OPEN.match(self.text[start:self.pos]):
                    self.array()
                    continue
                break
            if char == "\\":
                self.pos += 2
            elif char == "'":
                self.single_quoted()
            elif char == '"':
                self.double_quoted()
            elif char == "`":
                self.fail("unsupported backtick command substitution")
            elif char == "$":
                self.dollar()
            else:
                self.pos += 1
        return self.text[start:self.pos]

    def array(self):
        self.pos += 1
        while True:
            char = self.peek()
            if not char:
                self.fail("unterminated array assignment")
            if char == ")":
                self.pos += 1
                return
            if char in " \t\n":
                self.pos += 1
            elif char == "#":
                # A comment between elements (only at the start of a word).
                while self.peek() and self.peek() != "\n":
                    self.pos += 1
            elif char in ";&|(<>":
                self.fail("unexpected %r in an array assignment" % char)
            elif not self.word():
                self.fail("cannot read an array element")

    def single_quoted(self):
        end = self.text.find("'", self.pos + 1)
        if end < 0:
            self.fail("unterminated single quote")
        self.pos = end + 1

    def double_quoted(self):
        self.pos += 1
        while True:
            char = self.peek()
            if not char:
                self.fail("unterminated double quote")
            if char == '"':
                self.pos += 1
                return
            if char == "\\":
                self.pos += 2
            elif char == "`":
                self.fail("unsupported backtick command substitution")
            elif char == "$":
                self.dollar()
            else:
                self.pos += 1

    def dollar(self):
        following = self.peek(1)
        if following == "'":
            self.pos += 2
            while True:
                char = self.peek()
                if not char:
                    self.fail("unterminated $'...' quote")
                self.pos += 2 if char == "\\" else 1
                if char == "'":
                    return
        elif self.text.startswith("$((", self.pos):
            self.pos += 3
            depth = 2
            while depth:
                char = self.peek()
                if not char:
                    self.fail("unterminated arithmetic expansion")
                if char in "`":
                    self.fail("unsupported backtick command substitution")
                if char == "$" and self.peek(1) == "(" and self.peek(2) != "(":
                    self.dollar()
                    continue
                depth += (char == "(") - (char == ")")
                self.pos += 1
        elif following == "(":
            self.pos += 2
            self.regions.append(self.region(")"))
        elif following == "{":
            self.pos += 2
            while True:
                char = self.peek()
                if not char:
                    self.fail("unterminated parameter expansion")
                if char == "}":
                    self.pos += 1
                    return
                if char == "\\":
                    self.pos += 2
                elif char == "'":
                    self.single_quoted()
                elif char == '"':
                    self.double_quoted()
                elif char == "`":
                    self.fail("unsupported backtick command substitution")
                elif char == "$":
                    self.dollar()
                else:
                    self.pos += 1
        elif following and following in SPECIAL_PARAMETERS:
            self.pos += 2
        else:
            self.pos += 1


def _commands(tokens, commands, functions):
    """Walk one region's tokens, collecting command words and function names."""
    index, case_stack = 0, []
    separators = {";", "&&", "||", "|", "&", "(", ")", ";;"}

    def kind(offset=0):
        return tokens[index + offset][0] if index + offset < len(tokens) else "END"

    def value(offset=0):
        return tokens[index + offset][1] if index + offset < len(tokens) else ""

    while index < len(tokens):
        token_kind, token, line = tokens[index]
        if case_stack and case_stack[-1] == "pattern":
            if token_kind == "NEWLINE":
                index += 1
                continue
            if token_kind == "WORD" and token == "esac":
                case_stack.pop()
                index += 1
                continue
            # A pattern list runs to its closing ')'; an optional '(' may open it.
            if token_kind == "OP" and token == "(":
                index += 1
            while not (kind() == "OP" and value() == ")"):
                if kind() in ("END", "NEWLINE", "HEREDOC", "FUNCTION") or (
                        kind() == "OP" and value() != "|"):
                    raise ShellScanError("line %d: unreadable case pattern" % line)
                index += 1
            index += 1
            case_stack[-1] = "body"
            continue
        if token_kind in ("NEWLINE", "HEREDOC"):
            index += 1
            continue
        if token_kind == "OP":
            if token == ";;":
                if not case_stack:
                    raise ShellScanError("line %d: ';;' outside a case" % line)
                case_stack[-1] = "pattern"
            index += 1
            continue
        if token_kind == "FUNCTION":
            functions.add(token)
            index += 1
            continue
        # A word in command position.
        if ASSIGNMENT.match(token):
            index += 1
            continue
        if token in KEYWORDS_BEFORE_COMMAND or token in KEYWORDS_CLOSING:
            index += 1
            continue
        if token == "esac":
            if not case_stack:
                raise ShellScanError("line %d: 'esac' outside a case" % line)
            case_stack.pop()
            index += 1
            continue
        if token == "for":
            index += 1
            while kind() == "WORD":
                index += 1
            continue
        if token == "case":
            if not (kind(1) == "WORD" and kind(2) == "WORD" and value(2) == "in"):
                raise ShellScanError("line %d: unreadable case statement" % line)
            index += 3
            case_stack.append("pattern")
            continue
        if token == "[[":
            while not (kind() == "WORD" and value() == "]]"):
                if kind() == "END":
                    raise ShellScanError("line %d: unterminated [[" % line)
                index += 1
            index += 1
            continue
        if token in ("function", "select", "coproc"):
            raise ShellScanError("line %d: unsupported keyword %s" % (line, token))
        word, arguments, heredocs = token, [], []
        index += 1
        while index < len(tokens):
            token_kind, token, _ = tokens[index]
            if token_kind == "NEWLINE" or (token_kind == "OP" and token in separators):
                break
            if token_kind == "HEREDOC":
                heredocs.append(token)
            elif token_kind == "FUNCTION":
                raise ShellScanError("line %d: function definition inside a command" % line)
            else:
                arguments.append(token)
            index += 1
        commands.append(Command(line, word, arguments, heredocs))
    if case_stack:
        raise ShellScanError("unterminated case statement")


def scan(text):
    """Return (commands, function names) for a bash script's source text."""
    lexer = _Lexer(text)
    top = lexer.region(None)
    commands, functions = [], set()
    for tokens in [top] + lexer.regions:
        _commands(tokens, commands, functions)
    commands.sort(key=lambda command: command.line)
    return commands, functions
