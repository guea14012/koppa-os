#!/usr/bin/env python3
"""
KOPPA Language Interpreter v3.1 — transpiles .kop to Python and executes.

Syntax:
  let x = v          →  x = v
  fn name(args) {…}  →  def name(args):
  for x in y {…}     →  for x in y:
  if cond {…}        →  if cond:
  if cond {…} else{} →  if cond: … else:
  try {…} catch(e){} →  try: … except Exception as e:
  loop {…}           →  while True:
  x.len()            →  len(x)
  x.len              →  len(x)
  x.push(v)          →  x.append(v)
  x.to_int()         →  int(x)
  x.to_str()         →  str(x)
  x.trim()           →  x.strip()
  x.contains(s)      →  (s in x)
  x.starts_with(s)   →  x.startswith(s)
  x.ends_with(s)     →  x.endswith(s)
  x.chunk(n)         →  [x[i:i+n] for i in range(0,len(x),n)]
  x.to_json()        →  json.dumps(x)
  x.map(fn(v){…})    →  [… for v in x]
  "text {var}"       →  f"text {var}"
  ## comment         →  (skipped)
  __args__[n]        →  safe args access (None if out of range)
  && / ||            →  and / or
"""
import sys, os, re, json, importlib

RUNTIME_DIR = os.path.join(os.path.dirname(__file__), "runtime")

_MODULE_ALIASES = {
    "sys":  "sys_mod",
    "os":   "os_mod",
    "str":  "str_mod",
    "hash": "hash_mod",
    "ssl":  "ssl_mod",
    "time": "time_mod",
}


class _SafeList(list):
    """List that returns None for out-of-range index instead of crashing."""
    def __getitem__(self, idx):
        try:    return list.__getitem__(self, idx)
        except IndexError: return None


def _to_fstring(line):
    """Convert KOPPA string interpolation "text {var}" → f"text {var}"."""
    def _maybe_f(m):
        s = m.group(0)
        if re.search(r'\{[\w][\w.]*\}', s):
            return 'f' + s
        return s
    # Negative lookbehind: skip strings already prefixed with f/b/r/u
    return re.sub(r'(?<![fFbBrRuU])"[^"\n\\]*(?:\\.[^"\n\\]*)*"', _maybe_f, line)


def _fix_expr(expr):
    """Transform KOPPA expression syntax to Python equivalents."""
    expr = expr.strip().rstrip(";")
    # && / || → and / or
    expr = expr.replace(" && ", " and ").replace(" || ", " or ")
    expr = expr.replace("&&", " and ").replace("||", " or ")
    # .len() and .len property → len(x)
    expr = re.sub(r"([\w.\[\]\"']+)\.len\(\)", r"len(\1)", expr)
    expr = re.sub(r"([\w.\[\]\"']+)\.len\b(?!\s*\()", r"len(\1)", expr)
    # .push(v) → .append(v)
    expr = re.sub(r"\.push\(", ".append(", expr)
    # .to_int() / .to_str()
    expr = re.sub(r"([\w.]+)\.to_int\(\)", r"int(\1)", expr)
    expr = re.sub(r"([\w.]+)\.to_str\(\)", r"str(\1)", expr)
    # .trim() → .strip()
    expr = re.sub(r"([\w.]+)\.trim\(\)", r"\1.strip()", expr)
    # .contains(s) → (s in x)  — supports chained access like resp.body.contains(s)
    expr = re.sub(r"([\w.]+)\.contains\((.+?)\)", r"(\2 in \1)", expr)
    # .starts_with / .ends_with
    expr = re.sub(r"([\w.]+)\.starts_with\(", r"\1.startswith(", expr)
    expr = re.sub(r"([\w.]+)\.ends_with\(",   r"\1.endswith(",   expr)
    # .chunk(n)
    expr = re.sub(r"([\w.]+)\.chunk\((\d+)\)",
                  r"[\1[_i:\1[_i+\2]] for _i in range(0,len(\1),\2)]", expr)
    # .to_json() / .from_json()
    expr = re.sub(r"([\w.]+)\.to_json\(\)",   r"json.dumps(\1)",  expr)
    expr = re.sub(r"([\w.]+)\.from_json\(\)", r"json.loads(\1)",  expr)
    # .join(d)
    expr = re.sub(r"([\w.]+)\.join\((.+?)\)", r"\2.join(\1)", expr)
    # .substring(a, b)
    expr = re.sub(r"([\w.]+)\.substring\((\d+),\s*(\d+)\)", r"\1[\2:\3]", expr)
    # f-string conversion on string literals in the expression
    expr = _to_fstring(expr)
    return expr


def _fix_line(line):
    line = line.rstrip(";").rstrip("{")
    # Strip trailing lone } that hasn't been consumed
    line = re.sub(r"\s*\}\s*$", "", line)
    line = _to_fstring(line)
    return _fix_expr(line)


# ── Transpiler ────────────────────────────────────────────────────────────────
def _transpile(source):
    lines = source.splitlines()
    out   = ["import sys as _sys, os as _os, json, re"]
    indent_stack = [0]

    def ind():
        return "    " * (len(indent_stack) - 1)

    for raw in lines:
        stripped = raw.strip()

        # Skip header / standalone comments
        if stripped.startswith("## ") or stripped.startswith("# "):
            continue

        if not stripped:
            out.append(""); continue

        # Closing braces → dedent (handle multiple on same line: } else {)
        while stripped.startswith("}"):
            if len(indent_stack) > 1:
                indent_stack.pop()
            stripped = stripped[1:].strip()
            if not stripped:
                break

        if not stripped:
            continue

        # } catch(err) { — must come before generic } processing
        m = re.match(r"^\}\s*catch\s*\((\w+)\)\s*\{(.*)", raw.strip())
        if m:
            if len(indent_stack) > 1: indent_stack.pop()
            out.append(f"{ind()}except Exception as {m.group(1)}:")
            indent_stack.append(len(indent_stack))
            rest = m.group(2).strip()
            if rest and not rest.endswith("}"):
                out.append("    " * len(indent_stack) + _fix_line(rest))
            continue

        # import
        if re.match(r"^import\s+", stripped):
            names = re.sub(r"^import\s+", "", stripped).split(",")
            for n in [x.strip() for x in names if x.strip()]:
                alias = _MODULE_ALIASES.get(n, n)
                out.append(f"{ind()}import importlib as _il_{n}")
                out.append(f"{ind()}_spec_{n} = _il_{n}.util.spec_from_file_location('{alias}', '{RUNTIME_DIR}/{alias}.py')")
                out.append(f"{ind()}{n} = _il_{n}.util.module_from_spec(_spec_{n}) if _spec_{n} else None")
                out.append(f"{ind()}_spec_{n}.loader.exec_module({n}) if _spec_{n} and {n} else None")
            continue

        # Strip `let`
        stripped = re.sub(r"^let\s+", "", stripped)

        # fn → def
        m = re.match(r"^fn\s+(\w+)\s*\((.*?)\)\s*\{?(.*)", stripped)
        if m:
            name, params, rest = m.group(1), m.group(2), m.group(3).strip()
            out.append(f"{ind()}def {name}({params}):")
            indent_stack.append(len(indent_stack))
            if rest and rest not in ("{", "}"):
                out.append("    " * len(indent_stack) + _fix_line(rest))
            continue

        # try {
        if re.match(r"^try\s*\{", stripped):
            out.append(f"{ind()}try:")
            indent_stack.append(len(indent_stack))
            continue

        # loop {
        if re.match(r"^loop\s*\{", stripped):
            out.append(f"{ind()}while True:")
            indent_stack.append(len(indent_stack))
            continue

        # for x in y {
        m = re.match(r"^for\s+(\w+(?:,\s*\w+)?)\s+in\s+(.+?)\s*\{(.*)", stripped)
        if m:
            var, iterable, rest = m.group(1), m.group(2), m.group(3).strip()
            out.append(f"{ind()}for {var} in {_fix_expr(iterable)}:")
            indent_stack.append(len(indent_stack))
            if rest and "}" not in rest:
                out.append("    " * len(indent_stack) + _fix_line(rest))
            elif rest.endswith("}"):
                inner = rest[:-1].strip()
                if inner:
                    out.append("    " * len(indent_stack) + _fix_line(inner))
                if len(indent_stack) > 1: indent_stack.pop()
            continue

        # if cond { [body] [}] }
        m = re.match(r"^if\s+(.+?)\s*\{(.*)", stripped)
        if m:
            cond, rest = m.group(1), m.group(2).strip()
            out.append(f"{ind()}if {_fix_expr(cond)}:")
            indent_stack.append(len(indent_stack))
            if rest:
                if rest.endswith("}"):
                    inner = rest[:-1].strip()
                    if inner:
                        out.append("    " * len(indent_stack) + _fix_line(inner))
                    if len(indent_stack) > 1: indent_stack.pop()
                elif "}" not in rest:
                    out.append("    " * len(indent_stack) + _fix_line(rest))
            continue

        # else {
        if re.match(r"^else\s*\{", stripped):
            if len(indent_stack) > 1: indent_stack.pop()
            out.append(f"{ind()}else:")
            indent_stack.append(len(indent_stack))
            continue

        # return [value]
        m = re.match(r"^return\b(.*)", stripped)
        if m:
            val = m.group(1).strip()
            if val:
                out.append(f"{ind()}return {_fix_expr(val)}")
            else:
                out.append(f"{ind()}return")
            continue

        # break / continue
        if stripped in ("break", "continue"):
            out.append(f"{ind()}{stripped}")
            continue

        # Regular line
        out.append(f"{ind()}{_fix_line(stripped)}")

    return "\n".join(out)


def run_file(path, args=None):
    with open(path) as f:
        source = f.read()
    run_source(source, args or [], path)


def run_source(source, args=None, filename="<koppa>"):
    args = args or []
    code = _transpile(source)
    safe_args = _SafeList(args)
    globs = {
        "__name__": "__main__",
        "args":     safe_args,
        "__args__": safe_args,
        "json":     json,
        "re":       re,
        "True":     True,
        "False":    False,
        "None":     None,
    }
    try:
        exec(compile(code, filename, "exec"), globs)
        if "main" in globs:
            globs["main"](args)
    except SystemExit:
        pass
    except Exception as e:
        print(f"\033[91m[KOPPA ERROR]\033[0m {e}")
        if os.getenv("KOPPA_DEBUG"):
            import traceback; traceback.print_exc()
            print("\n--- Transpiled code ---\n" + code)


def repl():
    print("\033[1mKOPPA v3.1 Interactive Shell\033[0m  (type 'exit' to quit)")
    buf = ""
    globs = {
        "__name__": "__main__",
        "json": json, "re": re,
        "True": True, "False": False, "None": None,
        "__args__": _SafeList([]), "args": _SafeList([]),
    }
    while True:
        try:
            line = input("\033[91m>>>\033[0m " if not buf else "... ")
        except (EOFError, KeyboardInterrupt):
            print(); break
        if line.strip() == "exit":
            break
        buf += line + "\n"
        last = buf.rstrip("\n").split("\n")[-1]
        if last.strip() and not last.strip().endswith("{"):
            code = _transpile(buf)
            try:
                exec(compile(code, "<repl>", "exec"), globs)
            except SyntaxError:
                pass
            except Exception as e:
                print(f"\033[91m[-]\033[0m {e}")
            finally:
                buf = ""


if __name__ == "__main__":
    if len(sys.argv) < 2:
        repl()
    else:
        run_file(sys.argv[1], sys.argv[2:])
