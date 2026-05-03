#!/usr/bin/env python3
"""
KOPPA Language Interpreter — transpiles .kpkg / .kop to Python and executes it.

KOPPA syntax differences from Python:
  let x = v          →  x = v
  fn name(args) {…}  →  def name(args):
  for x in y {…}     →  for x in y:
  if cond {…}        →  if cond:
  if cond {…} else{} →  if cond: … else:
  loop {…}           →  while True:
  x.len()            →  len(x)
  x.push(v)          →  x.append(v)
  x.to_int()         →  int(x)
  x.to_str()         →  str(x)
  x.contains(s)      →  (s in x)
  x.starts_with(s)   →  x.startswith(s)
  x.chunk(n)         →  [x[i:i+n] for i in range(0,len(x),n)]
  x.to_json()        →  json.dumps(x)
  x.map(fn(v){…})    →  [… for v in x]
  x.enumerate()      →  enumerate(x)
  import net, log    →  from koppa_runtime import net, log, ...
  ## comment         →  # comment
"""
import sys, os, re, json, importlib

RUNTIME_DIR = os.path.join(os.path.dirname(__file__), "runtime")

_MODULE_ALIASES = {
    "sys": "sys_mod",
}

def _load_stdlib(names):
    mods = {}
    for name in names:
        alias = _MODULE_ALIASES.get(name, name)
        spec = importlib.util.spec_from_file_location(
            alias, os.path.join(RUNTIME_DIR, alias + ".py"))
        if spec:
            m = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(m)
            mods[name] = m
    return mods

# ── Transpiler ────────────────────────────────────────────────────────────────
def _transpile(source):
    lines = source.splitlines()
    out   = ["import sys as _sys, os, json, re"]
    indent_stack = [0]
    pending_else = False

    def cur_indent(): return "    " * (len(indent_stack) - 1)

    for raw in lines:
        stripped = raw.strip()

        # Strip header comments (## pkg: ...)
        if stripped.startswith("## "): continue

        # Blank lines
        if not stripped:
            out.append(""); continue

        indent = len(raw) - len(raw.lstrip())
        ind    = "    " * (len(indent_stack) - 1)

        # Closing braces → dedent
        while stripped.startswith("}"):
            if len(indent_stack) > 1: indent_stack.pop()
            ind = "    " * (len(indent_stack) - 1)
            stripped = stripped[1:].strip()
            if not stripped: break

        if not stripped: continue

        # import statement
        if re.match(r"^import\s+", stripped):
            names = re.sub(r"^import\s+", "", stripped).split(",")
            names = [n.strip() for n in names]
            for n in names:
                alias = _MODULE_ALIASES.get(n, n)
                out.append(f"{ind}import importlib as _il")
                out.append(f"{ind}_spec_{n} = _il.util.spec_from_file_location('{alias}', '{RUNTIME_DIR}/{alias}.py')")
                out.append(f"{ind}{n} = _il.util.module_from_spec(_spec_{n}) if _spec_{n} else None")
                out.append(f"{ind}_spec_{n}.loader.exec_module({n}) if _spec_{n} else None")
            continue

        # let
        stripped = re.sub(r"^let\s+", "", stripped)

        # fn → def
        m = re.match(r"^fn\s+(\w+)\s*\((.*?)\)\s*\{?(.*)", stripped)
        if m:
            name, params, rest = m.group(1), m.group(2), m.group(3).strip()
            out.append(f"{ind}def {name}({params}):")
            indent_stack.append(len(indent_stack))
            if rest and rest != "{":
                out.append("    " * len(indent_stack) + _fix_line(rest))
            continue

        # loop
        if re.match(r"^loop\s*\{", stripped):
            out.append(f"{ind}while True:")
            indent_stack.append(len(indent_stack)); continue

        # for … in … {
        m = re.match(r"^for\s+(\w+(?:,\s*\w+)?)\s+in\s+(.+?)\s*\{(.*)", stripped)
        if m:
            var, iterable, rest = m.group(1), m.group(2), m.group(3).strip()
            out.append(f"{ind}for {var} in {_fix_expr(iterable)}:")
            indent_stack.append(len(indent_stack))
            if rest: out.append("    " * len(indent_stack) + _fix_line(rest))
            continue

        # if … { … } else { … }
        m = re.match(r"^if\s+(.+?)\s*\{(.*)", stripped)
        if m:
            cond, rest = m.group(1), m.group(2).strip()
            out.append(f"{ind}if {_fix_expr(cond)}:")
            indent_stack.append(len(indent_stack))
            if rest and "}" not in rest:
                out.append("    " * len(indent_stack) + _fix_line(rest))
            continue

        # else {
        if re.match(r"^else\s*\{", stripped):
            if len(indent_stack) > 1: indent_stack.pop()
            ind = "    " * (len(indent_stack) - 1)
            out.append(f"{ind}else:")
            indent_stack.append(len(indent_stack)); continue

        # return
        m = re.match(r"^return\s+(.*)", stripped)
        if m:
            out.append(f"{ind}return {_fix_expr(m.group(1))}"); continue

        # break / continue
        if stripped in ("break", "continue"):
            out.append(f"{ind}{stripped}"); continue

        # Regular line
        out.append(f"{ind}{_fix_line(stripped)}")

    return "\n".join(out)

def _fix_expr(expr):
    """Fix KOPPA expressions to Python equivalents"""
    expr = expr.strip().rstrip(";")
    # .len() → len(x)
    expr = re.sub(r"(\w+)\.len\(\)", r"len(\1)", expr)
    # .push(v) → .append(v)
    expr = re.sub(r"\.push\(", ".append(", expr)
    # .to_int() → int(x)
    expr = re.sub(r"(\w+)\.to_int\(\)", r"int(\1)", expr)
    # .to_str() → str(x)
    expr = re.sub(r"(\w+)\.to_str\(\)", r"str(\1)", expr)
    # .contains(s) → (s in x)
    expr = re.sub(r"(\w+)\.contains\((.+?)\)", r"(\2 in \1)", expr)
    # .starts_with(s)
    expr = re.sub(r"(\w+)\.starts_with\(", r"\1.startswith(", expr)
    # .chunk(n)
    expr = re.sub(r"(\w+)\.chunk\((\d+)\)",
                  r"[\1[_i:\1[_i+\2]] for _i in range(0,len(\1),\2)]", expr)
    # .to_json()
    expr = re.sub(r"(\w+)\.to_json\(\)", r"json.dumps(\1)", expr)
    # .join(d)
    expr = re.sub(r"(\w+)\.join\((.+?)\)", r"\2.join(\1)", expr)
    # .split(d)
    # .replace handled natively
    # x or y (default value pattern: a or b where a might be None/empty)
    # Keep as-is — Python handles it
    # not keyword
    expr = re.sub(r"\bnot\b", "not", expr)
    return expr

def _fix_line(line):
    line = line.rstrip(";").rstrip("{").rstrip("}")
    return _fix_expr(line)


def run_file(path, args=None):
    with open(path) as f:
        source = f.read()
    run_source(source, args or [], path)


def run_source(source, args=None, filename="<koppa>"):
    args = args or []
    code = _transpile(source)
    globs = {"__name__": "__main__", "args": args, "json": json, "re": re,
             "True": True, "False": False, "None": None}
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
    print("\033[1mKOPPA v3.0 Interactive Shell\033[0m  (type 'exit' to quit)")
    buf = ""; imports_done = False
    globs = {"__name__": "__main__", "json": json, "re": re,
             "True": True, "False": False, "None": None}
    while True:
        try:
            line = input("\033[91m>>>\033[0m " if not buf else "... ")
        except (EOFError, KeyboardInterrupt):
            print(); break
        if line.strip() == "exit": break
        buf += line + "\n"
        if line.strip() and not line.strip().endswith("{") and "{" not in buf.split("\n")[-2]:
            code = _transpile(buf)
            try:
                exec(compile(code, "<repl>", "exec"), globs)
            except SyntaxError:
                pass  # wait for more input
            except Exception as e:
                print(f"\033[91m[-]\033[0m {e}")
            finally:
                buf = ""


if __name__ == "__main__":
    if len(sys.argv) < 2:
        repl()
    else:
        run_file(sys.argv[1], sys.argv[2:])
