#!/usr/bin/env python3
"""
Compares the Keycloak API our extensions actually use between two Keycloak versions.

How it works:
  1. Every org.keycloak.* class, method and field referenced by our compiled code is read
     directly from the .class files (constant pool).
  2. The complete superclass/interface chains within org.keycloak are added, because we
     extend Keycloak classes and override their methods.
  3. For each of these types the script checks:
       - Linkage:    does every referenced method/field still exist with the same signature?
                     (otherwise NoSuchMethodError at runtime)
       - Overrides:  does every method of ours that overrode something in the old version
                     still override it, and is it still called from the Keycloak class
                     hierarchy? (otherwise our code silently stops running)
       - Abstract:   were abstract methods added to types we extend?
       - API:        added/removed public/protected members.
       - Source:     source diff (behaviour changes without signature changes).
       - New API:    methods and types newly added to our superclasses, where Keycloak itself
                     calls them, and the upstream commits that introduced them.

Output: Markdown report (--report), compact issue variant (--issue), status line (--status).
Exit code 1 on linkage/override problems, otherwise 0.
"""
import argparse
import difflib
import os
import re
import struct
import subprocess
import sys
import zipfile

ACC_PUBLIC, ACC_PRIVATE, ACC_PROTECTED, ACC_STATIC, ACC_FINAL = 0x1, 0x2, 0x4, 0x8, 0x10
ACC_BRIDGE, ACC_VARARGS = 0x40, 0x80
ACC_INTERFACE, ACC_ABSTRACT, ACC_SYNTHETIC, ACC_ANNOTATION, ACC_ENUM = 0x200, 0x400, 0x1000, 0x2000, 0x4000

WATCH_PREFIX = "org/keycloak/"
KC_GITHUB = "https://github.com/keycloak/keycloak"
MAX_DIFF_LINES = 800


# ── Minimal class file parser ────────────────────────────────────────────────

class ClassInfo:
    __slots__ = ("name", "access", "super", "interfaces", "fields", "methods", "refs", "types", "calls")


# Instruction lengths (opcode + operands) for everything except tableswitch, lookupswitch, wide
_OPLEN = [1] * 256
for _op in (0x10, 0x12, *range(0x15, 0x1a), *range(0x36, 0x3b), 0xa9, 0xbc):
    _OPLEN[_op] = 2
for _op in (0x11, 0x13, 0x14, 0x84, *range(0x99, 0xa9), *range(0xb2, 0xb9), 0xbb, 0xbd, 0xc0, 0xc1, 0xc6, 0xc7):
    _OPLEN[_op] = 3
_OPLEN[0xc5] = 4
for _op in (0xb9, 0xba, 0xc8, 0xc9):
    _OPLEN[_op] = 5


def _scan_invokes(code, ref):
    """Returns all (owner, name, descriptor) invoked by a method's bytecode."""
    out, i, n = set(), 0, len(code)
    while i < n:
        op = code[i]
        if 0xb6 <= op <= 0xb9:  # invokevirtual/special/static/interface
            r = ref((code[i + 1] << 8) | code[i + 2])
            if r:
                out.add(r)
        if op == 0xaa:  # tableswitch
            j = i + 1 + (-(i + 1) % 4)
            low, high = struct.unpack_from(">ii", code, j + 4)
            i = j + 12 + (high - low + 1) * 4
        elif op == 0xab:  # lookupswitch
            j = i + 1 + (-(i + 1) % 4)
            (npairs,) = struct.unpack_from(">i", code, j + 4)
            i = j + 8 + npairs * 8
        elif op == 0xc4:  # wide
            i += 6 if code[i + 1] == 0x84 else 4
        else:
            i += _OPLEN[op]
    return out


def parse_class(data):
    """Reads name, hierarchy, members, references and per-method invocations of a class file."""
    if data[:4] != b"\xca\xfe\xba\xbe":
        raise ValueError("not a class file")
    pos = 10
    (count,) = struct.unpack_from(">H", data, 8)
    cp = [None] * count
    i = 1
    while i < count:
        tag = data[pos]
        pos += 1
        if tag == 1:  # Utf8
            (ln,) = struct.unpack_from(">H", data, pos)
            cp[i] = ("utf8", data[pos + 2:pos + 2 + ln].decode("utf-8", "replace"))
            pos += 2 + ln
        elif tag in (3, 4):
            pos += 4
        elif tag in (5, 6):
            pos += 8
            i += 1
        elif tag in (7, 8, 16, 19, 20):  # Class, String, MethodType, Module, Package
            (idx,) = struct.unpack_from(">H", data, pos)
            cp[i] = ({7: "class", 8: "string", 16: "mtype", 19: "module", 20: "package"}[tag], idx)
            pos += 2
        elif tag in (9, 10, 11):  # Field/Method/InterfaceMethod ref
            a, b = struct.unpack_from(">HH", data, pos)
            cp[i] = ({9: "field", 10: "method", 11: "imethod"}[tag], a, b)
            pos += 4
        elif tag == 12:  # NameAndType
            a, b = struct.unpack_from(">HH", data, pos)
            cp[i] = ("nat", a, b)
            pos += 4
        elif tag == 15:  # MethodHandle
            pos += 3
        elif tag in (17, 18):  # Dynamic, InvokeDynamic
            pos += 4
        else:
            raise ValueError("unknown constant pool tag %d" % tag)
        i += 1

    def utf(idx):
        return cp[idx][1]

    def cls(idx):
        return utf(cp[idx][1]) if idx else None

    def method_ref(idx):
        e = cp[idx]
        if not e or e[0] not in ("method", "imethod"):
            return None
        nat = cp[e[2]]
        return utf(cp[e[1]][1]), utf(nat[1]), utf(nat[2])

    access, this_i, super_i, n_if = struct.unpack_from(">HHHH", data, pos)
    pos += 8
    interfaces = []
    for _ in range(n_if):
        (idx,) = struct.unpack_from(">H", data, pos)
        interfaces.append(cls(idx))
        pos += 2

    calls = {}

    def members(with_code):
        nonlocal pos
        (n,) = struct.unpack_from(">H", data, pos)
        pos += 2
        out = {}
        for _ in range(n):
            acc, ni, di, na = struct.unpack_from(">HHHH", data, pos)
            pos += 8
            key = (utf(ni), utf(di))
            for _ in range(na):
                an, alen = struct.unpack_from(">HI", data, pos)
                if with_code and utf(an) == "Code":
                    (code_len,) = struct.unpack_from(">I", data, pos + 10)
                    calls[key] = _scan_invokes(data[pos + 14:pos + 14 + code_len], method_ref)
                pos += 6 + alen
            out[key] = acc
        return out

    info = ClassInfo()
    info.name = cls(this_i)
    info.access = access
    info.super = cls(super_i)
    info.interfaces = interfaces
    info.fields = members(False)
    info.methods = members(True)
    info.calls = calls

    # A nested class keeps its declared visibility only in the InnerClasses attribute
    (n_attr,) = struct.unpack_from(">H", data, pos)
    pos += 2
    for _ in range(n_attr):
        an, alen = struct.unpack_from(">HI", data, pos)
        if utf(an) == "InnerClasses":
            (n_inner,) = struct.unpack_from(">H", data, pos + 6)
            for k in range(n_inner):
                inner_i, _, _, inner_acc = struct.unpack_from(">HHHH", data, pos + 8 + k * 8)
                if inner_i and cls(inner_i) == info.name:
                    info.access = inner_acc
        pos += 6 + alen

    # References: (kind, owner, name, descriptor) and every type mentioned
    refs, types = set(), set()
    for e in cp:
        if not e:
            continue
        if e[0] in ("field", "method", "imethod"):
            owner = utf(cp[e[1]][1])
            nat = cp[e[2]]
            refs.add(("field" if e[0] == "field" else "method", owner, utf(nat[1]), utf(nat[2])))
        elif e[0] == "class":
            types.add(utf(e[1]))
        elif e[0] == "utf8":
            s = e[1]
            start = s.find("L" + WATCH_PREFIX)
            while start != -1:
                end = s.find(";", start)
                if end == -1:
                    break
                types.add(s[start + 1:end])
                start = s.find("L" + WATCH_PREFIX, end)
    info.refs = refs
    info.types = {t.lstrip("[").removeprefix("L").removesuffix(";") for t in types}
    return info


# ── Class path of one Keycloak version ───────────────────────────────────────

class ClassPath:
    def __init__(self, jar_dir, src_dir):
        self.index = {}      # "org/keycloak/Foo" -> jar path
        self.sources = {}    # "org/keycloak/Foo.java" -> sources jar path
        self.cache = {}
        self._zips = {}
        self._texts = None
        for f in sorted(os.listdir(jar_dir)):
            if f.endswith(".jar"):
                p = os.path.join(jar_dir, f)
                for n in self._zip(p).namelist():
                    if n.endswith(".class") and n != "module-info.class":
                        self.index.setdefault(n[:-6], p)
        if src_dir and os.path.isdir(src_dir):
            for f in sorted(os.listdir(src_dir)):
                if f.endswith(".jar"):
                    p = os.path.join(src_dir, f)
                    for n in self._zip(p).namelist():
                        if n.endswith(".java"):
                            self.sources.setdefault(n, p)

    def _zip(self, path):
        if path not in self._zips:
            self._zips[path] = zipfile.ZipFile(path)
        return self._zips[path]

    def get(self, name):
        if name not in self.cache:
            jar = self.index.get(name)
            self.cache[name] = parse_class(self._zip(jar).read(name + ".class")) if jar else None
        return self.cache[name]

    def source(self, name):
        top = name.split("$", 1)[0] + ".java"
        jar = self.sources.get(top)
        if not jar:
            return None
        return self._zip(jar).read(top).decode("utf-8", "replace").splitlines()

    def source_callers(self, method, exclude=None):
        """Source files under org/keycloak that contain `method(` (plain text search)."""
        if self._texts is None:
            self._texts = {p: self._zip(jar).read(p).decode("utf-8", "replace")
                           for p, jar in self.sources.items() if p.startswith(WATCH_PREFIX)}
        needle = method + "("
        return sorted(p[:-5] for p, text in self._texts.items() if p != exclude and needle in text)

    def supertypes(self, name):
        """All supertypes (classes and interfaces) available on the class path, including name."""
        seen, todo = [], [name]
        while todo:
            n = todo.pop(0)
            if n is None or n in seen:
                continue
            c = self.get(n)
            if c is None:
                continue
            seen.append(n)
            todo.append(c.super)
            todo.extend(c.interfaces)
        return seen

    def resolve(self, kind, owner, name, desc):
        """Looks a member up the way the JVM does: in owner and all of its supertypes."""
        for t in self.supertypes(owner):
            c = self.get(t)
            members = c.fields if kind == "field" else c.methods
            if (name, desc) in members:
                return t, members[(name, desc)]
        return None

    def callers_in(self, types, name, desc):
        """Methods within `types` whose bytecode invokes name+desc on one of `types`."""
        targets = set(types)
        out = []
        for t in types:
            c = self.get(t)
            if c is None:
                continue
            for (mname, mdesc), invoked in sorted(c.calls.items()):
                if any(o in targets and n == name and d == desc for o, n, d in invoked):
                    if mname.startswith("lambda$"):
                        mname = mname.split("$")[1]
                    label = "%s.%s()" % (simple(t), mname)
                    if label not in out:
                        out.append(label)
        return out


# ── Upstream history (partial clone of keycloak/keycloak) ────────────────────

class Upstream:
    """Commits touching a source file between the two release tags.

    Expects a bare repository fetched with
      git fetch --filter=blob:none --shallow-exclude=<old> <keycloak repo> tag <new>
    so that only the commits of the new release that are not in the old one are present.
    """

    def __init__(self, git_dir, new_ref):
        self.git_dir, self.ref = git_dir, new_ref
        self.files, self.boundary = [], set()
        self.ok = False
        if not git_dir or not os.path.isdir(git_dir):
            return
        try:
            self.files = self._git("ls-tree", "-r", "--name-only", new_ref).splitlines()
            shallow = os.path.join(git_dir, "shallow")
            if os.path.exists(shallow):
                self.boundary = set(open(shallow).read().split())
            self.ok = bool(self.files)
        except (subprocess.SubprocessError, OSError):
            self.ok = False

    def _git(self, *args, timeout=60):
        return subprocess.run(["git", "--git-dir", self.git_dir, *args], check=True, capture_output=True,
                              text=True, timeout=timeout).stdout

    def path(self, cls):
        suffix = "/src/main/java/" + cls.split("$", 1)[0] + ".java"
        hits = [f for f in self.files if f.endswith(suffix)]
        return hits[0] if hits else None

    def commits(self, cls, pickaxe=None):
        if not self.ok:
            return []
        path = self.path(cls)
        if not path:
            return []
        args = ["log", "--format=%H%x1f%s%x1f%b%x1e"]
        if pickaxe:
            args.append("-S" + pickaxe)
        try:
            out = self._git(*args, self.ref, "--", path, timeout=120)
        except (subprocess.SubprocessError, OSError):
            return []
        result = []
        for rec in out.split("\x1e"):
            rec = rec.strip("\n")
            if not rec:
                continue
            sha, subject, body = (rec.split("\x1f") + ["", ""])[:3]
            if sha in self.boundary:
                continue  # edge of the shallow history, shows up as touching every file
            pr = re.search(r"\(#(\d+)\)\s*$", subject)
            issues = re.findall(r"(?i)(?:closes|closed|fixes|fixed|fix|resolves|resolved)\s*:?\s*#(\d+)",
                                subject + "\n" + body)
            issues = [i for i in dict.fromkeys(issues) if not pr or i != pr.group(1)]
            result.append({"sha": sha, "subject": subject, "pr": pr.group(1) if pr else None, "issues": issues})
        return result


def render_commit(c):
    subject = re.sub(r"\s*\(#\d+\)\s*$", "", c["subject"]).replace("|", "\\|")
    links = []
    if c["pr"]:
        links.append("PR [#%s](%s/pull/%s)" % (c["pr"], KC_GITHUB, c["pr"]))
    links += ["issue [#%s](%s/issues/%s)" % (i, KC_GITHUB, i) for i in c["issues"]]
    return "[`%s`](%s/commit/%s) %s%s" % (c["sha"][:8], KC_GITHUB, c["sha"], subject,
                                         (" – " + ", ".join(links)) if links else "")


# ── Formatting helpers ───────────────────────────────────────────────────────

_PRIM = {"B": "byte", "C": "char", "D": "double", "F": "float", "I": "int", "J": "long",
         "S": "short", "Z": "boolean", "V": "void"}


def simple(n):
    return n.rsplit("/", 1)[-1].replace("$", ".")


def dotted(n):
    return n.replace("/", ".").replace("$", ".")


def _desc_types(desc):
    """'(Ljava/lang/String;I)Z' -> (['String', 'int'], 'boolean')"""
    def one(s, i):
        dims = 0
        while s[i] == "[":
            dims += 1
            i += 1
        if s[i] == "L":
            end = s.index(";", i)
            t, i = simple(s[i + 1:end]), end + 1
        else:
            t, i = _PRIM[s[i]], i + 1
        return t + "[]" * dims, i

    params, i = [], 1
    while desc[i] != ")":
        t, i = one(desc, i)
        params.append(t)
    ret, _ = one(desc, i + 1)
    return params, ret


def visibility(acc):
    if acc & ACC_PUBLIC:
        return "public"
    if acc & ACC_PROTECTED:
        return "protected"
    if acc & ACC_PRIVATE:
        return "private"
    return "package-private"


def modifiers(acc):
    parts = [visibility(acc)]
    for bit, word in ((ACC_ABSTRACT, "abstract"), (ACC_STATIC, "static"), (ACC_FINAL, "final")):
        if acc & bit:
            parts.append(word)
    return " ".join(parts)


def java_sig(name, desc, acc=0, owner=None, mods=False):
    """JVM descriptor -> Java declaration, e.g. 'protected static boolean foo(KeycloakSession, int)'."""
    prefix = (modifiers(acc) + " ") if mods else ""
    if "(" not in desc:  # field
        return "%s%s %s" % (prefix, _desc_types("()" + desc)[1], name)
    params, ret = _desc_types(desc)
    if acc & ACC_VARARGS and params and params[-1].endswith("[]"):
        params[-1] = params[-1][:-2] + "..."
    if name == "<init>":
        return "%s%s(%s)" % (prefix, simple(owner).rsplit(".", 1)[-1] if owner else "<init>", ", ".join(params))
    return "%s%s %s(%s)" % (prefix, ret, name, ", ".join(params))


def member(owner, name, desc, acc=0):
    """Qualified member for messages, e.g. 'String AcrUtils.getMinimumAcrValue(ClientModel)'."""
    if name == "<init>":
        return "new " + java_sig(name, desc, acc, owner)
    sig = java_sig(name, desc, acc, owner)
    if "(" not in desc:
        ret, fname = sig.rsplit(" ", 1)
        return "%s %s.%s" % (ret, simple(owner), fname)
    ret, rest = sig.split(" ", 1)
    return "%s %s.%s" % (ret, simple(owner), rest)


def is_api(acc):
    return bool(acc & (ACC_PUBLIC | ACC_PROTECTED))


def type_kind(acc):
    if acc & ACC_ANNOTATION:
        return "annotation"
    if acc & ACC_INTERFACE:
        return "interface"
    if acc & ACC_ENUM:
        return "enum"
    return ("abstract class" if acc & ACC_ABSTRACT else "class")


# ── Analysis ─────────────────────────────────────────────────────────────────

def load_own_classes(classes_dir):
    own = {}
    for root, _, files in os.walk(classes_dir):
        for f in files:
            if f.endswith(".class"):
                with open(os.path.join(root, f), "rb") as fh:
                    c = parse_class(fh.read())
                own[c.name] = c
    return own


def inheritance_paths(own, cp):
    """For each Keycloak type: chains from our classes to it, e.g. 'A → B → C'."""
    paths = {}
    for c in sorted(own.values(), key=lambda x: x.name):
        parent_of = {c.name: None}
        todo = [c.name]
        while todo:
            n = todo.pop(0)
            info = own.get(n) or cp.get(n)
            if info is None:
                continue
            for p in [info.super] + info.interfaces:
                if p and p not in parent_of:
                    parent_of[p] = n
                    todo.append(p)
        for t in parent_of:
            if t == c.name or not t.startswith(WATCH_PREFIX):
                continue
            chain, x = [], t
            while x is not None:
                chain.append(simple(x))
                x = parent_of[x]
            paths.setdefault(t, []).append(" → ".join(reversed(chain)))
    return paths


def analyse(own, old, new, upstream, old_v, new_v):
    r = {
        "problems": [],    # hard failures -> FAIL
        "attention": [],   # behaviour risks -> WARN
        "findings": {},    # type -> (notes, diff)
        "new_methods": [], # (type, name, desc, acc, source callers, commits)
        "new_types": {},   # superclass -> [description lines]
        "overrides": [],   # rows
        "commits": {},     # type -> [commit]
    }
    problems, attention = r["problems"], r["attention"]

    # 1. Collect relevant Keycloak types
    relevant = set()
    for c in own.values():
        relevant.update(t for t in c.types if t.startswith(WATCH_PREFIX))
        relevant.update(o for _, o, _, _ in c.refs if o.startswith(WATCH_PREFIX))
        for parent in [c.super] + c.interfaces:
            if parent:
                relevant.update(t for t in old.supertypes(parent) if t.startswith(WATCH_PREFIX))
    for t in list(relevant):
        relevant.update(x for x in old.supertypes(t) if x.startswith(WATCH_PREFIX))
    r["relevant"] = relevant

    # Types we inherit from directly or indirectly: changes there matter most
    inherited = set()
    for c in own.values():
        for parent in [c.super] + c.interfaces:
            if parent:
                inherited.update(x for x in old.supertypes(parent) if x.startswith(WATCH_PREFIX))
    r["inherited"] = inherited
    r["paths"] = inheritance_paths(own, old)
    users = {}
    for c in own.values():
        for t in c.types | {o for _, o, _, _ in c.refs}:
            users.setdefault(t, set()).add(simple(c.name))
    # types only reached as a supertype of something we use: name that type
    via = {}
    for u in sorted(users):
        if u.startswith(WATCH_PREFIX):
            for t in old.supertypes(u)[1:]:
                via.setdefault(t, []).append(simple(u))
    r["users"], r["via"] = users, via

    # 2. Linkage: every reference of our code must resolve in the new version
    for c in sorted(own.values(), key=lambda x: x.name):
        for kind, owner, name, desc in sorted(c.refs):
            if not owner.startswith(WATCH_PREFIX):
                continue
            hit = old.resolve(kind, owner, name, desc)
            if hit is None:
                continue  # not on the old class path either (e.g. array clone)
            if new.get(owner) is None:
                problems.append("`%s` references `%s`, which no longer exists" % (simple(c.name), dotted(owner)))
            elif new.resolve(kind, owner, name, desc) is None:
                problems.append("`%s` uses `%s`, which no longer exists with this signature"
                                % (simple(c.name), member(owner, name, desc, hit[1])))

    # 3. Overrides: still overriding, still called?
    for c in sorted(own.values(), key=lambda x: x.name):
        if c.access & ACC_INTERFACE or not c.super:
            continue
        old_chain = old.supertypes(c.super)
        new_chain = new.supertypes(c.super)
        for (name, desc), acc in sorted(c.methods.items()):
            if name in ("<init>", "<clinit>") or acc & (ACC_STATIC | ACC_PRIVATE | ACC_SYNTHETIC | ACC_BRIDGE):
                continue
            decl_old = next((t for t in old_chain if (name, desc) in old.get(t).methods), None)
            if decl_old is None:
                continue
            old_acc = old.get(decl_old).methods[(name, desc)]
            if not is_api(old_acc) or old_acc & ACC_STATIC:
                continue
            is_class_method = not old.get(decl_old).access & ACC_INTERFACE
            decl_new = next((t for t in new_chain if (name, desc) in new.get(t).methods), None)
            sig = java_sig(name, desc, acc, c.name)
            qual = member(c.name, name, desc, acc)
            if decl_new is None:
                problems.append("`%s` no longer overrides anything (used to override `%s`) - "
                                "our code would not be called any more" % (qual, simple(decl_old)))
                state = "❌ removed"
            else:
                new_acc = new.get(decl_new).methods[(name, desc)]
                if not is_api(new_acc) or new_acc & (ACC_STATIC | ACC_FINAL):
                    problems.append("`%s`: the overridden method in `%s` is now %s"
                                    % (qual, simple(decl_new), modifiers(new_acc)))
                    state = "❌ now %s" % modifiers(new_acc)
                elif decl_new != decl_old:
                    state = "moved to `%s`" % simple(decl_new)
                else:
                    state = "unchanged"
            if not is_class_method:
                continue  # plain SPI interface method: covered by linkage, called by the framework
            callers_old = old.callers_in(old_chain, name, desc)
            callers_new = new.callers_in(new_chain, name, desc)
            if callers_old and not callers_new:
                attention.append("`%s` is no longer called from Keycloak's class hierarchy "
                                 "(was called from %s) - check whether our override still has an effect"
                                 % (qual, ", ".join("`%s`" % x for x in callers_old)))
            r["overrides"].append({
                "ours": simple(c.name), "sig": sig, "decl": decl_old, "state": state, "chain": old_chain,
                "callers": callers_new, "callers_old": callers_old,
            })

    # 4. New abstract methods in types we extend/implement
    for c in sorted(own.values(), key=lambda x: x.name):
        if c.access & (ACC_ABSTRACT | ACC_INTERFACE):
            continue
        for p in [c.super] + c.interfaces:
            for t in new.supertypes(p) if p else []:
                for (name, desc), acc in new.get(t).methods.items():
                    if not acc & ACC_ABSTRACT:
                        continue
                    oc = old.get(t)
                    if oc and (name, desc) in oc.methods and oc.methods[(name, desc)] & ACC_ABSTRACT:
                        continue
                    implemented = (name, desc) in c.methods or any(
                        (name, desc) in new.get(x).methods and not new.get(x).methods[(name, desc)] & ACC_ABSTRACT
                        for x in (new.supertypes(c.super) if c.super else []))
                    if not implemented:
                        problems.append("`%s` extends `%s`, which has the new abstract method `%s` "
                                        "(AbstractMethodError when called)"
                                        % (simple(c.name), simple(t), member(t, name, desc, acc)))

    # 5. API and source changes per relevant type
    for t in sorted(relevant):
        notes = []
        oc, nc = old.get(t), new.get(t)
        if oc is None:
            continue
        if nc is None:
            problems.append("Class `%s` was removed" % dotted(t))
            continue
        if oc.super != nc.super:
            notes.append("Superclass changed: `%s` → `%s`" % (dotted(oc.super or "-"), dotted(nc.super or "-")))
        if set(oc.interfaces) != set(nc.interfaces):
            notes.append("Interfaces changed: %s → %s" % (", ".join(map(simple, sorted(oc.interfaces))) or "-",
                                                           ", ".join(map(simple, sorted(nc.interfaces))) or "-"))
        for label, om, nm in (("Method", oc.methods, nc.methods), ("Field", oc.fields, nc.fields)):
            for key in sorted(set(om) | set(nm)):
                a, b = om.get(key), nm.get(key)
                if a is not None and b is not None:
                    if is_api(a) or is_api(b):
                        mask = ACC_PUBLIC | ACC_PROTECTED | ACC_PRIVATE | ACC_STATIC | ACC_FINAL | ACC_ABSTRACT
                        if a & mask != b & mask:
                            notes.append("%s `%s`: %s → %s" % (label, java_sig(key[0], key[1], b, t),
                                                                modifiers(a), modifiers(b)))
                elif a is not None and is_api(a):
                    notes.append("%s removed: `%s`" % (label, java_sig(key[0], key[1], a, t, mods=True)))
                elif b is not None and is_api(b):
                    notes.append("%s added: `%s`" % (label, java_sig(key[0], key[1], b, t, mods=True)))
        src_old, src_new = old.source(t), new.source(t)
        diff = None
        if src_old is not None and src_new is not None and "$" not in t and src_old != src_new:
            diff = list(difflib.unified_diff(src_old, src_new, "%s (%s)" % (t, old_v), "%s (%s)" % (t, new_v),
                                             lineterm="", n=3))
        if notes or diff:
            r["findings"][t] = (notes, diff)
            if "$" not in t:
                r["commits"][t] = upstream.commits(t)

    # 6. New methods in our superclasses: who in Keycloak calls them, which commit added them.
    #    New helpers in a base class are often new security or validation steps that Keycloak's
    #    own subclasses adopt - ours do not automatically.
    for t in sorted(inherited):
        oc, nc = old.get(t), new.get(t)
        if not oc or not nc:
            continue
        for (name, desc), acc in sorted(nc.methods.items()):
            if not is_api(acc) or name.startswith("<") or (name, desc) in oc.methods or acc & ACC_SYNTHETIC:
                continue
            hits = new.source_callers(name, exclude=t.split("$", 1)[0] + ".java")
            r["new_methods"].append((t, name, desc, acc, hits, upstream.commits(t, pickaxe=name)))

    # 7. New types in our superclasses: nested classes and types referenced for the first time
    for t in sorted(inherited):
        oc, nc = old.get(t), new.get(t)
        if not oc or not nc:
            continue
        nested = [n for n in new.index if n.startswith(t + "$") and n not in old.index
                  and not re.search(r"\$\d", n[len(t):])]
        referenced = [n for n in nc.types if n.startswith(WATCH_PREFIX) and n not in old.index
                      and not n.startswith(t + "$")]
        for n in sorted(set(nested)) + sorted(set(referenced)):
            info = new.get(n)
            if info is None:
                continue
            ext = " extends `%s`" % simple(info.super) if info.super and info.super != "java/lang/Object" \
                and not info.access & ACC_INTERFACE else ""
            accessible = is_api(info.access)
            head = "`%s` – %s %s%s%s" % (
                dotted(n).removeprefix(dotted(t).rsplit(".", 1)[0] + "."), modifiers(info.access & ~ACC_ABSTRACT),
                type_kind(info.access), ext,
                "" if accessible else " – **not accessible from our code** (not public/protected)")
            members = []
            for (mname, mdesc), macc in sorted(info.methods.items(), key=lambda kv: (kv[0][0] != "<init>", kv[0])):
                if mname == "<clinit>" or macc & (ACC_PRIVATE | ACC_SYNTHETIC | ACC_BRIDGE):
                    continue
                members.append("`%s`" % java_sig(mname, mdesc, macc, n, mods=True))
            r["new_types"].setdefault(t, []).append((head, members))
    return r


# ── Rendering ────────────────────────────────────────────────────────────────

def our_classes_cell(r, t):
    if t in r["inherited"]:
        return "<br>".join("`%s`" % p.replace(" → ", "` → `") for p in r["paths"].get(t, [])) or "-"
    users = sorted(r["users"].get(t, []))
    if users:
        cell = ", ".join("`%s`" % u for u in users[:4])
        return cell + (" and %d more" % (len(users) - 4) if len(users) > 4 else "")
    via = r["via"].get(t, [])
    return ("via %s" % ", ".join("`%s`" % v for v in via[:3])) if via else "-"


def render_sections(r, old_v, new_v, full):
    lines = []
    if r["problems"]:
        lines += ["### ❌ Incompatibilities (old jars break at runtime)", ""]
        lines += ["- " + p for p in r["problems"]] + [""]
    else:
        lines += ["✅ Every referenced method/field still exists and every override still overrides.", ""]
    if r["attention"]:
        lines += ["### ⚠️ Needs attention", ""] + ["- " + a for a in r["attention"]] + [""]

    if r["new_methods"]:
        lines += ["### 🔎 New methods in our superclasses", "",
                  "Keycloak added these to classes we extend. If Keycloak's own subclasses call them, ours "
                  "probably should too (e.g. new security checks).", ""]
        for t, name, desc, acc, hits, commits in r["new_methods"]:
            ours = sorted({p.split(" → ", 1)[0] for p in r["paths"].get(t, [])})
            lines.append("- **`%s`** (extended by %s): `%s`" % (
                simple(t), ", ".join("`%s`" % o for o in ours) or "-", java_sig(name, desc, acc, t, mods=True)))
            if hits:
                limit = 50 if full else 12
                shown = ", ".join("`%s`" % simple(h) for h in hits[:limit])
                more = " and %d more" % (len(hits) - limit) if len(hits) > limit else ""
                lines.append("  - Called in Keycloak by: %s%s" % (shown, more))
            else:
                lines.append("  - Not called anywhere else in Keycloak's sources")
            for c in commits[:3]:
                lines.append("  - Introduced by: %s" % render_commit(c))
            lines.append("  - Not available in %s: calling it directly makes the jar require Keycloak ≥ %s "
                         "(`NoSuchMethodError` on older versions). Alternatives: call it via reflection, or raise "
                         "the minimum supported Keycloak version." % (old_v, new_v))
        lines.append("")

    if r["new_types"]:
        lines += ["### 🧬 New types in our superclasses", ""]
        for t, items in r["new_types"].items():
            for head, members in items:
                lines.append("- In `%s`: %s" % (simple(t), head))
                lines += ["  - " + m for m in members]
        lines.append("")

    rows = r["overrides"]
    if not full:
        rows = [o for o in rows if any(x in r["findings"] for x in o["chain"]) or o["state"] != "unchanged"
                or o["callers"] != o["callers_old"]]
    if rows:
        lines += ["### Methods we override", "",
                  "Methods inherited from Keycloak *classes* (plain SPI interface methods are covered by the "
                  "linkage check)%s." % ("" if full else ", limited to superclasses that changed"), "",
                  "| Our class | Method | Overrides | In %s | Called from (%s) |" % (new_v, new_v),
                  "|---|---|---|---|---|"]
        for o in rows:
            callers = ", ".join("`%s`" % x for x in o["callers"]) or "outside the class hierarchy (framework/SPI)"
            if o["callers_old"] and o["callers"] != o["callers_old"]:
                callers += " (before: %s)" % (", ".join("`%s`" % x for x in o["callers_old"]))
            lines.append("| `%s` | `%s` | `%s` | %s | %s |" % (o["ours"], o["sig"], simple(o["decl"]), o["state"],
                                                              callers))
        lines.append("")
    return lines


def render_class_details(r, t, max_diff):
    notes, diff = r["findings"][t]
    block = ["<details><summary><code>%s</code></summary>" % dotted(t), ""]
    block += ["- " + n for n in notes]
    commits = r["commits"].get(t, [])
    if commits:
        block += ["", "Upstream commits touching this file:", ""] + ["- " + render_commit(c) for c in commits[:15]]
        if len(commits) > 15:
            block.append("- … and %d more" % (len(commits) - 15))
    if diff:
        block += ["", "```diff"] + diff[:max_diff]
        if len(diff) > max_diff:
            block.append("... (%d more lines in the artifact)" % (len(diff) - max_diff))
        block.append("```")
    return block + ["", "</details>", ""]


def changed_table(r):
    lines = ["**extends** = our classes extend/implement this type (behaviour changes affect us directly), "
             "**uses** = only called or used as a type.", "",
             "| Relation | Class | Our classes | API changes | Source diff | Upstream commits |",
             "|---|---|---|---|---|---|"]
    for t, (notes, diff) in r["findings"].items():
        changed = sum(1 for d in diff[2:] if d[:1] in "+-") if diff else 0
        lines.append("| %s | `%s` | %s | %d | %s | %s |" % (
            "**extends**" if t in r["inherited"] else "uses", dotted(t), our_classes_cell(r, t), len(notes),
            ("%d lines" % changed) if diff else "-", len(r["commits"].get(t, [])) or "-"))
    return lines + [""]


def render(r, old_v, new_v):
    lines = ["## API comparison Keycloak %s → %s" % (old_v, new_v), "",
             "Checked: **%d** Keycloak types our code uses or inherits from." % len(r["relevant"]), ""]
    lines += render_sections(r, old_v, new_v, full=True)
    if r["findings"]:
        lines += ["### Changed Keycloak classes", ""] + changed_table(r)
        for t in r["findings"]:
            lines += render_class_details(r, t, MAX_DIFF_LINES)
    else:
        lines += ["✅ None of the relevant Keycloak classes changed.", ""]
    lines += ["<details><summary>Checked types</summary>", ""]
    lines += ["- `%s`" % dotted(t) for t in sorted(r["relevant"])]
    lines += ["", "</details>"]
    return "\n".join(lines) + "\n"


def render_issue(r, old_v, new_v, budget):
    """Compact variant for the issue: everything about superclasses incl. diffs, the rest as a table."""
    lines = render_sections(r, old_v, new_v, full=False)
    if r["findings"]:
        lines += ["### Changed Keycloak classes", ""] + changed_table(r)
    size = sum(len(x) + 1 for x in lines)
    skipped = []
    for t in r["findings"]:
        if t not in r["inherited"]:
            continue
        block = render_class_details(r, t, MAX_DIFF_LINES)
        block_size = sum(len(x) + 1 for x in block)
        if size + block_size > budget:
            # shorten the diff to what still fits instead of dropping the class entirely
            fit = MAX_DIFF_LINES
            while fit > 40 and size + block_size > budget:
                fit //= 2
                block = render_class_details(r, t, fit)
                block_size = sum(len(x) + 1 for x in block)
            if size + block_size > budget:
                skipped.append(dotted(t))
                continue
        lines += block
        size += block_size
    if skipped:
        lines += ["Details for %s did not fit into the issue, see the artifact." % ", ".join("`%s`" % x for x in skipped), ""]
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--classes", required=True, help="compiled classes of our extensions")
    ap.add_argument("--old-version", required=True)
    ap.add_argument("--old-jars", required=True)
    ap.add_argument("--old-sources")
    ap.add_argument("--new-version", required=True)
    ap.add_argument("--new-jars", required=True)
    ap.add_argument("--new-sources")
    ap.add_argument("--upstream-git", help="bare partial clone of keycloak/keycloak (see Upstream)")
    ap.add_argument("--report", help="write the full Markdown report")
    ap.add_argument("--issue", help="write the compact issue variant")
    ap.add_argument("--issue-budget", type=int, default=45000, help="max characters of the issue variant")
    ap.add_argument("--status", help="write a status line (STATUS<TAB>text)")
    args = ap.parse_args()

    own = load_own_classes(args.classes)
    old = ClassPath(args.old_jars, args.old_sources)
    new = ClassPath(args.new_jars, args.new_sources)
    upstream = Upstream(args.upstream_git, args.new_version)
    r = analyse(own, old, new, upstream, args.old_version, args.new_version)
    # superclasses first
    r["findings"] = dict(sorted(r["findings"].items(), key=lambda kv: (kv[0] not in r["inherited"], kv[0])))

    md = render(r, args.old_version, args.new_version)
    if args.report:
        with open(args.report, "w") as fh:
            fh.write(md)
    else:
        sys.stdout.write(md)
    if args.issue:
        with open(args.issue, "w") as fh:
            fh.write(render_issue(r, args.old_version, args.new_version, args.issue_budget))

    findings, inherited = r["findings"], r["inherited"]
    if r["problems"]:
        status = ("FAIL", "%d incompatibilit%s, %d changed class(es)"
                  % (len(r["problems"]), "y" if len(r["problems"]) == 1 else "ies", len(findings)))
    elif r["attention"] or findings:
        inh = [simple(t) for t in findings if t in inherited]
        status = ("WARN", "%d of %d relevant classes changed, %d of them superclasses%s%s" % (
            len(findings), len(r["relevant"]), len(inh), (": " + ", ".join(inh)) if inh else "",
            "; %d override(s) need attention" % len(r["attention"]) if r["attention"] else ""))
    else:
        status = ("PASS", "no relevant class changed (%d checked)" % len(r["relevant"]))
    if args.status:
        with open(args.status, "w") as fh:
            fh.write("%s\t%s\n" % status)
    print("%s: %s" % status, file=sys.stderr)
    if not upstream.ok and args.upstream_git:
        print("note: upstream history not available, commit links omitted", file=sys.stderr)
    return 1 if r["problems"] else 0


if __name__ == "__main__":
    sys.exit(main())
