#!/usr/bin/env python3
"""
Vergleicht die Keycloak-API, die unsere Extensions tatsächlich benutzen, zwischen zwei
Keycloak-Versionen.

Vorgehen:
  1. Alle Klassen, Methoden und Felder aus org.keycloak.*, die unser kompilierter Code
     referenziert, werden direkt aus den .class-Dateien gelesen (Konstantenpool).
  2. Dazu kommen die kompletten Oberklassen-/Interface-Ketten innerhalb von org.keycloak,
     weil wir von Keycloak-Klassen erben und deren Methoden überschreiben.
  3. Für jede dieser Klassen wird geprüft:
       - Linkage:   Existiert jede referenzierte Methode / jedes Feld in der neuen Version
                    noch mit identischer Signatur? (sonst NoSuchMethodError zur Laufzeit)
       - Overrides: Überschreibt jede unserer Methoden, die in der alten Version etwas
                    überschrieben hat, das auch in der neuen noch? (sonst wird unser Code
                    stillschweigend nicht mehr aufgerufen)
       - Abstrakt:  Sind neue abstrakte Methoden in Typen dazugekommen, die wir erweitern?
       - API:       Hinzugefügte/entfernte public/protected Member.
       - Quelltext: Diff der Sources (Verhaltensänderungen ohne Signaturänderung).

Ergebnis: Markdown-Report auf stdout bzw. in --report, Kurzfassung in --summary.
Exit-Code 1 bei Linkage-/Override-Problemen, sonst 0.
"""
import argparse
import difflib
import os
import struct
import sys
import zipfile

ACC_PUBLIC, ACC_PRIVATE, ACC_PROTECTED, ACC_STATIC, ACC_FINAL = 0x1, 0x2, 0x4, 0x8, 0x10
ACC_INTERFACE, ACC_ABSTRACT = 0x200, 0x400

WATCH_PREFIX = "org/keycloak/"
MAX_DIFF_LINES = 400


# ── Minimaler Class-File-Parser ──────────────────────────────────────────────

class ClassInfo:
    __slots__ = ("name", "access", "super", "interfaces", "fields", "methods", "refs", "types")


def parse_class(data):
    """Liest Name, Hierarchie, Member und alle Referenzen aus einer .class-Datei."""
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

    access, this_i, super_i, n_if = struct.unpack_from(">HHHH", data, pos)
    pos += 8
    interfaces = []
    for _ in range(n_if):
        (idx,) = struct.unpack_from(">H", data, pos)
        interfaces.append(cls(idx))
        pos += 2

    def members():
        nonlocal pos
        (n,) = struct.unpack_from(">H", data, pos)
        pos += 2
        out = {}
        for _ in range(n):
            acc, ni, di, na = struct.unpack_from(">HHHH", data, pos)
            pos += 8
            for _ in range(na):
                (alen,) = struct.unpack_from(">I", data, pos + 2)
                pos += 6 + alen
            out[(utf(ni), utf(di))] = acc
        return out

    info = ClassInfo()
    info.name = cls(this_i)
    info.access = access
    info.super = cls(super_i)
    info.interfaces = interfaces
    info.fields = members()
    info.methods = members()

    # Referenzen: (kind, owner, name, descriptor) sowie alle erwähnten Typen
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


# ── Klassenpfad einer Keycloak-Version ───────────────────────────────────────

class ClassPath:
    def __init__(self, jar_dir, src_dir):
        self.index = {}      # "org/keycloak/Foo" -> jar path
        self.sources = {}    # "org/keycloak/Foo.java" -> sources jar path
        self.cache = {}
        self._zips = {}
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

    def supertypes(self, name):
        """Alle Ober-Typen (Klassen und Interfaces) innerhalb des Klassenpfads, inkl. name."""
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
        """Sucht einen Member wie die JVM: in owner und allen Ober-Typen."""
        for t in self.supertypes(owner):
            c = self.get(t)
            members = c.fields if kind == "field" else c.methods
            if (name, desc) in members:
                return t, members[(name, desc)]
        return None


def visibility(acc):
    if acc & ACC_PUBLIC:
        return "public"
    if acc & ACC_PROTECTED:
        return "protected"
    if acc & ACC_PRIVATE:
        return "private"
    return "package"


def is_api(acc):
    return bool(acc & (ACC_PUBLIC | ACC_PROTECTED))


def flags(acc):
    parts = [visibility(acc)]
    for bit, word in ((ACC_STATIC, "static"), (ACC_FINAL, "final"), (ACC_ABSTRACT, "abstract")):
        if acc & bit:
            parts.append(word)
    return " ".join(parts)


def dotted(n):
    return n.replace("/", ".")


# ── Analyse ──────────────────────────────────────────────────────────────────

def load_own_classes(classes_dir):
    own = {}
    for root, _, files in os.walk(classes_dir):
        for f in files:
            if f.endswith(".class"):
                with open(os.path.join(root, f), "rb") as fh:
                    c = parse_class(fh.read())
                own[c.name] = c
    return own


def analyse(own, old, new):
    problems = []   # harte Fehler -> FAIL
    findings = {}   # pro Klasse: Liste von Hinweisen

    # 1. relevante Keycloak-Typen sammeln
    relevant = set()
    for c in own.values():
        for t in c.types:
            if t.startswith(WATCH_PREFIX):
                relevant.add(t)
        for kind, owner, _, _ in c.refs:
            if owner.startswith(WATCH_PREFIX):
                relevant.add(owner)
        for parent in [c.super] + c.interfaces:
            for t in old.supertypes(parent) if parent else []:
                if t.startswith(WATCH_PREFIX):
                    relevant.add(t)
    expanded = set()
    for t in relevant:
        expanded.update(x for x in old.supertypes(t) if x.startswith(WATCH_PREFIX))
    relevant |= expanded

    # Typen, von denen wir direkt oder indirekt erben: Änderungen dort sind am kritischsten
    inherited = set()
    for c in own.values():
        for parent in [c.super] + c.interfaces:
            if parent:
                inherited.update(x for x in old.supertypes(parent) if x.startswith(WATCH_PREFIX))

    # 2. Linkage: jede Referenz unseres Codes muss in der neuen Version auflösbar sein
    for c in sorted(own.values(), key=lambda x: x.name):
        for kind, owner, name, desc in sorted(c.refs):
            if not owner.startswith(WATCH_PREFIX):
                continue
            if old.resolve(kind, owner, name, desc) is None:
                continue  # schon in der alten Version nicht im Klassenpfad (z. B. Array-clone)
            if new.get(owner) is None:
                problems.append("`%s` referenziert `%s`, die Klasse existiert nicht mehr"
                                % (dotted(c.name), dotted(owner)))
            elif new.resolve(kind, owner, name, desc) is None:
                problems.append("`%s` ruft `%s#%s %s` auf, das existiert in der neuen Version nicht mehr"
                                % (dotted(c.name), dotted(owner), name, desc))

    # 3. Overrides: was alt überschrieben wurde, muss neu weiterhin überschrieben werden
    for c in sorted(own.values(), key=lambda x: x.name):
        parents = [p for p in [c.super] + c.interfaces if p]
        for (name, desc), acc in sorted(c.methods.items()):
            if name in ("<init>", "<clinit>") or acc & (ACC_STATIC | ACC_PRIVATE):
                continue
            for p in parents:
                hit_old = old.resolve("method", p, name, desc)
                if hit_old and is_api(hit_old[1]) and not hit_old[1] & ACC_STATIC:
                    hit_new = new.resolve("method", p, name, desc)
                    if hit_new is None or not is_api(hit_new[1]) or hit_new[1] & (ACC_STATIC | ACC_FINAL):
                        problems.append("`%s#%s%s` überschreibt in der neuen Version nichts mehr "
                                        "(vorher `%s`) - unser Code würde nicht mehr aufgerufen"
                                        % (dotted(c.name), name, desc, dotted(hit_old[0])))
                    break

    # 4. Neue abstrakte Methoden in Typen, die wir erweitern/implementieren
    for c in sorted(own.values(), key=lambda x: x.name):
        if c.access & (ACC_ABSTRACT | ACC_INTERFACE):
            continue
        for p in [c.super] + c.interfaces:
            for t in new.supertypes(p) if p else []:
                tc = new.get(t)
                for (name, desc), acc in tc.methods.items():
                    if not acc & ACC_ABSTRACT:
                        continue
                    oc = old.get(t)
                    if oc and (name, desc) in oc.methods and oc.methods[(name, desc)] & ACC_ABSTRACT:
                        continue
                    # implementiert irgendwer in der Kette (inkl. uns) die Methode konkret?
                    implemented = (name, desc) in c.methods or any(
                        (name, desc) in new.get(x).methods and not new.get(x).methods[(name, desc)] & ACC_ABSTRACT
                        for x in new.supertypes(c.super) if c.super)
                    if not implemented:
                        problems.append("`%s` erweitert `%s`, dort ist die abstrakte Methode `%s%s` neu "
                                        "(AbstractMethodError beim Aufruf)" % (dotted(c.name), dotted(t), name, desc))

    # 5. API- und Quelltextänderungen pro relevanter Klasse
    for t in sorted(relevant):
        notes = []
        oc, nc = old.get(t), new.get(t)
        if oc is None:
            continue
        if nc is None:
            problems.append("Klasse `%s` wurde entfernt" % dotted(t))
            continue
        if oc.super != nc.super:
            notes.append("Oberklasse geändert: `%s` → `%s`" % (dotted(oc.super or "-"), dotted(nc.super or "-")))
        if set(oc.interfaces) != set(nc.interfaces):
            notes.append("Interfaces geändert: %s → %s" % (sorted(map(dotted, oc.interfaces)),
                                                             sorted(map(dotted, nc.interfaces))))
        for label, om, nm in (("Methode", oc.methods, nc.methods), ("Feld", oc.fields, nc.fields)):
            for key in sorted(set(om) | set(nm)):
                a, b = om.get(key), nm.get(key)
                if a is not None and b is not None:
                    if is_api(a) or is_api(b):
                        mask = ACC_PUBLIC | ACC_PROTECTED | ACC_PRIVATE | ACC_STATIC | ACC_FINAL | ACC_ABSTRACT
                        if a & mask != b & mask:
                            notes.append("%s `%s%s`: %s → %s" % (label, key[0], key[1], flags(a), flags(b)))
                elif a is not None and is_api(a):
                    notes.append("%s entfernt: `%s %s%s`" % (label, flags(a), key[0], key[1]))
                elif b is not None and is_api(b):
                    notes.append("%s neu: `%s %s%s`" % (label, flags(b), key[0], key[1]))
        src_old, src_new = old.source(t), new.source(t)
        diff = None
        if src_old is not None and src_new is not None and "$" not in t:
            if src_old != src_new:
                diff = list(difflib.unified_diff(src_old, src_new, "%s (alt)" % t, "%s (neu)" % t, lineterm="", n=3))
        if notes or diff:
            findings[t] = (notes, diff)

    return relevant, inherited, problems, findings


def render(old_v, new_v, relevant, inherited, problems, findings):
    lines = ["## API-Vergleich Keycloak %s → %s" % (old_v, new_v), ""]
    lines.append("Geprüft: **%d** Keycloak-Typen, die unser Code benutzt oder von denen er erbt." % len(relevant))
    lines.append("")
    if problems:
        lines.append("### ❌ Inkompatibilitäten (alte Jars brechen zur Laufzeit)")
        lines.append("")
        lines += ["- " + p for p in problems]
        lines.append("")
    else:
        lines.append("✅ Alle referenzierten Methoden/Felder existieren weiter, alle Overrides greifen weiter.")
        lines.append("")
    if findings:
        lines.append("### ⚠️ Geänderte Klassen (Verhalten prüfen)")
        lines.append("")
        lines.append("**erbt** = unsere Klassen erweitern/implementieren diesen Typ (Verhaltensänderungen "
                     "wirken direkt auf uns), **verwendet** = nur aufgerufen oder als Typ benutzt.")
        lines.append("")
        lines.append("| Bezug | Klasse | API-Änderungen | Quelltext-Diff |")
        lines.append("|---|---|---|---|")
        for t, (notes, diff) in findings.items():
            changed = sum(1 for d in diff[2:] if d[:1] in "+-") if diff else 0
            lines.append("| %s | `%s` | %d | %s |" % ("**erbt**" if t in inherited else "verwendet", dotted(t),
                                                   len(notes), ("%d Zeilen" % changed) if diff else "-"))
        lines.append("")
        for t, (notes, diff) in findings.items():
            lines.append("<details><summary><code>%s</code></summary>" % dotted(t))
            lines.append("")
            lines += ["- " + n for n in notes]
            if diff:
                shown = diff[:MAX_DIFF_LINES]
                lines.append("")
                lines.append("```diff")
                lines += shown
                if len(diff) > MAX_DIFF_LINES:
                    lines.append("... (%d weitere Zeilen gekürzt)" % (len(diff) - MAX_DIFF_LINES))
                lines.append("```")
            lines.append("")
            lines.append("</details>")
            lines.append("")
    else:
        lines.append("✅ Keine der relevanten Keycloak-Klassen hat sich geändert.")
        lines.append("")
    lines.append("<details><summary>Liste der geprüften Typen</summary>")
    lines.append("")
    lines += ["- `%s`" % dotted(t) for t in sorted(relevant)]
    lines.append("")
    lines.append("</details>")
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--classes", required=True, help="kompilierte Klassen unserer Extensions")
    ap.add_argument("--old-version", required=True)
    ap.add_argument("--old-jars", required=True)
    ap.add_argument("--old-sources")
    ap.add_argument("--new-version", required=True)
    ap.add_argument("--new-jars", required=True)
    ap.add_argument("--new-sources")
    ap.add_argument("--report", help="Markdown-Report schreiben")
    ap.add_argument("--status", help="Statuszeile (STATUS<TAB>Text) schreiben")
    args = ap.parse_args()

    own = load_own_classes(args.classes)
    old = ClassPath(args.old_jars, args.old_sources)
    new = ClassPath(args.new_jars, args.new_sources)
    relevant, inherited, problems, findings = analyse(own, old, new)
    # Klassen, von denen wir erben, zuerst
    findings = dict(sorted(findings.items(), key=lambda kv: (kv[0] not in inherited, kv[0])))
    md = render(args.old_version, args.new_version, relevant, inherited, problems, findings)

    if args.report:
        with open(args.report, "w") as fh:
            fh.write(md)
    else:
        sys.stdout.write(md)

    if problems:
        status = ("FAIL", "%d Inkompatibilität(en), %d geänderte Klasse(n)" % (len(problems), len(findings)))
    elif findings:
        inh = [dotted(t).rsplit(".", 1)[-1] for t in findings if t in inherited]
        status = ("WARN", "%d von %d relevanten Klassen geändert, davon %d Oberklassen%s" % (
            len(findings), len(relevant), len(inh), (": " + ", ".join(inh)) if inh else ""))
    else:
        status = ("PASS", "keine relevanten Klassen geändert (%d geprüft)" % len(relevant))
    if args.status:
        with open(args.status, "w") as fh:
            fh.write("%s\t%s\n" % status)
    print("%s: %s" % status, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
