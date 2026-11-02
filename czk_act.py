#!/usr/bin/env python3
"""czk-act: act on a saved Czkawka duplicate-results JSON without rescanning.

Single file, Python 3.8+ standard library only. Built by AI agents (see README.md).

Dry run is the default. Nothing on disk changes without --apply.
Schema notes: SCHEMA.md. Safety rules: INVARIANTS.md.
"""

import argparse
import csv
import errno
import hashlib
import json
import os
import secrets
import tempfile
import stat
import sys

__version__ = "0.2.0"

EXIT_OK = 0
EXIT_FAILURES = 1
EXIT_USAGE = 2
EXIT_SKIPS = 3
EXIT_REFUSED = 4

DESTRUCTIVE = ("delete", "hardlink", "symlink")
ACTED = {"deleted", "hardlinked", "symlinked"}
# Statuses meaning "a safety or keep rule refused the whole group" (exit 4 if nothing worse happened).
REFUSED = {"group-refused"}

# Member statuses that mean "the saved result no longer matches the disk".
STALE = {"missing", "not-regular", "size-changed", "mtime-changed", "content-mismatch",
         "symlink", "unreadable", "changed-before-act"}

CHUNK = 1024 * 1024


class InputError(Exception):
    pass


# ---------------------------------------------------------------- parsing

def _is_int(x):
    return isinstance(x, int) and not isinstance(x, bool)


def _check_path(p, where):
    if not isinstance(p, str):
        raise InputError("%s: \"path\" must be a string" % where)
    if not p:
        raise InputError("%s: \"path\" is empty" % where)
    if "\x00" in p:
        raise InputError("%s: \"path\" contains a NUL character" % where)
    try:
        os.fsencode(p)
    except (UnicodeError, ValueError):
        raise InputError("%s: \"path\" cannot be encoded for this filesystem" % where)


def _norm_entry(e, where):
    """Validate one DuplicateEntry strictly (SCHEMA.md) and return a normalised copy."""
    if not isinstance(e, dict):
        raise InputError("%s: expected an entry object" % where)
    if "path" not in e:
        raise InputError("%s: entry has no \"path\"" % where)
    _check_path(e["path"], where)
    size = e.get("size")
    if not _is_int(size) or size < 0:
        raise InputError("%s: \"size\" must be a non-negative integer, got %r" % (where, size))
    mtime = e.get("modified_date")
    if not _is_int(mtime) or mtime < 0:
        raise InputError("%s: \"modified_date\" must be a non-negative integer, got %r" % (where, mtime))
    h = e.get("hash", "")
    if not isinstance(h, str):
        raise InputError("%s: \"hash\" must be a string" % where)
    return {"path": e["path"], "size": size, "modified_date": mtime, "hash": h}


def _is_ref_pair(v):
    return isinstance(v, list) and len(v) == 2 and isinstance(v[0], dict) and isinstance(v[1], list)


def _is_entry_list(v):
    return isinstance(v, list) and len(v) > 0 and all(isinstance(x, dict) for x in v)


def _group_from(value, key, where):
    """Return (group, kind) where kind is 'ref' or 'plain'. Raises InputError if not a group."""
    if _is_ref_pair(value):
        ref = _norm_entry(value[0], where + " reference")
        others = [_norm_entry(x, "%s member %d" % (where, i + 1)) for i, x in enumerate(value[1])]
        return {"key": key, "reference": True, "members": [ref] + others}, "ref"
    if _is_entry_list(value):
        return ({"key": key, "reference": False,
                 "members": [_norm_entry(x, "%s member %d" % (where, i + 1)) for i, x in enumerate(value)]},
                "plain")
    raise InputError("%s: unrecognised group shape" % where)


def _groups_from_value(value, key):
    """One value of the top-level object. Returns (groups, shape) or ([], None) for an empty list."""
    where = "key %r" % key
    if not isinstance(value, list):
        raise InputError("%s: unrecognised value shape" % where)
    if not value:
        return [], None
    if _is_ref_pair(value) or _is_entry_list(value):
        g, kind = _group_from(value, key, where)
        return [g], ("size/name+reference" if kind == "ref" else "size/name")
    if all(isinstance(x, list) for x in value):
        out, kinds = [], set()
        for i, sub in enumerate(value):
            sg, kind = _group_from(sub, key if len(value) == 1 else "%s#%d" % (key, i + 1),
                                   "%s group %d" % (where, i + 1))
            out.append(sg)
            kinds.add(kind)
        if len(kinds) > 1:
            raise InputError("%s: mixes reference and non-reference groups" % where)
        return out, ("hash+reference" if kinds == {"ref"} else "hash")
    raise InputError("%s: unrecognised value shape" % where)


def parse_results(data):
    """Turn any Czkawka duplicate JSON shape (SCHEMA.md) into a list of groups.

    Validation is strict and complete before anything is returned: every entry must have a non-empty
    string path without NUL, non-negative integer size and modified_date, and a string hash (if present);
    all groups in one file must have the same shape. Any violation raises InputError (exit 2, nothing done).
    """
    groups = []
    shapes = set()
    if isinstance(data, dict):
        for k, v in data.items():
            gs, shape = _groups_from_value(v, str(k))
            groups.extend(gs)
            if shape:
                shapes.add(shape)
    elif isinstance(data, list):
        for i, v in enumerate(data):
            g, kind = _group_from(v, "#%d" % (i + 1), "top-level index %d" % i)
            groups.append(g)
            shapes.add("size+name+reference" if kind == "ref" else "size+name")
    else:
        raise InputError("top level must be a JSON object or array")
    if len(shapes) > 1:
        raise InputError("groups have different shapes (%s); not one Czkawka results file"
                         % ", ".join(sorted(shapes)))
    for gi, g in enumerate(groups, 1):
        g["id"] = gi
        for mi, m in enumerate(g["members"]):
            m["index"] = mi
    return groups


def load_results(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except OSError as e:
        raise InputError("cannot read %s: %s" % (path, e))
    except ValueError as e:
        raise InputError("%s is not valid JSON: %s" % (path, e))
    except RecursionError:
        raise InputError("%s is nested too deeply to be Czkawka output" % path)
    return parse_results(data)


# ---------------------------------------------------------------- verification

def snapshot(path):
    st = os.lstat(path)
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, stat.S_IFMT(st.st_mode))


def sha256_file(path):
    h = hashlib.sha256()
    # O_NOFOLLOW where available, so a member swapped for a symlink is not read through.
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as f:
        while True:
            b = f.read(CHUNK)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def verify_member(m, verify):
    """Fill m['status'], m['snap'], m['real'], m['mtime_ns']. Status 'ok' means usable."""
    p = m["path"]
    m["note"] = ""
    try:
        st = os.lstat(p)
    except FileNotFoundError:
        m["status"] = "missing"
        return
    except (OSError, ValueError) as e:
        m["status"] = "unreadable"
        m["note"] = str(e)
        return
    m["real"] = os.path.realpath(p)
    if stat.S_ISLNK(st.st_mode):
        m["status"] = "symlink"
        return
    if not stat.S_ISREG(st.st_mode):
        m["status"] = "not-regular"
        return
    if m["size"] >= 0 and st.st_size != m["size"]:
        m["status"] = "size-changed"
        m["note"] = "json %d, disk %d" % (m["size"], st.st_size)
        return
    if verify == "size" and int(st.st_mtime) != m["modified_date"]:
        m["status"] = "mtime-changed"
        m["note"] = "json %d, disk %d" % (m["modified_date"], int(st.st_mtime))
        return
    m["snap"] = (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, stat.S_IFMT(st.st_mode))
    m["mtime_ns"] = st.st_mtime_ns
    if verify == "hash":
        try:
            m["digest"] = sha256_file(p)
        except (OSError, ValueError) as e:
            m["status"] = "unreadable"
            m["note"] = str(e)
            return
        # Content is authoritative; reject if the file changed while we hashed it.
        try:
            if snapshot(p) != m["snap"]:
                m["status"] = "changed-before-act"
                m["note"] = "changed while hashing"
                return
        except (OSError, ValueError):
            m["status"] = "missing"
            return
        if int(st.st_mtime) != m["modified_date"]:
            m["note"] = "mtime differs from scan; content verified"
    m["status"] = "ok"


# ---------------------------------------------------------------- keep rules

def parse_keep_rule(s):
    if s in ("first", "oldest", "newest", "shortest-path"):
        return (s, None)
    if s.startswith("path-prefix="):
        prefix = s[len("path-prefix="):]
        if not prefix:
            raise argparse.ArgumentTypeError("path-prefix= needs a value")
        return ("path-prefix", prefix)
    raise argparse.ArgumentTypeError(
        "keep rule must be first, oldest, newest, shortest-path or path-prefix=X")


def _under_prefix(path, prefix):
    p = os.path.normpath(os.path.abspath(path))
    pre = os.path.normpath(os.path.abspath(prefix))
    return p == pre or p.startswith(pre.rstrip(os.sep) + os.sep)


def choose_keeper(cands, rule):
    name, arg = rule
    if name == "first":
        return min(cands, key=lambda m: m["index"])
    if name == "oldest":
        return min(cands, key=lambda m: (m["mtime_ns"], m["index"]))
    if name == "newest":
        return min(cands, key=lambda m: (-m["mtime_ns"], m["index"]))
    if name == "shortest-path":
        return min(cands, key=lambda m: (len(m["path"]), m["index"]))
    if name == "path-prefix":
        hits = [m for m in cands if _under_prefix(m["path"], arg)]
        return min(hits, key=lambda m: m["index"]) if hits else None
    raise ValueError(name)


# ---------------------------------------------------------------- acting

def _before_act(member, keeper):
    """Test hook: called right before re-verification of each act."""


def _tmp_name(path):
    d, base = os.path.split(path)
    return os.path.join(d, ".%s.czkact-%s.tmp" % (base, secrets.token_hex(6)))


def _replace_with_link(member_path, make_link):
    tmp = _tmp_name(member_path)
    try:
        make_link(tmp)
        os.replace(tmp, member_path)
    except BaseException:
        try:
            if os.path.lexists(tmp):
                os.unlink(tmp)
        except OSError:
            pass
        raise


def act(action, member, keeper):
    """Perform one action. Returns (status, note). Raises nothing."""
    _before_act(member, keeper)
    try:
        if snapshot(keeper["path"]) != keeper["snap"]:
            return ("keeper-changed", "keeper changed or vanished; group aborted")
    except (OSError, ValueError):
        return ("keeper-changed", "keeper vanished; group aborted")
    try:
        if snapshot(member["path"]) != member["snap"]:
            return ("changed-before-act", "member changed since verification")
    except (OSError, ValueError):
        return ("changed-before-act", "member vanished since verification")
    try:
        if action == "delete":
            os.unlink(member["path"])
            return ("deleted", "")
        if action == "hardlink":
            _replace_with_link(member["path"], lambda tmp: os.link(keeper["path"], tmp))
            return ("hardlinked", "")
        if action == "symlink":
            target = keeper["real"]
            _replace_with_link(member["path"], lambda tmp: os.symlink(target, tmp))
            return ("symlinked", "")
    except OSError as e:
        if e.errno == errno.EXDEV:
            return ("failed", "cross-device: cannot hardlink across filesystems")
        return ("failed", "%s: %s" % (type(e).__name__, e.strerror or e))
    except ValueError as e:
        return ("failed", "%s: %s" % (type(e).__name__, e))
    return ("failed", "unknown action")


# ---------------------------------------------------------------- planning

def process_group(g, args, rows, counts):
    members = g["members"]
    destructive = args.action != "report"
    gid = g["id"]

    def row(m, role, status, note="", keeper=None):
        rows.append({"group": gid, "group_key": g["key"], "role": role, "status": status,
                     "path": m["path"], "size": m["size"], "modified_date": m["modified_date"],
                     "action": args.action, "keeper": keeper["path"] if keeper else "",
                     "note": note})
        counts[status] = counts.get(status, 0) + 1

    for m in members:
        verify_member(m, args.verify)

    # Deduplicate by resolved real path (same entry listed twice or via a symlinked directory).
    seen = {}
    for m in members:
        if m["status"] == "ok":
            if m["real"] in seen:
                m["status"] = "duplicate-path"
                m["note"] = "same file as %s" % seen[m["real"]]["path"]
            else:
                seen[m["real"]] = m

    ok = [m for m in members if m["status"] == "ok"]
    ref = members[0] if g["reference"] else None

    def bad_row(m):
        # A symlink that already points at a verified member is the result of an earlier run.
        if m["status"] == "symlink" and m.get("real") in seen:
            row(m, "skip", "already-symlinked", "points to %s" % seen[m["real"]]["path"])
        else:
            row(m, "skip", m["status"], m.get("note", ""))

    def finish_unacted(reason_status, note):
        for m in members:
            if m["status"] == "ok":
                row(m, "skip", reason_status, note)
            else:
                bad_row(m)

    if g["reference"] and ref["status"] != "ok":
        finish_unacted("group-skipped", "reference file failed verification")
        return
    if len(ok) < 2:
        finish_unacted("group-skipped", "fewer than 2 verified members")
        return
    no_hash = any(not m["hash"] for m in members)
    if destructive and no_hash and args.verify != "hash":
        finish_unacted("group-refused",
                       "no stored hash (name/size mode); destructive action needs --verify hash")
        return

    # Partition by content when hashing.
    if args.verify == "hash":
        clusters = {}
        for m in ok:
            clusters.setdefault(m["digest"], []).append(m)
        if ref is not None:
            work = [clusters[ref["digest"]]]
        else:
            work = [c for c in clusters.values() if len(c) >= 2]
        in_work = {id(m) for c in work for m in c}
        for m in ok:
            if id(m) not in in_work:
                m["status"] = "content-mismatch"
                m["note"] = "content differs from the rest of the group"
    else:
        work = [ok]

    for m in members:
        if m["status"] != "ok":
            bad_row(m)

    for cluster in work:
        if ref is not None:
            keeper = ref
        else:
            keeper = choose_keeper(cluster, args.keep_rule)
        if keeper is None:
            for m in cluster:
                row(m, "skip", "group-refused", "no member under keep prefix")
            continue
        row(keeper, "keep", "keep", keeper.get("note", ""), keeper)
        aborted = False
        for m in cluster:
            if m is keeper:
                continue
            if m["snap"][:2] == keeper["snap"][:2]:
                row(m, "skip", "already-linked", "same inode as keeper", keeper)
                continue
            if aborted:
                row(m, "skip", "group-aborted", "keeper changed earlier in this group", keeper)
                continue
            if not destructive:
                row(m, "dup", "duplicate", m.get("note", ""), keeper)
                continue
            if not args.apply:
                row(m, "act", "would-" + args.action, m.get("note", ""), keeper)
                continue
            status, note = act(args.action, m, keeper)
            if status == "keeper-changed":
                aborted = True
            row(m, "act", status, note, keeper)


CSV_FIELDS = ["group", "group_key", "role", "status", "path", "size", "modified_date",
              "action", "keeper", "note"]


# Cells starting with one of these are prefixed with a single quote so spreadsheets do not run them as
# formulas (CSV injection). "'" itself is included so the escape is reversible: if a cell starts with "'",
# drop exactly one leading "'" to get the original text.
CSV_ESCAPE_LEAD = ("=", "+", "-", "@", "\t", "\r", "'")


def csv_cell(v):
    if isinstance(v, str) and v.startswith(CSV_ESCAPE_LEAD):
        return "'" + v
    return v


def csv_unescape(v):
    """Inverse of csv_cell for string cells read back from the CSV."""
    return v[1:] if v.startswith("'") else v


def _ident(p, follow=True):
    try:
        st = os.stat(p) if follow else os.lstat(p)
    except (OSError, ValueError):
        return None
    return (st.st_dev, st.st_ino)


def check_csv_dest(csv_path, results_path, groups):
    """Refuse a --csv destination that could destroy input (INVARIANTS 12). Returns the real path to write.

    Raises InputError (exit 2, nothing done) when the destination
      - is empty, or is (by spelling, realpath or same device/inode) the results JSON or any listed member;
      - exists and is not a regular file, or is a dangling symlink;
      - exists, is not empty, and its name does not end in .csv.
    """
    if not csv_path or "\x00" in csv_path:
        raise InputError("--csv needs a file name")
    listed = [results_path] + [m["path"] for g in groups for m in g["members"]]
    c_abs = os.path.normpath(os.path.abspath(csv_path))
    c_real = os.path.realpath(csv_path)
    for p in listed:
        if os.path.normpath(os.path.abspath(p)) == c_abs or os.path.realpath(p) == c_real:
            raise InputError("--csv %s is the results file or a listed file (%s); refusing" % (csv_path, p))
    if os.path.lexists(csv_path):
        if not os.path.exists(csv_path):
            raise InputError("--csv %s is a dangling symlink; refusing" % csv_path)
        st = os.stat(csv_path)
        if not stat.S_ISREG(st.st_mode):
            raise InputError("--csv %s exists and is not a regular file; refusing" % csv_path)
        me = (st.st_dev, st.st_ino)
        for p in listed:
            if _ident(p) == me or _ident(p, follow=False) == me:
                raise InputError("--csv %s is the same file as %s; refusing" % (csv_path, p))
        if st.st_size > 0 and not csv_path.lower().endswith(".csv"):
            raise InputError("--csv %s exists, is not empty and does not end in .csv; refusing to overwrite"
                             % csv_path)
    return c_real


class CsvDest(object):
    """A CSV destination opened before anything is acted on: a temp file next to the real target, renamed
    over it at the end. A listed file is never opened for writing, even if an alias slipped past the check."""

    def __init__(self, real_path):
        self.final = real_path
        d, base = os.path.split(real_path)
        fd, self.tmp = tempfile.mkstemp(prefix=".%s.czkact-" % base, suffix=".tmp", dir=d or ".")
        try:
            um = os.umask(0)
            os.umask(um)
            os.fchmod(fd, 0o666 & ~um)
        except (OSError, AttributeError):
            pass
        self.f = os.fdopen(fd, "w", newline="", encoding="utf-8")

    def commit(self, rows):
        try:
            w = csv.DictWriter(self.f, fieldnames=CSV_FIELDS)
            w.writeheader()
            for r in rows:
                w.writerow({k: csv_cell(v) for k, v in r.items()})
            self.f.flush()
            os.fsync(self.f.fileno())
            self.f.close()
            os.replace(self.tmp, self.final)
        except BaseException:
            self.discard()
            raise

    def discard(self):
        try:
            self.f.close()
        except (OSError, ValueError):
            pass
        try:
            if os.path.lexists(self.tmp):
                os.unlink(self.tmp)
        except OSError:
            pass


def write_csv(path, rows):
    """Write rows to path (escaped as above) via a temp file and atomic rename."""
    dest = CsvDest(os.path.realpath(path))
    dest.commit(rows)


def build_parser():
    p = argparse.ArgumentParser(
        prog="czk-act",
        description="Act on a saved Czkawka duplicate-results JSON without rescanning. "
                    "Dry run unless --apply is given.")
    p.add_argument("results", help="Czkawka JSON saved with czkawka_cli -C/-p or the GUI Save button")
    p.add_argument("--keep-rule", type=parse_keep_rule, default=("first", None),
                   help="first (default), oldest, newest, shortest-path, path-prefix=DIR")
    p.add_argument("--action", choices=["report", "delete", "hardlink", "symlink"], default="report")
    p.add_argument("--apply", action="store_true", help="really change files (default: dry run)")
    p.add_argument("--verify", choices=["exists", "size", "hash"], default="hash",
                   help="exists: present, regular, same size; size: also same mtime as the scan; "
                        "hash (default): present, same size, and SHA-256 of full content equal")
    p.add_argument("--csv", metavar="FILE",
                   help="also write a CSV report. Refused if FILE is the results JSON or a listed file, or "
                        "an existing non-empty file whose name does not end in .csv")
    p.add_argument("--i-accept-unverified", action="store_true",
                   help="allow --verify exists with a destructive --apply (content is NOT checked)")
    p.add_argument("-q", "--quiet", action="store_true", help="print only the summary")
    p.add_argument("--version", action="version", version="czk-act " + __version__)
    return p


def main(argv=None, out=None):
    out = out or sys.stdout
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        return EXIT_USAGE if e.code not in (0, None) else EXIT_OK

    def err(msg):
        print("czk-act: error: %s" % msg, file=sys.stderr)

    destructive = args.action in DESTRUCTIVE
    if destructive and args.verify == "exists":
        if args.apply and not args.i_accept_unverified:
            err("--verify exists does not check content: a file changed since the scan (same size) would be "
                "%s. Use --verify hash (default), or pass --i-accept-unverified to accept that risk. "
                "Nothing was done." % ("deleted" if args.action == "delete" else "replaced"))
            return EXIT_USAGE
        print("czk-act: warning: --verify exists does not check file content%s" %
              ("" if args.apply else "; --apply will also need --i-accept-unverified"), file=sys.stderr)

    try:
        groups = load_results(args.results)
        csv_dest = None
        if args.csv is not None:
            real = check_csv_dest(args.csv, args.results, groups)
            try:
                csv_dest = CsvDest(real)
            except OSError as e:
                raise InputError("cannot write CSV %s: %s" % (args.csv, e))
    except InputError as e:
        err("%s (nothing was done)" % e)
        return EXIT_USAGE

    rows, counts = [], {}
    try:
        for g in groups:
            process_group(g, args, rows, counts)
    except BaseException:
        if csv_dest is not None:
            csv_dest.discard()
        raise

    mode = "APPLY" if args.apply and destructive else "DRY RUN"
    if not args.quiet:
        last = None
        for r in rows:
            if r["group"] != last:
                print("group %d (%s)" % (r["group"], r["group_key"]), file=out)
                last = r["group"]
            print("  %-18s %s%s" % (r["status"], r["path"],
                                   ("  [" + r["note"] + "]") if r["note"] else ""), file=out)
    print("czk-act %s: action=%s verify=%s groups=%d" % (mode, args.action, args.verify, len(groups)),
          file=out)
    print("  " + ", ".join("%s=%d" % kv for kv in sorted(counts.items())) if counts else "  nothing to do",
          file=out)
    if mode == "DRY RUN" and destructive:
        print("  dry run: nothing was changed. Re-run with --apply to act.", file=out)
    refused = sum(v for k, v in counts.items() if k in REFUSED)
    if refused:
        print("  %d member(s) in refused groups: nothing was done for those groups (see notes)." % refused,
              file=out)

    if csv_dest is not None:
        try:
            csv_dest.commit(rows)
        except OSError as e:
            done = [r for r in rows if r["status"] in ACTED]
            err("cannot write CSV %s: %s" % (args.csv, e))
            if done:
                print("czk-act: %d action(s) WERE applied before the CSV failed:" % len(done), file=sys.stderr)
                for r in done:
                    print("  %s %s (keeper %s)" % (r["status"], r["path"], r["keeper"]), file=sys.stderr)
                return EXIT_FAILURES
            return EXIT_USAGE

    failed = counts.get("failed", 0) + counts.get("keeper-changed", 0)
    stale = sum(v for k, v in counts.items() if k in STALE)
    if failed:
        return EXIT_FAILURES
    if stale:
        return EXIT_SKIPS
    if refused:
        return EXIT_REFUSED
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
