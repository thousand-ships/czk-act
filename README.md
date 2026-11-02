# czk-act

Act on a saved [Czkawka](https://github.com/qarmin/czkawka) duplicate-results JSON **without rescanning**.
Answers qarmin/czkawka#1295 and #269: "I saved the results of a week-long scan but cannot load them back."

> **Disclosure:** this tool was written and tested by AI agents, not by the Czkawka
> maintainers. It is not affiliated with Czkawka. Read the dry-run output before you use `--apply`.

- One file, `czk_act.py`, Python 3.8+ standard library only. No install step.
- **Dry run is the default.** Nothing on disk changes unless you pass `--apply`.
- Every file is re-checked on disk before anything happens (see INVARIANTS.md).

## Get results from Czkawka
```
czkawka_cli dup -d /mnt/big -p results.json      # pretty JSON (or -C for compact)
```
or the GUI/Krokiet **Save** button (`results_duplicates_pretty.json`). All duplicate modes (hash, size, name,
size+name) and reference-folder results are understood; the shape is detected automatically (SCHEMA.md).

## Usage
```
python3 czk_act.py results.json [--keep-rule RULE] [--action ACTION] [--verify LEVEL] [--apply] [--csv report.csv] [--i-accept-unverified]
```
| option | values | default |
|---|---|---|
| `--keep-rule` | `first` (first listed), `oldest`, `newest` (by current mtime), `shortest-path`, `path-prefix=/dir` (keep the copy under this folder; groups with no copy there are skipped) | `first` |
| `--action` | `report`, `delete`, `hardlink`, `symlink` | `report` |
| `--verify` | `exists` (present, regular file, same size as the scan), `size` (also same mtime as the scan), `hash` (same size and identical content by SHA-256 over the full file). `exists` with `--apply` and a destructive action is refused unless `--i-accept-unverified` is also given | `hash` |
| `--apply` | actually change files | off (dry run) |
| `--csv FILE` | CSV of every member: group, role, status, path, size, keeper, note. See "CSV report" below for what FILE may be | none |
| `--i-accept-unverified` | allow `--verify exists` with a destructive `--apply` (file content is **not** checked; a file edited since the scan with the same size would be lost) | off |

Examples:
```
python3 czk_act.py results.json                                    # what is still a duplicate today?
python3 czk_act.py results.json --action hardlink                  # preview
python3 czk_act.py results.json --action hardlink --apply          # do it
python3 czk_act.py results.json --action delete --keep-rule path-prefix=/mnt/big/master --apply --csv done.csv
```

## What it guarantees
- One copy per group is kept and never modified; it is re-checked before each change, and the group stops if it changed or vanished.
- Missing, changed-size, non-regular and (with `--verify size`) changed-mtime files are skipped and listed. A group with fewer than 2 verified copies is skipped.
- `--verify hash` reads every file and only acts on copies whose content equals the kept copy. Czkawka's Blake3 hash is not in the Python standard library, so czk-act computes its own SHA-256; the hash stored in the JSON is never trusted for content.
- Name/size/size+name results have no hash. Destructive actions on them require `--verify hash` (the default).
- The whole JSON is validated before anything happens (paths, sizes, dates, one shape per file); anything off is exit 2 with nothing done.
- Hardlinks and symlinks are made under a temporary name and moved into place with an atomic rename.
- Symlinked members are never deleted or used as the kept copy; the same file reached by two paths is never deleted.
- A second run changes nothing. A hardlink that fails (e.g. across drives) is reported for that file and the run continues.
- With reference folders, the file in the reference folder is always kept.

## CSV report
- FILE must not be the results JSON or any file listed in it, under any spelling or alias (symlink, hardlink, `./`, symlinked directory). czk-act refuses with exit 2 before doing anything.
- An existing FILE is overwritten only if it is empty, or its name ends in `.csv`; otherwise exit 2. A directory or dangling symlink is refused.
- The destination is opened before anything is changed (a missing directory is exit 2, nothing done). The report is written to a temp file next to FILE and renamed over it.
- Cells that start with `=` `+` `-` `@` tab, CR or `'` get one leading `'` so spreadsheets do not run them as formulas. To get the exact path back, drop one leading `'`. Czkawka writes absolute paths (they start with `/`), so those are never changed.

## Exit codes
`0` done, nothing stale · `3` done, some files skipped because they no longer match the saved results · `4` done, but at least one group was refused by a rule (name/size results without `--verify hash`, or no copy under `path-prefix`) so nothing happened to it · `1` at least one action failed, or actions were applied and the CSV could not be written afterwards (the applied actions are printed to stderr) · `2` bad arguments, unreadable/unknown/invalid JSON, a refused `--csv` destination, or `--verify exists --apply` without `--i-accept-unverified` (nothing done). If several apply, the first in the order 2, 1, 3, 4, 0 wins.
A second `delete --apply` run exits 3, because the files it deleted the first time are now "missing".

## Tests
```
python3 -m unittest discover -s tests -v       # unit tests
python3 -m unittest discover -s blackbox -v    # independent black-box suite
```

Version 0.2.0 (round-1 fixes, see FIXES-r1.md).

## Limits
- Checked against real `czkawka_cli` 12.0.2 JSON (Docker image, 2026-11-02; see ROUNDTRIP.md). Older Czkawka releases and Windows are untested.
- Similar-images / similar-videos / same-music results are different formats and are not supported.
- Paths are used as written in the JSON; results from another machine or a different mount point need the same paths.
- `--verify hash` reads every listed file in full, which is slow on large drives (that is the point: no trust in old data).

License: MIT.
