#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The PYTHON leg of the T10 conformance oracle.

Runs `seetrex_verifier.py` over every case of
`crates/verifier/tests/fixtures/corpus/` and compares its answer with the
answer the SPECIFICATION gives in that case's `expected.txt`. The Rust leg
(`crates/verifier/tests/corpus_equivalence.rs`) answers the same files from
the same expectations, so a divergence shows up as ONE leg red and the corpus
can indict either implementation.

The Python is written to the CLI shape of spec 9.6 / 8.1, so -- unlike the
Rust leg -- this runner needs no adapter: `cmd.txt` is passed through as
written. Standard library only, like the verifier it drives.

    python3 crates/verifier/reference/run_corpus.py

**The two legs must be equally strict, or the weaker one is where a
regression hides.** This runner therefore checks the same four axes the Rust
leg checks -- exit code, outcome token, the OTHER mode's token, and the
reserved-token sanitizer -- and parses `expected.txt` with the same strict
parser: an unrecognised line, a missing `# spec:` citation or a `class=` that
disagrees with the `token=`/`exit=` beside it is an error here, never a
silently ignored line.

The one axis this leg cannot check is whether a `# spec:` heading RESOLVES in
the specification: the document lives outside this crate and nothing here
reads outside it. The Rust leg owns that check.

Everything this runner opens is resolved from its own location and stays
inside `crates/verifier`; no path here climbs above the crate.
"""
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
VERIFIER = HERE / "seetrex_verifier.py"
CORPUS = HERE.parent / "tests" / "fixtures" / "corpus"

# The two success tokens 9.6's binding table defines, the token 9.6 RESERVES
# for the strong surfaces, and the success token 8.1 binds for `verify-chain`
# -- one of the two surfaces the reserved word belongs to, which is why a
# failing chain run is held to that token's ABSENCE and not to the 9.6 rule.
TOKEN_ANCHORED = "INTEGRITY-OK (weak)"
TOKEN_UNANCHORED = "SELF-CONSISTENT (unanchored)"
RESERVED_TOKEN = "VERIFIED"
TOKEN_CHAIN = "VERIFIED OFFLINE"

# A suite that runs almost nothing passes for the wrong reason. Same floor,
# and same reason, as `load_corpus()` in the Rust leg.
CASE_FLOOR = 40

CLASSES = ("PASS", "PASS_UNANCHORED", "FAIL")


def die(case_name, message):
    raise SystemExit("case %s: %s" % (case_name, message))


def subject(case):
    """The file or directory `{PKG}` stands for, exactly as the Rust leg resolves it."""
    pkg = case / "pkg"
    if pkg.is_dir():
        return pkg
    export = case / "export.json"
    if export.is_file():
        return export
    die(case.name, "carries neither pkg/ nor export.json. Material that ships "
                   "elsewhere in the repository is COPIED into the case, never "
                   "resolved by an indirection out of the corpus.")


def expectation(case):
    """`token`, `exit`, `class`, `# spec:` and `sanitize` as the file states them.

    Strict by construction: every non-empty line must be one this parser
    knows. A lenient parser is the quiet way an expectation stops being
    checked -- a typo in `token=` would leave that axis unasserted and the
    case green.
    """
    path = case / "expected.txt"
    if not path.is_file():
        die(case.name, "has no expected.txt; a case without an expectation "
                       "must be loud, never skipped")
    token = exit_code = klass = heading = None
    sanitize = ""
    # Split on the NEWLINE alone, never `splitlines()` (R3-B I-5): Python
    # also breaks lines at the vertical tab, form feed, the file/group/record
    # separators, NEL and the Unicode line separator, and the Rust leg's `str::lines()` does not. An expectation file carrying one of
    # those bytes would be read as two lines by this leg and as one by the
    # other, so a `token=` could be hidden from one implementation.
    for raw in path.read_text(encoding="utf-8").split("\n"):
        line = raw.rstrip("\r\n")
        if line.startswith("# spec:"):
            heading = line[len("# spec:"):].strip()
        elif line.startswith("# gap:"):
            gap = line[len("# gap:"):].strip()
            if not (gap.startswith("SPEC-GAP-") or gap.startswith("DIV-")):
                die(case.name, "carries `# gap: %s`, which is not a ledger id" % gap)
        elif line.startswith("# note:"):
            # Free prose: WHY the specification gives this answer, written when
            # the case was authored and before either binary ran.  Ignored on
            # purpose -- the expectation is token/exit/class.  A NAMED key, not
            # a lenient catch-all: an unrecognised line still dies.
            pass
        elif line.startswith("sanitize="):
            sanitize = line[len("sanitize="):].strip()
            if sanitize != "ci":
                die(case.name, "unknown sanitize mode %r" % sanitize)
        elif line.startswith("token="):
            token = line[len("token="):]
        elif line.startswith("exit="):
            try:
                exit_code = int(line[len("exit="):].strip())
            except ValueError:
                die(case.name, "exit= is not an integer: %r" % line)
        elif line.startswith("class="):
            klass = line[len("class="):].strip()
            if klass not in CLASSES:
                die(case.name, "unknown class %r" % klass)
        elif line.strip():
            die(case.name, "unrecognised line in expected.txt: %r" % line)
    for name, value in (("token=", token), ("exit=", exit_code),
                        ("class=", klass), ("# spec:", heading)):
        if value is None:
            die(case.name, "expected.txt has no `%s` line" % name)
    return token, exit_code, klass, sanitize


def check_class(case_name, token, exit_code, klass, sub):
    """`class=` must agree with the `token=`/`exit=` beside it.

    The three axes are written by hand, so a case can state a class its own
    token and exit contradict; that case then asserts something nobody
    intended. 9.6 binds the package outcomes (0/4/1), 8.1 the chain ones.
    """
    if klass == "FAIL":
        if exit_code != 1 or token != "":
            die(case_name, "class=FAIL but token=%r exit=%d; a failing run "
                           "exits 1 and prints no success token"
                           % (token, exit_code))
    elif klass == "PASS_UNANCHORED":
        if exit_code != 4 or token != TOKEN_UNANCHORED:
            die(case_name, "class=PASS_UNANCHORED but token=%r exit=%d; 9.6 "
                           "binds that outcome to %r and exit 4"
                           % (token, exit_code, TOKEN_UNANCHORED))
    else:
        want = TOKEN_CHAIN if sub == "verify-chain" else TOKEN_ANCHORED
        if exit_code != 0 or token != want:
            die(case_name, "class=PASS but token=%r exit=%d; the binding for "
                           "%s is %r and exit 0"
                           % (token, exit_code, sub, want))


def subcommand(case_name, argv):
    if "--package-dir" in argv:
        return "verify-package"
    if "--chain-export" in argv:
        return "verify-chain"
    die(case_name, "cmd.txt names neither --package-dir nor --chain-export")


def main():
    cases = sorted(p for p in CORPUS.iterdir() if p.is_dir())
    if len(cases) <= CASE_FLOOR:
        raise SystemExit("only %d corpus case(s) under %s; a suite that runs "
                         "almost nothing passes for the wrong reason"
                         % (len(cases), CORPUS))
    passed = 0
    for case in cases:
        token, exit_want, klass, sanitize = expectation(case)
        argv = [a.replace("{PKG}", str(subject(case)))
                for a in (case / "cmd.txt").read_text(encoding="utf-8").split()]
        sub = subcommand(case.name, argv)
        check_class(case.name, token, exit_want, klass, sub)
        run = subprocess.run([sys.executable, str(VERIFIER), sub] + argv,
                             capture_output=True, text=True)
        # Split on the NEWLINE alone, not with `splitlines()` (R2-B M-2):
        # Python splits on a dozen Unicode line boundaries -- vertical tab,
        # form feed, the C1 file/group/record separators, U+2028 and U+2029 --
        # that Rust's `str::lines()` does not, so a tool line carrying one of
        # them was ONE line to the Rust leg and TWO to this one: the two legs
        # read the same output differently.  A trailing carriage return is
        # stripped, which is the rest of what `lines()` does.
        out_lines = [line.strip("\r").strip() for line in run.stdout.split("\n")]
        err_lines = [line.strip("\r").strip() for line in run.stderr.split("\n")]
        combined = run.stdout + run.stderr
        problems = []
        if run.returncode != exit_want:
            problems.append("exit %d, expected %d" % (run.returncode, exit_want))
        if sanitize == "ci":
            unmasked = combined.replace("VERIF[REDACTED]", "")
            if "verified" in unmasked.lower():
                problems.append("reserved token leaked in some casing past the sanitizer")
        if klass == "FAIL":
            if sub == "verify-chain":
                # 8.1: a failing chain verification prints no success token.
                if TOKEN_CHAIN in combined:
                    problems.append("success token %r printed by a failing "
                                    "chain verification" % TOKEN_CHAIN)
            else:
                # 9.6: a failing run prints an error line and NO success token.
                # Failures print on stderr, so both streams are read; the
                # RESERVED token is a SUBSTRING check, uppercased, because the
                # point of the reserve is that it must not appear anywhere in
                # a weak check's output -- interpolated package bytes included.
                for leaked in (TOKEN_ANCHORED, TOKEN_UNANCHORED):
                    if leaked in out_lines or leaked in err_lines:
                        problems.append("success token %r printed by a failing run" % leaked)
                if RESERVED_TOKEN in combined.upper():
                    problems.append("reserved token %r leaked from a failing "
                                    "weak-mode run" % RESERVED_TOKEN)
        elif sub == "verify-chain":
            # 8.1 binds the chain token as CONTAINED in the success line, not
            # as a whole line: the reference prints it inside a sentence.
            if token and not any(token in line for line in run.stdout.split("\n")):
                problems.append("token %r on no stdout line" % token)
        else:
            # 9.6 binds the package token as a LINE, and a pass must not carry
            # the other mode's token either -- an exit 4 read as an exit 0 is
            # the confusion the two tokens exist to prevent.
            if token and token not in out_lines:
                problems.append("token %r not on stdout" % token)
            other = TOKEN_UNANCHORED if token == TOKEN_ANCHORED else TOKEN_ANCHORED
            if token and other in out_lines:
                problems.append("token %r leaked into a %r pass" % (other, token))
        if problems:
            print("FAIL %-32s %s" % (case.name, "; ".join(problems)))
        else:
            passed += 1
            print("ok   %s" % case.name)
    print("PYTHON LEG: %d/%d" % (passed, len(cases)))
    return 0 if passed == len(cases) else 1


if __name__ == "__main__":
    sys.exit(main())
