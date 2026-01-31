import re
import subprocess
import sys


ALLOWED = set("0123456789+-()")


def extract_expr(line: str) -> str | None:
    # Find the longest contiguous substring that looks like an arithmetic expr.
    cands = re.findall(r"[0-9+\-()]{5,}", line)
    if not cands:
        return None
    cands.sort(key=len, reverse=True)
    for cand in cands:
        if "(" in cand and ")" in cand and any(ch.isdigit() for ch in cand):
            return cand
    return None


def safe_eval(expr: str) -> int:
    if not expr or any(ch not in ALLOWED for ch in expr):
        raise ValueError("invalid expression")
    # Only digits, +, -, parentheses. eval is safe after validation.
    return int(eval(expr))


def main() -> int:
    proc = subprocess.Popen(
        ["/readflag"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    assert proc.stdout is not None
    assert proc.stdin is not None

    expr_sent = False
    output_parts: list[str] = []

    while True:
        line = proc.stdout.readline()
        if not line:
            break
        output_parts.append(line)

        if not expr_sent:
            expr = extract_expr(line)
            if expr:
                try:
                    value = safe_eval(expr)
                except Exception:
                    continue
                proc.stdin.write(f"{value}\n")
                proc.stdin.flush()
                expr_sent = True

    # Drain any remaining output.
    rest = proc.stdout.read()
    if rest:
        output_parts.append(rest)

    sys.stdout.write("".join(output_parts))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
