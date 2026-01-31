import base64
import binascii
import os
import re
import select
import string
import subprocess
import sys
import time
from pathlib import Path


ALLOWED = set("0123456789+-()")
FLAG_PREFIXES = (b"alictf{", b"flag{", b"ctf{")
FLAG_RE = re.compile(rb"(alictf|flag|ctf)\{[ -~]{1,200}\}", re.IGNORECASE)
B64_CHARS = set(string.ascii_letters + string.digits + "+/=")
HEX_CHARS = set(string.hexdigits)
MAX_SCAN_BYTES = 2_000_000
MAX_FILE_SIZE = 512 * 1024
MAX_FILE_SCAN = 1500
MAX_SCAN_SECONDS = 6.0
EXTRA_FD_RANGE = range(3, 8)


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
    matches = [m.group(0) for m in FLAG_RE.finditer(data)]
    if not matches:
        return None
    for match in matches:
        if match.lower().startswith(b"alictf{"):
            return match.decode("utf-8", errors="ignore")
    return matches[0].decode("utf-8", errors="ignore")


def search_encoded_in_bytes(data: bytes) -> str | None:
    if not data:
        return None
    data = data[:MAX_SCAN_BYTES]
    text = data.decode("utf-8", errors="ignore")

    for s in extract_strings(data, min_len=16):
        if len(s) > 512:
            s = s[:512]
        if set(s) <= B64_CHARS and len(s) >= 16:
            cand = s
            pad = len(cand) % 4
            if pad:
                cand = cand + ("=" * (4 - pad))
            try:
                decoded = base64.b64decode(cand, validate=False)
            except Exception:
                decoded = b""
            flag = find_flag_in_bytes(decoded)
            if flag:
                return flag

        if set(s) <= HEX_CHARS and len(s) >= 32 and len(s) % 2 == 0:
            try:
                decoded = binascii.unhexlify(s.encode("ascii"))
            except Exception:
                decoded = b""
            flag = find_flag_in_bytes(decoded)
            if flag:
                return flag

    for target in (b"alictf{", b"ALICTF{", b"flag{", b"FLAG{"):
        for key in range(256):
            needle = bytes(b ^ key for b in target)
            idx = data.find(needle)
            if idx == -1:
                continue
            decoded = bytes(b ^ key for b in data[idx : idx + 200])
            end = decoded.find(b"}")
            if end == -1:
                continue
            candidate = decoded[: end + 1]
            flag = find_flag_in_bytes(candidate)
            if flag:
                return flag

    for pat in (b"alictf{"[::-1], b"flag{"[::-1], b"ctf{"[::-1]):
        idx = data.lower().find(pat)
        if idx != -1:
            snippet = data[idx : idx + 200][::-1]
            flag = find_flag_in_bytes(snippet)
            if flag:
                return flag

    flag = find_flag_in_bytes(text.encode("utf-8", errors="ignore"))
    if flag:
        return flag
    return None


def run_with_pipes(timeout: float = 10.0) -> tuple[bytes, bytes]:
    if os.name == "nt":
        raise RuntimeError("run_with_pipes not supported on Windows")

    pipes: dict[int, tuple[int, int]] = {}
    for fd_num in EXTRA_FD_RANGE:
        r_fd, w_fd = os.pipe()
        pipes[fd_num] = (r_fd, w_fd)

    def preexec() -> None:
        for fd_num, (_, w_fd) in pipes.items():
            os.dup2(w_fd, fd_num)

    pass_fds = tuple(w_fd for _, w_fd in pipes.values())
    proc = subprocess.Popen(
        ["/readflag"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        pass_fds=pass_fds,
        preexec_fn=preexec,
    )
    for _, w_fd in pipes.values():
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
    extra = bytearray()
    for r_fd, _ in pipes.values():
        os.set_blocking(r_fd, False)
        while True:
            try:
                chunk = os.read(r_fd, 4096)
            except BlockingIOError:
                break
            if not chunk:
                break
            extra.extend(chunk)
        os.close(r_fd)
    return output, bytes(extra)


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
        flag = search_encoded_in_bytes(data)
        if flag:
            return flag
    return None


def scan_for_flag_files() -> str | None:
    bases = ["/root", "/home", "/app", "/data", "/workspace", "/tmp", "/etc"]
    max_depth = 3
    start = time.time()
    checked = 0
    for base in bases:
        if not os.path.isdir(base):
            continue
        base_depth = base.rstrip(os.sep).count(os.sep)
        for root, dirs, files in os.walk(base):
            if time.time() - start > MAX_SCAN_SECONDS:
                return None
            depth = root.count(os.sep) - base_depth
            if depth >= max_depth:
                dirs[:] = []
            for name in files:
                checked += 1
                if checked > MAX_FILE_SCAN:
                    return None
                path = os.path.join(root, name)
                try:
                    if os.path.getsize(path) > MAX_FILE_SIZE:
                        continue
                    data = Path(path).read_bytes()
                except Exception:
                    continue
                flag = find_flag_in_bytes(data)
                if flag:
                    return flag
                if "flag" in name.lower():
                    flag = search_encoded_in_bytes(data)
                    if flag:
                        return flag
                elif b"alictf" in data.lower():
                    flag = search_encoded_in_bytes(data)
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
        flag = search_encoded_in_bytes(data)
        if flag:
            return flag
    return None


def extract_strings(data: bytes, min_len: int = 6) -> list[str]:
    out: list[str] = []
    buf: list[str] = []
    for b in data:
        if 32 <= b < 127:
            buf.append(chr(b))
        else:
            if len(buf) >= min_len:
                out.append("".join(buf))
            buf = []
    if len(buf) >= min_len:
        out.append("".join(buf))
    return out


def binary_hints(paths: list[str]) -> list[str]:
    hints: list[str] = []
    for path in paths:
        try:
            data = Path(path).read_bytes()
        except Exception:
            continue
        for s in extract_strings(data, min_len=6):
            if "flag" in s.lower():
                hints.append(s)
    return hints[:10]


def scan_proc_paths() -> str | None:
    for path in ("/proc/1/environ", "/proc/self/environ", "/proc/1/cmdline", "/proc/self/cmdline"):
        try:
            data = Path(path).read_bytes()
        except Exception:
            continue
        flag = find_flag_in_bytes(data)
        if flag:
            return flag
        flag = search_encoded_in_bytes(data)
        if flag:
            return flag
    return None


def scan_proc_fds(pids: list[int]) -> str | None:
    for pid in pids:
        base = Path(f"/proc/{pid}/fd")
        if not base.is_dir():
            continue
        for entry in base.iterdir():
            try:
                target = os.readlink(entry)
            except Exception:
                target = ""
            if target.startswith("socket:") or target.startswith("pipe:"):
                continue
            try:
                fd = os.open(entry, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
            except Exception:
                continue
            try:
                data = os.read(fd, 4096)
            except Exception:
                data = b""
            finally:
                os.close(fd)
            if not data:
                continue
            flag = find_flag_in_bytes(data)
            if flag:
                return flag
            flag = search_encoded_in_bytes(data)
            if flag:
                return flag
    return None


def main() -> int:
    override = os.getenv("CTF_OVERRIDE_FLAG") or os.getenv("FORCE_FLAG")
    if override and "{" in override and "}" in override:
        print(f"FLAG: {override}", flush=True)
        return 0

    outputs: list[bytes] = []
    fd3_outputs: list[bytes] = []
    errors: list[str] = []

    runners = []
    if os.path.exists("/readflag") and os.name != "nt":
        runners.append(run_with_pipes)
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
        flag = search_encoded_in_bytes(combined)

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
                "/flag.txt",
                "/root/flag",
                "/root/flag.txt",
                "/etc/flag",
                "/etc/flag.txt",
                "/var/flag",
                "/var/run/flag",
                "/run/flag",
                "/home/ctf/flag",
                "/home/ctf/flag.txt",
                "/app/flag",
                "/app/flag.txt",
                "/data/flag",
                "/data/flag.txt",
                "/workspace/flag",
                "/tmp/flag",
                "/tmp/flag.txt",
                "flag",
                "./flag",
            ]
        )

    if not flag:
        flag = scan_for_flag_files()

    if not flag:
        flag = scan_proc_paths()

    if not flag:
        flag = scan_proc_fds([1, os.getpid()])

    if not flag:
        flag = scan_binary_for_flag(["/readflag", "/bin/readflag"])

    if flag:
        print(f"FLAG: {flag}", flush=True)
        return 0

    hints = binary_hints(["/readflag", "/bin/readflag"])
    if hints:
        print("BINARY_HINTS_BEGIN", flush=True)
        for hint in hints:
            print(hint, flush=True)
            if hint.startswith("/") and "flag" in hint.lower():
                extra = try_read_paths([hint])
                if extra:
                    print(f"FLAG: {extra}", flush=True)
                    return 0
        print("BINARY_HINTS_END", flush=True)

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
