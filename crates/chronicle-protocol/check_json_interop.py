"""Valid-input byte comparison with an independent ECMAScript oracle.
Requires cargo build --locked -p chronicle-cli, Python 3, and Node.
Node JSON.parse is not a duplicate-key validator.
"""
from pathlib import Path
import json
import random
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
BINARY = ROOT / "target/debug/chronicle-cli"
ORACLE = """
const fs = require('fs');
function encode(v) {
  if (v === null || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(encode).join(',') + ']';
  return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + encode(v[k])).join(',') + '}';
}
process.stdout.write(encode(JSON.parse(fs.readFileSync(process.argv[1], 'utf8'))));
"""
rng = random.Random(8592)
strings = ["", "中文", "😀", "דּ", "é", "e\u0301", "\n\r\t\u000f", "/", "\\", '"', "\u2028"]

def value(depth=0):
    if depth >= 4 or rng.randrange(3) == 0:
        return rng.choice([None, True, False, *strings])
    if rng.randrange(2):
        return [value(depth + 1) for _ in range(rng.randrange(5))]
    return {key: value(depth + 1) for key in rng.sample(strings + ["1", "10", "2"], rng.randrange(5))}

fixtures = [
    {"דּ": None, "😀": None, "€": None, "ö": None, "\u0080": None, "1": None, "\r": None},
    {"s": "\u000f\b\t\n\f\r/\u2028", "nested": {"10": "ten", "2": "two", "1": "one"}},
    *[{"payload": value()} for _ in range(64)],
]
with tempfile.TemporaryDirectory(prefix="chronicle-json-") as temporary:
    path = Path(temporary) / "input.json"
    for index, item in enumerate(fixtures):
        path.write_text(json.dumps(item, ensure_ascii=index % 2 == 0), encoding="utf-8")
        rust = subprocess.run([str(BINARY), "canonicalize", str(path)], capture_output=True, check=True).stdout
        node = subprocess.run(["node", "-e", ORACLE, str(path)], capture_output=True, check=True).stdout
        if rust != node:
            raise SystemExit(f"Canonical byte mismatch at fixture {index}")
    for bad in ['{"a":true,"\\u0061":false}', '{"n":1}', '{"s":"\\ud800"}']:
        path.write_text(bad, encoding="utf-8")
        rejected = subprocess.run([str(BINARY), "canonicalize", str(path)], capture_output=True)
        if rejected.returncode != 2 or rejected.stdout:
            raise SystemExit("Invalid input was not rejected without output")
print(f"INTEROP_OK: {len(fixtures)} seeded valid fixtures match Node byte-for-byte; 3 invalid CLI inputs rejected")
