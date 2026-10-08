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


# Header CLI checks are separate from the valid-input Node encoding oracle.
import copy

header_fixture = {
    "schema": "ec.statement-header.v0.1",
    "project": "p1",
    "position": {"source": "ci1", "epoch": "e1", "sequence": "9007199254740993"},
    "kind": "test.failed",
    "subject": "sha256:" + "a" * 64,
}
with tempfile.TemporaryDirectory() as header_dir:
    header_path = Path(header_dir) / "header.json"
    header_path.write_text(json.dumps(header_fixture), encoding="utf-8")
    header_result = subprocess.run(
        [str(ROOT / "target/debug/chronicle-cli"), "validate-header", str(header_path)],
        capture_output=True, check=False,
    )
    assert header_result.returncode == 0, header_result.stderr
    canonical_result = subprocess.run(
        [str(ROOT / "target/debug/chronicle-cli"), "canonicalize", str(header_path)],
        capture_output=True, check=True,
    )
    assert header_result.stdout == canonical_result.stdout
    header_bad = []
    for field in ["schema", "project", "position", "kind", "subject"]:
        value = copy.deepcopy(header_fixture)
        del value[field]
        header_bad.append(json.dumps(value))
    value = copy.deepcopy(header_fixture)
    value["authorized"] = True
    header_bad.append(json.dumps(value))
    value = copy.deepcopy(header_fixture)
    value["position"]["sequence"] = 1
    header_bad.append(json.dumps(value))
    header_bad.append(json.dumps(header_fixture).replace(
        "{", '{"project":"attacker",', 1
    ))
    for invalid in header_bad:
        header_path.write_text(invalid, encoding="utf-8")
        result = subprocess.run(
            [str(ROOT / "target/debug/chronicle-cli"), "validate-header", str(header_path)],
            capture_output=True, check=False,
        )
        assert result.returncode == 2 and result.stdout == b"", result
print("HEADER_CLI_OK: valid header matches canonicalize; 8 invalid headers rejected with empty stdout")


# Independent Python PAE oracle: source bytes are retained, never reserialized.
import base64

header_canonical = json.dumps(
    header_fixture, ensure_ascii=False, sort_keys=True, separators=(",", ":")
).encode("utf-8")
envelope_type = "application/vnd.engineering-chronicle.statement-header.v0.1+json"
expected_pae = (
    b"DSSEv1 " + str(len(envelope_type.encode())).encode() + b" "
    + envelope_type.encode() + b" " + str(len(header_canonical)).encode() + b" "
    + header_canonical
)
envelope_fixture = {
    "payloadType": envelope_type,
    "payload": base64.b64encode(header_canonical).decode(),
    "signatures": [{"keyid": "ci-key", "sig": base64.b64encode(bytes([255]) * 64).decode()}],
}
with tempfile.TemporaryDirectory() as envelope_dir:
    envelope_path = Path(envelope_dir) / "envelope.json"

    def run_envelope(value):
        envelope_path.write_text(json.dumps(value), encoding="utf-8")
        return subprocess.run(
            [str(ROOT / "target/debug/chronicle-cli"), "envelope-pae", str(envelope_path)],
            capture_output=True, check=False,
        )

    for encode in [base64.b64encode, base64.urlsafe_b64encode]:
        for padded in [True, False]:
            value = copy.deepcopy(envelope_fixture)
            for field, raw in [("payload", header_canonical), ("sig", bytes([255]) * 64)]:
                encoded = encode(raw).decode()
                if not padded:
                    encoded = encoded.rstrip("=")
                if field == "payload":
                    value[field] = encoded
                else:
                    value["signatures"][0][field] = encoded
            result = run_envelope(value)
            assert result.returncode == 0 and result.stdout == expected_pae, result
    bad_envelopes = []
    for field, bad in [
        ("payloadType", "application/json"),
        ("payload", "!"),
        ("payload", base64.b64encode(b" " + header_canonical).decode()),
        ("signatures", []),
        ("trusted", True),
    ]:
        value = copy.deepcopy(envelope_fixture)
        value[field] = bad
        bad_envelopes.append(value)
    value = copy.deepcopy(envelope_fixture)
    value["signatures"][0]["sig"] = base64.b64encode(bytes(63)).decode()
    bad_envelopes.append(value)
    for value in bad_envelopes:
        result = run_envelope(value)
        assert result.returncode == 2 and result.stdout == b"", result
print("ENVELOPE_CLI_OK: 4 encodings match independent Python PAE; 6 invalid envelopes rejected")
