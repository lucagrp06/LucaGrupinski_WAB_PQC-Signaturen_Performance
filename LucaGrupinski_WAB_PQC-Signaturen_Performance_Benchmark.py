"""
WAB-Benchmark: RSA-3072, ECDSA-P256 und ML-DSA-65 im Vergleich
================================================================

Misst für alle drei Verfahren
  - die Laufzeit von Schlüsselerzeugung, Signaturerzeugung und Verifikation,
  - den zusätzlichen Spitzen-Arbeitsspeicher je Operation,
  - die Grössen von Schlüsseln und Signaturen.

Alle Verfahren laufen über dieselbe Bibliothek (cryptography, OpenSSL-Backend).

Installation und Start unter Windows (PowerShell oder Eingabeaufforderung):

    py -3.13 -m venv wab-venv
    .\\wab-venv\\Scripts\\python.exe -m pip install cryptography==50.0.1 psutil==7.2.2
    .\\wab-venv\\Scripts\\python.exe wab_benchmark.py

Vor dem Start alle anderen Programme schliessen. Die Ergebnisse landen in
einem neuen Ordner results_<Datum>_<Uhrzeit> neben diesem Skript.

Optionen (Standardwerte entsprechen Kapitel 3 der WAB):
    --runs 1000        gemessene Wiederholungen je Operation
    --warmup 100       verworfene Aufwärmdurchläufe je Operation
    --mem-procs 30     frische Prozesse je Speichermessung
    --mem-ops 10       Operationen je Speicher-Prozess
    --core 2           logischer Prozessorkern, auf den der Test festgelegt wird
    --msg-size 1024    Nachrichtengrösse in Byte
"""

import argparse
import csv
import datetime as dt
import gc
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import psutil
import cryptography
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, mldsa, padding, rsa

ALGORITHMS = ("RSA-3072", "ECDSA-P256", "ML-DSA-65")
OPERATIONS = ("keygen", "sign", "verify")
IS_WINDOWS = sys.platform.startswith("win")

RSA_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH)
ECDSA_SHA256 = ec.ECDSA(hashes.SHA256())
DER = serialization.Encoding.DER
SPKI = serialization.PublicFormat.SubjectPublicKeyInfo
PKCS8 = serialization.PrivateFormat.PKCS8
NO_ENC = serialization.NoEncryption()


# --------------------------------------------------------------------------
# Kryptographische Operationen
# --------------------------------------------------------------------------

def keygen(alg):
    if alg == "RSA-3072":
        return rsa.generate_private_key(public_exponent=65537, key_size=3072)
    if alg == "ECDSA-P256":
        return ec.generate_private_key(ec.SECP256R1())
    if alg == "ML-DSA-65":
        return mldsa.MLDSA65PrivateKey.generate()
    raise ValueError(alg)


def sign(alg, private_key, message):
    if alg == "RSA-3072":
        return private_key.sign(message, RSA_PSS, hashes.SHA256())
    if alg == "ECDSA-P256":
        return private_key.sign(message, ECDSA_SHA256)
    return private_key.sign(message)


def verify(alg, public_key, signature, message):
    """Wirft InvalidSignature, falls die Signatur ungültig ist."""
    if alg == "RSA-3072":
        public_key.verify(signature, message, RSA_PSS, hashes.SHA256())
    elif alg == "ECDSA-P256":
        public_key.verify(signature, message, ECDSA_SHA256)
    else:
        public_key.verify(signature, message)


def load_private(alg, data):
    if alg == "ML-DSA-65":
        return mldsa.MLDSA65PrivateKey.from_seed_bytes(data)
    return serialization.load_der_private_key(data, password=None)


def load_public(alg, data):
    if alg == "ML-DSA-65":
        return mldsa.MLDSA65PublicKey.from_public_bytes(data)
    return serialization.load_der_public_key(data)


def dump_private(alg, private_key):
    if alg == "ML-DSA-65":
        return private_key.private_bytes_raw()
    return private_key.private_bytes(DER, PKCS8, NO_ENC)


def dump_public(alg, public_key):
    if alg == "ML-DSA-65":
        return public_key.public_bytes_raw()
    return public_key.public_bytes(DER, SPKI)


# --------------------------------------------------------------------------
# Prozess-Einstellungen und Speichermessung
# --------------------------------------------------------------------------

def setup_process(core):
    """Legt den Prozess auf einen logischen Kern fest und erhöht die Priorität."""
    proc = psutil.Process()
    used_core = None
    try:
        allowed = proc.cpu_affinity()
        used_core = core if core in allowed else allowed[0]
        proc.cpu_affinity([used_core])
    except (AttributeError, psutil.Error, OSError):
        pass
    priority = "normal"
    if IS_WINDOWS:
        try:
            proc.nice(psutil.HIGH_PRIORITY_CLASS)
            priority = "HIGH_PRIORITY_CLASS"
        except (psutil.Error, OSError):
            pass
    return used_core, priority


# Minimaler Messprozess: wird mit "python -c" gestartet, damit das Kompilieren
# dieses Skripts die Speicherspitze nicht verfälscht.
WORKER_CODE = r"""
import gc, json, sys
import psutil
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, mldsa, padding, rsa
alg, op, data_dir, ops, core = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5])
proc = psutil.Process()
try:
    allowed = proc.cpu_affinity()
    proc.cpu_affinity([core if core in allowed else allowed[0]])
except Exception:
    pass
if sys.platform.startswith("win"):
    try:
        proc.nice(psutil.HIGH_PRIORITY_CLASS)
    except Exception:
        pass
def peak():
    # Windows: Peak Working Set; Linux: VmHWM (Spitzen-RSS dieses Prozesses)
    if sys.platform.startswith("win"):
        return proc.memory_info().peak_wset
    if sys.platform.startswith("linux"):
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("VmHWM:"):
                    return int(line.split()[1]) * 1024
    import resource
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH)
def read(name):
    with open(data_dir + "/" + name, "rb") as f:
        return f.read()
gc.collect()
base_imports = peak()
msg = read("message.bin")
if op == "sign":
    raw = read(alg + ".priv")
    key = mldsa.MLDSA65PrivateKey.from_seed_bytes(raw) if alg == "ML-DSA-65" else serialization.load_der_private_key(raw, None)
elif op == "verify":
    raw = read(alg + ".pub")
    key = mldsa.MLDSA65PublicKey.from_public_bytes(raw) if alg == "ML-DSA-65" else serialization.load_der_public_key(raw)
    sig = read(alg + ".sig")
gc.collect()
base_inputs = peak()
for _ in range(ops):
    if op == "keygen":
        if alg == "RSA-3072":
            rsa.generate_private_key(public_exponent=65537, key_size=3072)
        elif alg == "ECDSA-P256":
            ec.generate_private_key(ec.SECP256R1())
        else:
            mldsa.MLDSA65PrivateKey.generate()
    elif op == "sign":
        if alg == "RSA-3072":
            key.sign(msg, PSS, hashes.SHA256())
        elif alg == "ECDSA-P256":
            key.sign(msg, ec.ECDSA(hashes.SHA256()))
        else:
            key.sign(msg)
    else:
        if alg == "RSA-3072":
            key.verify(sig, msg, PSS, hashes.SHA256())
        elif alg == "ECDSA-P256":
            key.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
        else:
            key.verify(sig, msg)
print(json.dumps({"baseline_imports": base_imports, "baseline_inputs": base_inputs, "peak": peak()}))
"""


# --------------------------------------------------------------------------
# Laufzeitmessung
# --------------------------------------------------------------------------

def time_operations(alg, runs, warmup, msg_size, timing_rows, size_rows):
    perf = time.perf_counter_ns
    results = {}

    # Schlüsselerzeugung
    for _ in range(warmup):
        keygen(alg)
    times = []
    gc.disable()
    for _ in range(runs):
        t0 = perf()
        keygen(alg)
        times.append(perf() - t0)
    gc.enable()
    results["keygen"] = times

    # Signaturerzeugung (je Durchlauf eine neue zufällige Nachricht)
    private_key = keygen(alg)
    public_key = private_key.public_key()
    warm_msgs = [os.urandom(msg_size) for _ in range(warmup)]
    msgs = [os.urandom(msg_size) for _ in range(runs)]
    for m in warm_msgs:
        sign(alg, private_key, m)
    signatures = []
    times = []
    gc.disable()
    for m in msgs:
        t0 = perf()
        s = sign(alg, private_key, m)
        times.append(perf() - t0)
        signatures.append(s)
    gc.enable()
    results["sign"] = times

    # Verifikation: jede erzeugte Signatur wird geprüft
    for m in warm_msgs:
        verify(alg, public_key, sign(alg, private_key, m), m)
    times = []
    invalid = 0
    gc.disable()
    for m, s in zip(msgs, signatures):
        t0 = perf()
        try:
            verify(alg, public_key, s, m)
        except InvalidSignature:
            invalid += 1
        times.append(perf() - t0)
    gc.enable()
    results["verify"] = times

    for op in OPERATIONS:
        for i, t in enumerate(results[op], start=1):
            timing_rows.append([alg, op, i, t])

    # Grössen
    sig_lengths = [len(s) for s in signatures]
    size_rows.extend(collect_sizes(alg, private_key, sig_lengths))

    return private_key, public_key, msgs[0], signatures[0], invalid


def collect_sizes(alg, private_key, sig_lengths):
    pub = private_key.public_key()
    rows = []
    if alg == "RSA-3072":
        modulus = pub.public_numbers().n
        rows.append([alg, "public key", "raw (modulus n)", (modulus.bit_length() + 7) // 8])
        rows.append([alg, "public key", "DER SubjectPublicKeyInfo", len(pub.public_bytes(DER, SPKI))])
        rows.append([alg, "private key", "DER PKCS#8", len(private_key.private_bytes(DER, PKCS8, NO_ENC))])
        rows.append([alg, "signature", "raw (RSA-PSS)", min(sig_lengths), max(sig_lengths), statistics.mean(sig_lengths)])
    elif alg == "ECDSA-P256":
        rows.append([alg, "public key", "raw X9.62 uncompressed point", len(pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))])
        rows.append([alg, "public key", "DER SubjectPublicKeyInfo", len(pub.public_bytes(DER, SPKI))])
        rows.append([alg, "private key", "raw scalar", 32])
        rows.append([alg, "private key", "DER PKCS#8", len(private_key.private_bytes(DER, PKCS8, NO_ENC))])
        rows.append([alg, "signature", "raw (r und s)", 64])
        rows.append([alg, "signature", "DER", min(sig_lengths), max(sig_lengths), statistics.mean(sig_lengths)])
    else:
        rows.append([alg, "public key", "raw (FIPS 204)", len(pub.public_bytes_raw())])
        rows.append([alg, "public key", "DER SubjectPublicKeyInfo", len(pub.public_bytes(DER, SPKI))])
        rows.append([alg, "private key", "raw seed (FIPS 204)", len(private_key.private_bytes_raw())])
        rows.append([alg, "private key", "DER PKCS#8 (seed)", len(private_key.private_bytes(DER, PKCS8, NO_ENC))])
        rows.append([alg, "signature", "raw (FIPS 204)", min(sig_lengths), max(sig_lengths), statistics.mean(sig_lengths)])
    for r in rows:
        if len(r) == 4:
            r.extend([r[3], r[3]])
    return rows


# --------------------------------------------------------------------------
# Umgebung, Auswertung, Hauptprogramm
# --------------------------------------------------------------------------

def openssl_version():
    try:
        from cryptography.hazmat.bindings._rust import openssl as rust_openssl
        return rust_openssl.openssl_version_text()
    except Exception:
        try:
            from cryptography.hazmat.backends.openssl import backend
            return backend.openssl_version_text()
        except Exception:
            return "unknown"


def environment_info(args, used_core, priority):
    clock = time.get_clock_info("perf_counter")
    freq = psutil.cpu_freq()
    k = mldsa.MLDSA65PrivateKey.generate()
    randomized = k.sign(b"test") != k.sign(b"test")
    return {
        "timestamp": dt.datetime.now().isoformat(timespec="seconds"),
        "os": platform.platform(),
        "os_version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "cpu_logical": psutil.cpu_count(logical=True),
        "cpu_physical": psutil.cpu_count(logical=False),
        "cpu_freq_mhz": {"current": freq.current, "max": freq.max} if freq else None,
        "ram_total_gb": round(psutil.virtual_memory().total / 1024**3, 2),
        "python": platform.python_version(),
        "cryptography": cryptography.__version__,
        "openssl": openssl_version(),
        "psutil": psutil.__version__,
        "timer": {"function": "time.perf_counter_ns", "implementation": clock.implementation,
                  "resolution_s": clock.resolution},
        "pinned_logical_core": used_core,
        "priority": priority,
        "runs": args.runs,
        "warmup": args.warmup,
        "message_size_bytes": args.msg_size,
        "mem_processes": args.mem_procs,
        "mem_ops_per_process": args.mem_ops,
        "rsa": "3072 bit, e = 65537, RSA-PSS with SHA-256, MGF1-SHA-256, salt = 32 bytes",
        "ecdsa": "NIST P-256 (secp256r1) with SHA-256",
        "mldsa": "ML-DSA-65 (FIPS 204), empty context string",
        "mldsa_signing_randomized": randomized,
    }


def summarize_times(timing_rows):
    rows = []
    for alg in ALGORITHMS:
        for op in OPERATIONS:
            us = [r[3] / 1000 for r in timing_rows if r[0] == alg and r[1] == op]
            rows.append([alg, op, len(us), statistics.mean(us), statistics.median(us),
                         statistics.stdev(us) if len(us) > 1 else 0.0, min(us), max(us)])
    return rows


def summarize_memory(mem_rows):
    rows = []
    for alg in ALGORITHMS:
        for op in OPERATIONS:
            tot = [r[5] / 1024 for r in mem_rows if r[0] == alg and r[1] == op]
            opn = [r[6] / 1024 for r in mem_rows if r[0] == alg and r[1] == op]
            rows.append([alg, op, len(tot), statistics.median(tot), max(tot), statistics.median(opn), max(opn)])
    return rows


def write_csv(path, header, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(header)
        w.writerows(rows)


def write_markdown(path, env, time_summary, mem_summary, size_rows, invalid):
    lines = ["# Benchmark-Ergebnisse", "",
             f"- System: {env['os']}, {env['processor']}, {env['ram_total_gb']} GB RAM",
             f"- Python {env['python']}, cryptography {env['cryptography']}, {env['openssl']}",
             f"- Timer: {env['timer']['function']} ({env['timer']['implementation']}, "
             f"Auflösung {env['timer']['resolution_s']} s)",
             f"- Kern: {env['pinned_logical_core']}, Priorität: {env['priority']}",
             f"- {env['warmup']} Aufwärmdurchläufe, {env['runs']} Messungen je Operation, "
             f"Nachricht {env['message_size_bytes']} Byte",
             f"- ML-DSA-65 randomisiertes Signieren: {env['mldsa_signing_randomized']}",
             f"- Ungültige Signaturen: {invalid}", "",
             "## Laufzeit (Mikrosekunden)", "",
             "| Verfahren | Operation | n | Mittelwert | Median | Std.-Abw. | Min | Max |",
             "|---|---|---|---|---|---|---|---|"]
    for r in time_summary:
        lines.append(f"| {r[0]} | {r[1]} | {r[2]} | " + " | ".join(f"{v:,.1f}" for v in r[3:]) + " |")
    lines += ["", "## Zusätzlicher Spitzen-Arbeitsspeicher (KiB)", "",
              "Operation = Zuwachs durch die Operation selbst (nach Laden von Bibliothek und Schlüsseln). "
              "Gesamt = zusätzlich inkl. Laden der Schlüssel. Bei ML-DSA-65 berechnet das Laden des "
              "privaten Schlüssels aus dem 32-Byte-Seed den expandierten Schlüssel neu; dieser Aufwand "
              "steckt nur in 'Gesamt'.", "",
              "| Verfahren | Operation | Prozesse | Gesamt Median | Gesamt Max | Operation Median | Operation Max |",
              "|---|---|---|---|---|---|---|"]
    for r in mem_summary:
        lines.append(f"| {r[0]} | {r[1]} | {r[2]} | " + " | ".join(f"{v:,.1f}" for v in r[3:]) + " |")
    lines += ["", "## Grössen (Byte)", "",
              "| Verfahren | Element | Format | Min | Max | Mittel |", "|---|---|---|---|---|---|"]
    for r in size_rows:
        lines.append(f"| {r[0]} | {r[1]} | {r[2]} | {r[3]} | {r[4]} | {r[5]:.1f} |")
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description="WAB-Benchmark RSA-3072 / ECDSA-P256 / ML-DSA-65")
    parser.add_argument("--runs", type=int, default=1000)
    parser.add_argument("--warmup", type=int, default=100)
    parser.add_argument("--mem-procs", type=int, default=30)
    parser.add_argument("--mem-ops", type=int, default=10)
    parser.add_argument("--core", type=int, default=2)
    parser.add_argument("--msg-size", type=int, default=1024)
    args = parser.parse_args()

    used_core, priority = setup_process(args.core)
    out = Path(__file__).resolve().parent / f"results_{dt.datetime.now():%Y%m%d_%H%M%S}"
    out.mkdir()
    env = environment_info(args, used_core, priority)
    print(f"System: {env['os']} | {env['processor']} | Python {env['python']} | "
          f"cryptography {env['cryptography']} | {env['openssl']}")
    print(f"Kern {used_core}, Priorität {priority}, {args.warmup} Aufwärmläufe, {args.runs} Messungen\n")

    timing_rows, size_rows, mem_rows = [], [], []
    invalid_total = 0
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        message = os.urandom(args.msg_size)
        (tmp / "message.bin").write_bytes(message)

        # 1) Laufzeiten und Grössen
        for alg in ALGORITHMS:
            print(f"[Laufzeit] {alg} ...", flush=True)
            priv, pub, _, _, invalid = time_operations(alg, args.runs, args.warmup, args.msg_size,
                                                       timing_rows, size_rows)
            invalid_total += invalid
            (tmp / f"{alg}.priv").write_bytes(dump_private(alg, priv))
            (tmp / f"{alg}.pub").write_bytes(dump_public(alg, pub))
            (tmp / f"{alg}.sig").write_bytes(sign(alg, priv, message))

        # 2) Speicher: jede Messung in einem frischen Prozess
        for alg in ALGORITHMS:
            for op in OPERATIONS:
                print(f"[Speicher] {alg} {op} ...", flush=True)
                for p in range(1, args.mem_procs + 1):
                    res = subprocess.run(
                        [sys.executable, "-c", WORKER_CODE, alg, op, str(tmp),
                         str(args.mem_ops), str(args.core)],
                        capture_output=True, text=True, check=True)
                    d = json.loads(res.stdout.strip().splitlines()[-1])
                    mem_rows.append([alg, op, p, d["baseline_imports"], d["peak"],
                                     d["peak"] - d["baseline_imports"], d["peak"] - d["baseline_inputs"]])

    time_summary = summarize_times(timing_rows)
    mem_summary = summarize_memory(mem_rows)

    (out / "environment.json").write_text(json.dumps(env, indent=2), encoding="utf-8")
    write_csv(out / "timings_raw.csv", ["algorithm", "operation", "run", "time_ns"], timing_rows)
    write_csv(out / "memory_raw.csv", ["algorithm", "operation", "process", "baseline_bytes", "peak_bytes",
                                       "delta_total_bytes", "delta_operation_bytes"], mem_rows)
    write_csv(out / "sizes.csv", ["algorithm", "item", "format", "min_bytes", "max_bytes", "mean_bytes"], size_rows)
    write_csv(out / "summary_times.csv", ["algorithm", "operation", "n", "mean_us", "median_us", "stdev_us",
                                          "min_us", "max_us"], time_summary)
    write_csv(out / "summary_memory.csv", ["algorithm", "operation", "processes", "total_median_kib",
                                           "total_max_kib", "operation_median_kib", "operation_max_kib"], mem_summary)
    write_markdown(out / "summary.md", env, time_summary, mem_summary, size_rows, invalid_total)

    print(f"\nFertig. Ungültige Signaturen: {invalid_total}")
    print(f"Ergebnisse: {out}")
    print((out / "summary.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
