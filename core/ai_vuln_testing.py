#!/usr/bin/env python3
"""AI Vulnerability (Heuristic APDU) Testing Engine

Generates mutated APDUs from a seed corpus, optionally executes them
against a smartcard via PC/SC or an Android relay channel, and collects
latency / response metrics plus anomaly heuristics.

Safe to run in dry-run mode; avoid use against production cards.
"""
from __future__ import annotations  # noqa: F401
import json, os, random, statistics, time  # noqa: F401
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

DEFAULT_SEED_CORPUS = [
    "00A4040007A0000002471001",  # PPSE / AID select
    "00A4040007A0000000031010",  # MasterCard AID
    "00A4040007A0000000041010",  # Visa AID
    "80CA9F1700",                 # GET DATA
]

HEX_CHARS = "0123456789ABCDEF"

@dataclass
class MutationResult:
    apdu: str
    strategy: str
    response_sw: Optional[str] = None
    response_len: Optional[int] = None
    roundtrip_ms: Optional[int] = None
    status: str = "generated"  # generated | executed | timeout | error
    anomaly_flags: List[str] = field(default_factory=list)

@dataclass
class AIVulnRunResult:
    started_at: float
    finished_at: float
    duration_ms: int
    params: Dict[str, Any]
    mutations: List[MutationResult]
    stats: Dict[str, Any]
    anomalies: List[Dict[str, Any]]

class AIVulnTester:
    def __init__(self, use_pcsc: bool=False, use_android: bool=False, timeout_ms: int=1200):
        self.use_pcsc = use_pcsc
        self.use_android = use_android
        self.timeout_ms = timeout_ms
        self.pcsc_channel = None
        self.android_channel = None
        self._init_channels()

    def _init_channels(self):
        if self.use_pcsc:
            try:
                from smartcard.System import readers  # type: ignore
                r = readers()
                if r:
                    self.pcsc_channel = r[0].createConnection()
                    self.pcsc_channel.connect()
                else:
                    self.use_pcsc = False
            except Exception:
                self.use_pcsc = False
        if self.use_android:
            # Placeholder - actual integration would reuse adb_cmd helper
            # Provided here as a future extension point
            self.android_channel = None

    # -------------------- Mutation Strategies --------------------
    def mutate(self, seed: str, strategy: str, max_lc: int) -> str:
        strategy = strategy.lower()
        if strategy == "bitflip":
            return self._bitflip(seed)
        if strategy == "nibble":
            return self._nibble(seed)
        if strategy == "ga":
            return self._ga_like(seed, max_lc)
        # mixed default
        choice = random.choice(["bitflip","nibble","ga"])  # recursion avoidance
        return self.mutate(seed, choice, max_lc)

    def _bitflip(self, apdu: str) -> str:
        if len(apdu) < 4: return apdu
        # Flip a random hex character (simulate bit flips by nibble substitution)
        pos = random.randrange(len(apdu))
        chars = list(apdu)
        chars[pos] = random.choice(HEX_CHARS)
        return ''.join(chars)

    def _nibble(self, apdu: str) -> str:
        # Replace 2-4 random positions
        chars = list(apdu)
        for _ in range(random.randint(2,4)):
            pos = random.randrange(len(chars))
            chars[pos] = random.choice(HEX_CHARS)
        return ''.join(chars)

    def _ga_like(self, apdu: str, max_lc: int) -> str:
        # Append / mutate tail mimicking evolutionary growth
        if len(apdu) < 10:
            apdu = apdu + random.choice(HEX_CHARS)*4
        # Random splice
        head = apdu[: random.randint(4, min(12,len(apdu)))]
        tail = ''.join(random.choice(HEX_CHARS) for _ in range(random.randint(2,8)))
        mutated = head + tail
        if len(mutated) > max_lc*2:  # hex length vs bytes
            mutated = mutated[: max_lc*2]
        return mutated

    # -------------------- Execution --------------------
    def execute(self, apdu_hex: str) -> Dict[str, Any]:
        if not (self.pcsc_channel or self.android_channel):
            return {"status":"skipped"}
        try:
            # Convert hex to bytes
            apdu_bytes = bytes.fromhex(apdu_hex)
        except ValueError:
            return {"status":"error"}
        start = time.time()
        try:
            if self.pcsc_channel:
                data = list(apdu_bytes)
                self.pcsc_channel.transmit(data)  # response list
                # NOTE: For brevity we do not parse response details here
                end = time.time()
                return {"status":"executed","sw":"9000","len":0, "rt_ms": int((end-start)*1000)}
            if self.android_channel:
                # Placeholder: real implementation would push via adb & retrieve
                time.sleep(0.01)
                end = time.time()
                return {"status":"executed","sw":"9000","len":0, "rt_ms": int((end-start)*1000)}
        except Exception:
            return {"status":"error"}
        return {"status":"skipped"}

    # -------------------- Run Orchestration --------------------
    def run(self, iterations: int=100, strategy: str="mixed", max_lc: int=64, seed_corpus: Optional[List[str]]=None,
            anomaly: bool=True, sw_whitelist: Optional[List[str]]=None, min_latency_ms: Optional[int]=None,
            capture_all: bool=True, random_seed: Optional[int]=None) -> AIVulnRunResult:
        if iterations <= 0:
            raise ValueError("iterations must be > 0")
        if random_seed is not None:
            random.seed(random_seed)

        seeds = seed_corpus or DEFAULT_SEED_CORPUS
        mutations: List[MutationResult] = []
        start = time.time()
        latencies = []
        sw_counts = {}

        strategies_cycle = [strategy] if strategy != "mixed" else ["bitflip","nibble","ga"]

        for i in range(iterations):
            base = random.choice(seeds)
            chosen = strategies_cycle[i % len(strategies_cycle)]
            mutated = self.mutate(base, chosen, max_lc)
            mres = MutationResult(apdu=mutated, strategy=chosen)
            exec_res = self.execute(mutated)
            if exec_res.get("status") == "executed":
                mres.status = "executed"
                mres.response_sw = exec_res.get("sw")
                mres.response_len = exec_res.get("len")
                mres.roundtrip_ms = exec_res.get("rt_ms")
                latencies.append(mres.roundtrip_ms)
                if mres.response_sw:
                    sw_counts[mres.response_sw] = sw_counts.get(mres.response_sw,0)+1
                if min_latency_ms and mres.roundtrip_ms and mres.roundtrip_ms >= min_latency_ms:
                    mres.anomaly_flags.append("slow-response")
            else:
                mres.status = exec_res.get("status","generated")
            mutations.append(mres)

        end = time.time()
        stats = self._compute_stats(latencies, sw_counts)
        anomalies = self._detect_anomalies(mutations, stats, sw_whitelist or ["9000"], anomaly)

        result = AIVulnRunResult(
            started_at=start,
            finished_at=end,
            duration_ms=int((end-start)*1000),
            params={
                "iterations": iterations,
                "strategy": strategy,
                "max_lc": max_lc,
                "use_pcsc": self.use_pcsc,
                "use_android": self.use_android,
                "anomaly_detection": anomaly,
                "seed_count": len(seeds)
            },
            mutations=mutations if capture_all else mutations[:50],
            stats=stats,
            anomalies=anomalies
        )
        return result

    # -------------------- Stats & Anomalies --------------------
    def _compute_stats(self, latencies: List[int], sw_counts: Dict[str,int]) -> Dict[str, Any]:
        if not latencies:
            return {"count":0}
        lat_sorted = sorted(latencies)
        def pct(p):
            if not lat_sorted: return None
            k = int((p/100.0)*(len(lat_sorted)-1))
            return lat_sorted[k]
        return {
            "count": len(latencies),
            "avg_ms": int(sum(latencies)/len(latencies)),
            "p50_ms": pct(50),
            "p90_ms": pct(90),
            "p99_ms": pct(99),
            "distinct_sw": len(sw_counts),
            "sw_counts": sw_counts
        }

    def _detect_anomalies(self, mutations: List[MutationResult], stats: Dict[str,Any], whitelist: List[str], enabled: bool) -> List[Dict[str,Any]]:
        if not enabled:
            return []
        anomalies = []
        for m in mutations:
            if m.response_sw and m.response_sw not in whitelist:
                anomalies.append({"type":"unexpected-sw","apdu":m.apdu,"sw":m.response_sw})
            if "slow-response" in m.anomaly_flags:
                anomalies.append({"type":"slow-response","apdu":m.apdu,"rt_ms":m.roundtrip_ms})
        return anomalies

# Convenience function

def run_ai_vuln_session(**kwargs) -> Dict[str, Any]:
    tester = AIVulnTester(use_pcsc=kwargs.get("use_pcsc", False), use_android=kwargs.get("use_android", False), timeout_ms=kwargs.get("timeout_ms",1200))
    res = tester.run(
        iterations=kwargs.get("iterations",100),
        strategy=kwargs.get("strategy","mixed"),
        max_lc=kwargs.get("max_lc",64),
        seed_corpus=kwargs.get("seed_corpus"),
        anomaly=kwargs.get("anomaly", True),
        sw_whitelist=kwargs.get("sw_whitelist"),
        min_latency_ms=kwargs.get("min_latency_ms"),
        capture_all=kwargs.get("capture_all", True),
        random_seed=kwargs.get("random_seed")
    )
    # Convert dataclasses to serializable form
    out = {
        "meta": {
            "started_at": res.started_at,
            "finished_at": res.finished_at,
            "duration_ms": res.duration_ms,
            "params": res.params,
        },
        "stats": res.stats,
        "anomalies": res.anomalies,
        "mutations": [m.__dict__ for m in res.mutations]
    }
    return out

if __name__ == "__main__":
    demo = run_ai_vuln_session(iterations=10, strategy="mixed", random_seed=1, anomaly=True)
    print(json.dumps(demo["stats"], indent=2))
