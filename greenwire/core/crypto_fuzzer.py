#!/usr/bin/env python3
"""Deterministic cryptographic hash fuzzing utilities."""
from __future__ import annotations

import logging
import hmac
import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger("greenwire.core.crypto_fuzzer")

__all__ = ["HashFuzzer", "HashFuzzResult", "HMACFuzzResult", "CryptoFuzzOrchestrator"]


@dataclass
class HashFuzzResult:
    algorithm: str
    rounds: int
    collision_count: int
    unique_hashes: int
    average_time_ms: float
    min_time_ms: float
    max_time_ms: float
    hash_rate_hps: float
    total_input_bytes: int
    known_collision_detected: bool
    samples: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "rounds": self.rounds,
            "collision_count": self.collision_count,
            "unique_hashes": self.unique_hashes,
            "average_time_ms": round(self.average_time_ms, 6),
            "min_time_ms": round(self.min_time_ms, 6),
            "max_time_ms": round(self.max_time_ms, 6),
            "hash_rate_hps": round(self.hash_rate_hps, 3),
            "total_input_bytes": self.total_input_bytes,
            "known_collision_detected": self.known_collision_detected,
            "samples": self.samples,
        }


@dataclass
class HMACFuzzResult:
    algorithm: str
    rounds: int
    average_time_ms: float
    min_time_ms: float
    max_time_ms: float
    hash_rate_hps: float
    key_preview: str
    samples: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "rounds": self.rounds,
            "average_time_ms": round(self.average_time_ms, 6),
            "min_time_ms": round(self.min_time_ms, 6),
            "max_time_ms": round(self.max_time_ms, 6),
            "hash_rate_hps": round(self.hash_rate_hps, 3),
            "key_preview": self.key_preview,
            "samples": self.samples,
        }


class HashFuzzer:
    """Perform hash algorithm stress tests with deterministic echo mutations."""

    DEFAULT_ALGORITHMS = (
        "md5",
        "sha1",
        "sha224",
        "sha256",
        "sha384",
        "sha512",
        "sha3_256",
        "sha3_512",
        "blake2s",
        "blake2b",
        "shake_128",
        "shake_256",
    )

    DEFAULT_DIGEST_LENGTHS: Dict[str, int] = {
        "shake_128": 32,
        "shake_256": 64,
    }

    KNOWN_COLLISIONS: Dict[str, List[bytes]] = {
        "md5": [
            bytes.fromhex(
                "d131dd02c5e6eec4693d9a0698aff95c"  # first block (prefix) truncated representation
                "2fcab58712467eab4004583eb8fb7f89"
                "55ad340609f4b30283e488832571415a"
                "085125e8f7cdc99fd91dbdf280373c5b"
            ),
            bytes.fromhex(
                "d131dd02c5e6eec4693d9a0698aff95c"
                "2fcab50712467eab4004583eb8fb7f89"
                "55ad340609f4b30283e488832571415a"
                "085125e8f7cdc99fd91dbd7280373c5b"
            ),
        ]
    }

    def __init__(
        self,
        algorithms: Optional[Iterable[str]] = None,
        rounds: int = 256,
        max_samples: int = 5,
        digest_lengths: Optional[Dict[str, int]] = None,
    ) -> None:
        self.algorithms = tuple(algorithms) if algorithms else self.DEFAULT_ALGORITHMS
        self.rounds = rounds
        self.max_samples = max_samples
        self.digest_lengths = {**self.DEFAULT_DIGEST_LENGTHS, **(digest_lengths or {})}

    # ------------------------------------------------------------------
    def run_suite(
        self,
        seed_material: Optional[Iterable[bytes]] = None,
        echo_payload: Optional[bytes] = None,
    ) -> List[Dict[str, Any]]:
        start_time = time.perf_counter()
        seeds = self._prepare_seed_pool(seed_material, echo_payload)
        results: List[Dict[str, Any]] = []
        for algorithm in self.algorithms:
            result = self._fuzz_algorithm(algorithm, seeds)
            logger.info(
                "Hash fuzz complete | algorithm=%s rounds=%d avg_ms=%.3f min_ms=%.3f max_ms=%.3f collisions=%d known_collision=%s",
                result.algorithm,
                result.rounds,
                result.average_time_ms,
                result.min_time_ms,
                result.max_time_ms,
                result.collision_count,
                result.known_collision_detected,
            )
            results.append(result.to_dict())
        total_duration_ms = (time.perf_counter() - start_time) * 1000.0
        logger.info(
            "Hash fuzz suite completed in %.3f ms across %d algorithms",
            total_duration_ms,
            len(self.algorithms),
        )
        return results

    # ------------------------------------------------------------------
    def _prepare_seed_pool(
        self,
        seed_material: Optional[Iterable[bytes]],
        echo_payload: Optional[bytes],
    ) -> List[bytes]:
        seeds: List[bytes] = []
        if seed_material:
            for item in seed_material:
                if item is None:
                    continue
                if isinstance(item, bytes):
                    seeds.append(item)
                elif isinstance(item, bytearray):
                    seeds.append(bytes(item))
                else:
                    seeds.append(str(item).encode("utf-8"))
        if echo_payload:
            seeds.append(bytes(echo_payload))
        if not seeds:
            seeds.append(os.urandom(32))
        if len(seeds) == 1:
            # ensure at least two seeds for mutation variance
            seeds.append(os.urandom(len(seeds[0])))
        return seeds

    # ------------------------------------------------------------------
    def _inject_collision_corpus(self, algorithm: str, seeds: List[bytes]) -> None:
        corpus = self.KNOWN_COLLISIONS.get(algorithm)
        if not corpus:
            return
        for payload in corpus:
            if payload not in seeds:
                seeds.append(payload)

    # ------------------------------------------------------------------
    def _hash_bytes(self, algorithm: str, payload: bytes) -> bytes:
        if algorithm.startswith("shake"):
            digest_len = self.digest_lengths.get(algorithm, 32)
            hasher = getattr(hashlib, algorithm)
            return hasher(payload).digest(digest_len)
        return hashlib.new(algorithm, payload).digest()

    # ------------------------------------------------------------------
    def _fuzz_algorithm(self, algorithm: str, seeds: List[bytes]) -> HashFuzzResult:
        try:
            hashlib.new(algorithm)
        except ValueError:
            raise ValueError(f"Hash algorithm '{algorithm}' is not supported on this platform")

        prepared_seeds = list(seeds)
        self._inject_collision_corpus(algorithm, prepared_seeds)

        observed: Dict[str, bytes] = {}
        timings: List[float] = []
        samples: List[Dict[str, Any]] = []
        collisions = 0
        total_input_bytes = 0
        known_collision_detected = False

        for idx in range(self.rounds):
            seed = prepared_seeds[idx % len(prepared_seeds)]
            mutated = self._mutate(seed, idx)
            start = time.perf_counter()
            digest = self._hash_bytes(algorithm, mutated)
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            timings.append(elapsed_ms)
            total_input_bytes += len(mutated)

            digest_hex = digest.hex()
            if digest_hex in observed:
                collisions += 1
                if seed in self.KNOWN_COLLISIONS.get(algorithm, []):
                    known_collision_detected = True
            else:
                observed[digest_hex] = mutated

            if len(samples) < self.max_samples:
                samples.append(
                    {
                        "round": idx,
                        "input_prefix": mutated[:32].hex(),
                        "digest": digest_hex,
                        "elapsed_ms": round(elapsed_ms, 6),
                    }
                )

        avg_time = sum(timings) / len(timings) if timings else 0.0
        hash_rate_hps = (1000.0 / avg_time) if avg_time else 0.0

        result = HashFuzzResult(
            algorithm=algorithm,
            rounds=self.rounds,
            collision_count=collisions,
            unique_hashes=len(observed),
            average_time_ms=avg_time,
            min_time_ms=min(timings) if timings else 0.0,
            max_time_ms=max(timings) if timings else 0.0,
            hash_rate_hps=hash_rate_hps,
            total_input_bytes=total_input_bytes,
            known_collision_detected=known_collision_detected,
            samples=samples,
        )
        logger.debug(
            "Hash algorithm stats | algorithm=%s rounds=%d unique=%d avg_ms=%.3f",
            result.algorithm,
            result.rounds,
            result.unique_hashes,
            result.average_time_ms,
        )
        return result

    # ------------------------------------------------------------------
    @staticmethod
    def _mutate(seed: bytes, iteration: int) -> bytes:
        payload = bytearray(seed or b"\x00")
        salt = iteration.to_bytes(4, "big")
        for idx, value in enumerate(salt):
            payload[idx % len(payload)] ^= value
        payload.extend(secrets.token_bytes(8))
        payload.extend(hashlib.sha256(seed + iteration.to_bytes(4, "big")).digest()[:8])
        return bytes(payload)

    # ------------------------------------------------------------------
    @staticmethod
    def serialize_results(results: List[Dict[str, Any]]) -> str:
        return json.dumps(results, indent=2)


class CryptoFuzzOrchestrator:
    """Aggregate multiple cryptographic fuzzers into a single suite."""

    HMAC_ALGORITHMS = ("md5", "sha1", "sha256", "sha512")

    def __init__(
        self,
        hash_algorithms: Optional[Iterable[str]] = None,
        hash_rounds: int = 320,
        hmac_rounds: int = 160,
        max_samples: int = 5,
    ) -> None:
        self.hash_fuzzer = HashFuzzer(
            algorithms=hash_algorithms,
            rounds=hash_rounds,
            max_samples=max_samples,
        )
        self.hmac_rounds = hmac_rounds
        self.max_samples = max_samples

    # ------------------------------------------------------------------
    def run_suite(
        self,
        seed_material: Optional[Iterable[bytes]] = None,
        echo_payload: Optional[bytes] = None,
    ) -> Dict[str, Any]:
        suite_start = time.perf_counter()
        seeds = self.hash_fuzzer._prepare_seed_pool(seed_material, echo_payload)
        hash_results = [
            self.hash_fuzzer._fuzz_algorithm(algorithm, seeds).to_dict()
            for algorithm in self.hash_fuzzer.algorithms
        ]
        hmac_results = [result.to_dict() for result in self._run_hmac_suite(seeds)]
        summary = self._summarize(hash_results, hmac_results)
        total_duration_ms = (time.perf_counter() - suite_start) * 1000.0
        logger.info(
            "Crypto fuzz orchestrator complete in %.3f ms | hash_algorithms=%d hmac_algorithms=%d",
            total_duration_ms,
            len(self.hash_fuzzer.algorithms),
            len(self.HMAC_ALGORITHMS),
        )
        return {
            "hash": hash_results,
            "hmac": hmac_results,
            "summary": summary,
        }

    # ------------------------------------------------------------------
    def _run_hmac_suite(self, seeds: List[bytes]) -> List[HMACFuzzResult]:
        results: List[HMACFuzzResult] = []
        for algorithm in self.HMAC_ALGORITHMS:
            key = os.urandom(32)
            timings: List[float] = []
            samples: List[Dict[str, Any]] = []
            for idx in range(self.hmac_rounds):
                payload = self.hash_fuzzer._mutate(seeds[idx % len(seeds)], idx + 17)
                start = time.perf_counter()
                digest = hmac.new(key, payload, algorithm).digest()
                elapsed_ms = (time.perf_counter() - start) * 1000.0
                timings.append(elapsed_ms)
                if len(samples) < self.max_samples:
                    samples.append(
                        {
                            "round": idx,
                            "input_prefix": payload[:32].hex(),
                            "digest": digest.hex(),
                            "elapsed_ms": round(elapsed_ms, 6),
                        }
                    )
            avg = sum(timings) / len(timings) if timings else 0.0
            result = HMACFuzzResult(
                algorithm=algorithm,
                rounds=len(timings),
                average_time_ms=avg,
                min_time_ms=min(timings) if timings else 0.0,
                max_time_ms=max(timings) if timings else 0.0,
                hash_rate_hps=(1000.0 / avg) if avg else 0.0,
                key_preview=key[:8].hex(),
                samples=samples,
            )
            logger.info(
                "HMAC fuzz complete | algorithm=%s rounds=%d avg_ms=%.3f min_ms=%.3f max_ms=%.3f",
                result.algorithm,
                result.rounds,
                result.average_time_ms,
                result.min_time_ms,
                result.max_time_ms,
            )
            results.append(result)
        return results

    # ------------------------------------------------------------------
    @staticmethod
    def _summarize(hash_results: List[Dict[str, Any]], hmac_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        fastest_hash = min(hash_results, key=lambda item: item.get("average_time_ms", float("inf"))) if hash_results else {}
        fastest_hmac = min(hmac_results, key=lambda item: item.get("average_time_ms", float("inf"))) if hmac_results else {}
        combined_hashes = sum(item.get("rounds", 0) for item in hash_results)
        combined_hmac = sum(item.get("rounds", 0) for item in hmac_results)
        collision_algorithms = [item["algorithm"] for item in hash_results if item.get("known_collision_detected")]
        return {
            "total_hash_rounds": combined_hashes,
            "total_hmac_rounds": combined_hmac,
            "fastest_hash_algorithm": fastest_hash.get("algorithm"),
            "fastest_hash_rate_hps": fastest_hash.get("hash_rate_hps"),
            "fastest_hmac_algorithm": fastest_hmac.get("algorithm"),
            "fastest_hmac_rate_hps": fastest_hmac.get("hash_rate_hps"),
            "collision_algorithms": collision_algorithms,
        }
