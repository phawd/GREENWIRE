"""Public EMV contactless kernel registry used by GREENWIRE.

The registry intentionally stores only public mapping and metadata derived from
EMVCo public pages and public Letters of Approval. It does not ship
proprietary kernel code.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Dict, List, Optional


@dataclass(frozen=True)
class KernelProfile:
    kernel_id: int
    book: str
    scheme: str
    display_name: str
    rid_prefixes: tuple[str, ...]
    source: str
    notes: str = ""

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


KERNEL_PROFILES: Dict[int, KernelProfile] = {
    2: KernelProfile(2, "Book C-2", "mastercard", "Mastercard PayPass / Kernel 2", ("A000000004",), "EMVCo LoA TCP_LOA_MATS_00043"),
    3: KernelProfile(3, "Book C-3", "visa", "Visa qVSDC / Kernel 3", ("A000000003",), "EMVCo LoA TCP_LOA_MATS_00043"),
    4: KernelProfile(4, "Book C-4", "amex", "American Express Expresspay / Kernel 4", ("A000000025",), "EMVCo LoA TCP_LOA_MATS_00043"),
    5: KernelProfile(5, "Book C-5", "jcb", "JCB J/Speedy / Kernel 5", ("A000000065",), "EMVCo LoA TCP_LOA_MATS_00043"),
    6: KernelProfile(6, "Book C-6", "discover", "Discover D-PAS / Kernel 6", ("A000000152", "A000000324"), "EMVCo LoA TCP_LOA_MATS_00043"),
    7: KernelProfile(7, "Book C-7", "unionpay", "UnionPay qPBOC / Kernel 7", ("A000000333",), "EMVCo LoA TCP_LOA_MATS_00043"),
    8: KernelProfile(
        8,
        "Book C-8",
        "emvco",
        "EMVCo Shared Contactless Kernel / Kernel 8",
        (),
        "EMVCo public contactless kernel materials",
        "Public EMVCo kernel intended to reduce the number of scheme-specific kernels terminals maintain.",
    ),
}

SCHEME_TO_KERNEL_ID = {
    "mastercard": 2,
    "visa": 3,
    "amex": 4,
    "american_express": 4,
    "jcb": 5,
    "discover": 6,
    "unionpay": 7,
    "cup": 7,
    "emvco": 8,
    "generic": 8,
}


def list_kernel_profiles() -> List[Dict[str, object]]:
    return [KERNEL_PROFILES[k].to_dict() for k in sorted(KERNEL_PROFILES)]


def get_kernel_profile(kernel_id: int) -> Optional[KernelProfile]:
    return KERNEL_PROFILES.get(kernel_id)


def infer_kernel_from_scheme(scheme: str | None) -> KernelProfile:
    key = (scheme or "generic").strip().lower()
    return KERNEL_PROFILES[SCHEME_TO_KERNEL_ID.get(key, 8)]


def infer_kernel_from_aid(aid: str | None) -> KernelProfile:
    if not aid:
        return KERNEL_PROFILES[8]
    normalized = aid.replace(" ", "").upper()
    for profile in KERNEL_PROFILES.values():
        if any(normalized.startswith(rid) for rid in profile.rid_prefixes):
            return profile
    return KERNEL_PROFILES[8]


def build_kernel_seed_corpus(kernel_id: int | None = None) -> List[str]:
    profile = KERNEL_PROFILES.get(kernel_id or 8, KERNEL_PROFILES[8])
    seeds = {
        2: ["00A4040007A0000000041010", "80A80000028300", "80AE400000"],
        3: ["00A4040007A0000000031010", "80A80000028300", "80AE800000"],
        4: ["00A4040006A00000002501", "80A80000028300", "80AE800000"],
        5: ["00A4040007A0000000651010", "80A80000028300", "80AE400000"],
        6: ["00A4040007A0000003241010", "80A80000028300", "80AE400000"],
        7: ["00A4040008A000000333010101", "80A80000028300", "80AE400000"],
        8: ["00A404000E325041592E5359532E4444463031", "80A80000028300", "80CA9F1700"],
    }[profile.kernel_id]
    return seeds + ["00B2010C00", "00B2020C00"]


__all__ = [
    "KernelProfile",
    "KERNEL_PROFILES",
    "build_kernel_seed_corpus",
    "get_kernel_profile",
    "infer_kernel_from_aid",
    "infer_kernel_from_scheme",
    "list_kernel_profiles",
]
