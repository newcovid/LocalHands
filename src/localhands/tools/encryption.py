"""Detection of DLP-encrypted files.

Why this module exists
----------------------
Some corporate endpoints run a transparent-encryption (DLP) filter driver.  Such
drivers encrypt on write for *protected* applications and decrypt on read only
for those same applications.  This daemon is not one of them, so a file that a
protected application produced comes back to it as ciphertext.

Left undetected this is worse than a plain failure: ``read_file`` falls back to
latin-1 and cheerfully returns several kilobytes of mojibake, and the agent then
reasons — confidently and at full token price — about noise.  Detecting the
condition and saying so converts a silent wrong answer into an actionable one.

Two facts, both measured against a driver of this class, shape the remedy that
gets reported:

* **Copying never decrypts.** ``shutil.copyfile``, ``cmd copy`` and
  ``Copy-Item`` all produce a still-encrypted copy, in ``%TEMP%`` or anywhere
  else.  The ciphertext *is* the file content; location is irrelevant.
* **%TEMP% is excluded from encryption on write.** A protected application doing
  "Save As" into ``%TEMP%`` writes plaintext, because the driver skips that path.

So the only route back to readable bytes is to re-export from the application
that owns the file, targeting the staging directory. That is what the error
payload tells the agent to do.

Detection is by magic bytes rather than entropy: the driver stamps a fixed
4-byte prefix, which is exact, while an entropy heuristic would also flag every
legitimately compressed file.
"""

from __future__ import annotations

import logging
import os
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

# Prefixes observed in the field. Sampling ~400 files under one such driver:
# every .pdf and roughly two thirds of the .jpg / .png / source files produced
# by protected applications begin with one of these; plain-text files written by
# unprotected processes never do. Override through ``encrypted_file_markers``
# for a site running a different product.
DEFAULT_MARKERS: tuple[bytes, ...] = (b"b\x14#e", b"c\x14#e")

# Longest marker we might need to compare against.
_PROBE_BYTES = 16


def parse_markers(raw: list[str] | None) -> tuple[bytes, ...]:
    """Turn hex strings from config into marker bytes.

    Accepts ``"6214 2365"``, ``"62142365"`` or ``"0x62142365"``. Invalid entries
    are dropped with a warning rather than aborting startup — a mistyped marker
    should degrade detection, not prevent the daemon from running.
    """
    if not raw:
        return DEFAULT_MARKERS

    markers: list[bytes] = []
    for entry in raw:
        cleaned = str(entry).replace(" ", "").replace("0x", "").replace("0X", "")
        try:
            markers.append(bytes.fromhex(cleaned))
        except ValueError:
            logger.warning("Ignoring invalid encrypted_file_marker: %r", entry)
    return tuple(markers) if markers else DEFAULT_MARKERS


def head_is_encrypted(head: bytes, markers: tuple[bytes, ...] = DEFAULT_MARKERS) -> bool:
    """Check an already-read prefix, so callers need not re-open the file."""
    return any(head.startswith(m) for m in markers)


def is_encrypted(path: Path, markers: tuple[bytes, ...] = DEFAULT_MARKERS) -> bool:
    """Check whether a file carries a DLP encryption marker.

    Returns False for unreadable files: the caller's own error handling gives a
    better message for those than a speculative encryption claim would.
    """
    try:
        with path.open("rb") as fh:
            return head_is_encrypted(fh.read(_PROBE_BYTES), markers)
    except OSError:
        return False


# Formats produced by the applications a DLP policy typically protects — office
# suites, PDF writers, engineering tools. Source files and configs are written by
# unprotected editors and stay plaintext even on a machine that encrypts heavily,
# so a sample drawn from a code tree finds nothing and concludes, wrongly, that
# the machine is clean.
_LIKELY_PROTECTED = frozenset({
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".wps", ".et",
    ".png", ".jpg", ".jpeg", ".bmp", ".gif", ".tif", ".tiff", ".vsd", ".vsdx",
    ".dwg", ".dxf", ".scl", ".udt", ".awl", ".db", ".zip", ".rar", ".7z",
})

# Bound on directories visited, so a huge tree cannot stall startup.
_MAX_DIRS = 600


def probe_for_encryption(
    roots: list[Path],
    markers: tuple[bytes, ...] = DEFAULT_MARKERS,
    sample_limit: int = 300,
) -> bool:
    """Sample the allowed paths to decide whether a DLP driver is in play.

    Most machines have no transparent encryption at all, and on those the whole
    subject is noise: ``scan_encrypted`` can only ever return zero, and telling
    the agent about ciphertext it will never meet wastes context on every turn.

    Evidence beats configuration. Enumerating filter drivers needs elevation and
    still requires knowing which vendor's product does what, whereas a marker in
    a real file is direct proof.

    Sampling is deliberately biased toward document and image formats and spread
    evenly across the configured roots. Walking in directory order instead would
    exhaust the budget on whichever tree came first, and in a source tree every
    one of those files is plaintext no matter how aggressive the policy is.

    A false negative is harmless: the per-read marker check stays active
    regardless, so a file encrypted later still produces the right error.
    """
    real_roots = [r for r in roots if r.is_dir()]
    if not real_roots:
        return False

    per_root = max(40, sample_limit // len(real_roots))
    checked = 0

    for root in real_roots:
        likely: list[Path] = []
        other: list[Path] = []

        for dirs_seen, (dirpath, dirnames, filenames) in enumerate(os.walk(root), start=1):
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]
            if dirs_seen > _MAX_DIRS or len(likely) >= per_root:
                break
            for filename in filenames:
                target = likely if Path(filename).suffix.lower() in _LIKELY_PROTECTED else other
                if len(target) < per_root:
                    target.append(Path(dirpath) / filename)

        # Likely-protected formats first; fall back to anything else only if the
        # root has too few of them to be conclusive on its own.
        for candidate in (likely + other)[:per_root]:
            try:
                with candidate.open("rb") as fh:
                    head = fh.read(_PROBE_BYTES)
            except OSError:
                continue
            checked += 1
            if head_is_encrypted(head, markers):
                logger.info(
                    "DLP encryption detected after sampling %d file(s): %s",
                    checked, candidate,
                )
                return True

    logger.info("No DLP encryption markers in %d sampled file(s).", checked)
    return False


def staging_dir(configured: str | None = None) -> Path:
    """Return the directory where plaintext exports should be staged.

    Defaults under ``%TEMP%`` because that is the path the encryption driver
    excludes; a protected application saving there produces readable bytes.
    """
    base = Path(configured) if configured else Path(tempfile.gettempdir()) / "localhands_staging"
    base = Path(os.path.expandvars(str(base))).expanduser()
    base.mkdir(parents=True, exist_ok=True)
    return base


def encrypted_error(path: Path, staging: Path) -> dict[str, object]:
    """Build the error payload returned for an encrypted file.

    The remedy is spelled out concretely: the agent cannot fix this by retrying,
    copying, or picking a different tool, and without explicit guidance it will
    burn turns discovering that.
    """
    return {
        "status": "error",
        "error": (
            f"{path.name} is encrypted by a transparent-encryption (DLP) driver. "
            f"This process receives ciphertext, not the real content."
        ),
        "error_type": "FileEncrypted",
        "path": str(path),
        "remedy": (
            f"Copying will NOT decrypt it — the ciphertext is the file's content, "
            f"so the copy is encrypted too, wherever it lands. The only fix is to "
            f"re-export the file from the application that created it (its office "
            f"suite, CAD or engineering tool) with the save target set to {staging}. "
            f"That directory is "
            f"excluded from the encryption driver, so exports written there stay "
            f"readable."
        ),
        "staging_dir": str(staging),
    }
