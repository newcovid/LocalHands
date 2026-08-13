"""Image tools: hand local images and screen captures over as one-time URLs.

Nothing here ever returns pixels inside a tool result.  The client spools tool
results to a JSON file and reads them back as text, so a base64 payload is
billed at the full text-token price — a 500 KB image is roughly 680,000
characters.  Every tool that produces an image therefore writes it to a staging
file and returns a one-time download URL, exactly as ``xfer.prepare_download``
does; those bytes travel over plain HTTP and cost nothing.

Resolution is the other half of the cost story.  Once the agent does view the
fetched file, vision tokens scale with pixel count, so images are fitted to a
longest edge of 1568 px before they are staged.
"""

from __future__ import annotations

import io
import logging
import mimetypes
import secrets
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from mcp.types import Tool
from PIL import Image, ImageGrab, ImageOps, UnidentifiedImageError

from ..security import PathGuardError
from .base import LocalProvider, err, ok

logger = logging.getLogger(__name__)

# Default longest edge. 1568 px is the point above which mainstream vision
# models downscale anyway, so larger transfers buy nothing but bytes.
DEFAULT_MAX_EDGE = 1568

# Fallback when the config predates ``max_image_bytes``.
DEFAULT_MAX_IMAGE_BYTES = 1_572_864  # 1.5 MB

# Shrink ladder used when a first encode overshoots the byte cap: quality is
# spent first because it degrades the image far less than pixels do.
QUALITY_STEPS = (70, 55, 40)
EDGE_FACTORS = (1.0, 0.75, 0.5, 0.35)
MIN_EDGE = 160

# Staged files are derived artifacts; anything this old is from a transfer that
# already happened or was abandoned.
STAGING_MAX_AGE_SECONDS = 3600
STAGING_DIR_NAME = "localhands_media"

# Where a transparent-encryption (DLP) driver is active, it hands ciphertext to
# any process that is not the protected application that wrote the file.
# Ciphertext starts with one of these markers, which is the only way to tell it
# apart from a genuinely corrupt image.
ENCRYPTED_MARKERS = (b"b\x14#e", b"c\x14#e")

# Modes JPEG/PNG/WebP cannot all store. Normalising once at load keeps every
# save path below from having to special-case them.
EXOTIC_MODES = frozenset({"CMYK", "YCbCr", "I", "F", "I;16", "I;16B", "I;16L"})

FORMAT_ALIASES = {
    "jpeg": "JPEG",
    "jpg": "JPEG",
    "png": "PNG",
    "webp": "WEBP",
}
FORMAT_EXTENSIONS = {"JPEG": "jpg", "PNG": "png", "WEBP": "webp"}


class MediaProvider(LocalProvider):
    """Image inspection, screen capture, and editing tools."""

    # ngrok's free tier serves an HTML interstitial (ERR_NGROK_6024) to requests
    # that look like a browser, which a client would silently save as if it were
    # the image. This header opts out; other tunnel providers ignore it.
    _TUNNEL_HEADER = 'ngrok-skip-browser-warning: true'

    name = "media"

    tools: list[Tool] = [
    Tool(
        name="read_image",
        description=(
            "Make a LOCAL image viewable. Returns a temporary URL, never pixels.\n"
            "\n"
            "Call this, then run the exact command in the 'curl' field inside "
            "your own environment and open the file it writes with your normal "
            "image-viewing path. Use the command verbatim — it carries a header "
            "needed to bypass the tunnel's browser check.\n"
            "\n"
            "The image is re-encoded before transfer: EXIF rotation is applied, "
            "the longest edge is capped at max_edge, and the result is JPEG "
            "unless the image really uses transparency. Leave max_edge at 1568 "
            "for normal reading and lower it (e.g. 800) for a quick glance — "
            "vision tokens scale with resolution, so this is the main cost "
            "control.\n"
            "\n"
            "NEVER ask for image bytes as base64: billed as text, a 500 KB image "
            "becomes ~680,000 characters. This URL costs nothing.\n"
            "\n"
            "The URL works exactly ONCE and expires within minutes."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path of the local image file."},
                "max_edge": {
                    "type": "integer",
                    "description": "Cap on the longest edge in pixels. Default 1568.",
                    "default": DEFAULT_MAX_EDGE,
                },
                "quality": {
                    "type": "integer",
                    "description": "JPEG quality, 1-95. Default 85.",
                    "default": 85,
                },
            },
            "required": ["path"],
        },
    ),
    Tool(
        name="screenshot",
        description=(
            "Capture the local screen and return a temporary URL for it.\n"
            "\n"
            "PRIVACY: this sends the contents of the user's screen — every "
            "visible window, not just the one of interest — to a cloud service "
            "over the tunnel. Only call it when the user has asked to be shown "
            "something on their screen, and prefer a region over the whole "
            "desktop when you know where to look.\n"
            "\n"
            "All monitors are captured as one image. Optional region is "
            "[x, y, width, height] in pixels relative to the top-left of that "
            "combined capture. Fetch the result with the returned 'curl' "
            "command, verbatim, then view the downloaded file.\n"
            "\n"
            "The URL works exactly ONCE and expires within minutes."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "region": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "minItems": 4,
                    "maxItems": 4,
                    "description": "Optional [x, y, width, height] crop of the full capture.",
                },
                "max_edge": {
                    "type": "integer",
                    "description": "Cap on the longest edge in pixels. Default 1568.",
                    "default": DEFAULT_MAX_EDGE,
                },
                "save_to": {
                    "type": "string",
                    "description": "Optional local path to also keep the capture at full resolution.",
                },
            },
            "required": [],
        },
    ),
    Tool(
        name="process_image",
        description=(
            "Crop, resize, or convert a local image and save the result to "
            "dest_path. Nothing is transferred — call read_image on dest_path "
            "afterwards if you need to see it.\n"
            "\n"
            "Crop values are pixels trimmed off each edge, applied before any "
            "resize; a crop that would leave nothing is rejected. Use this to "
            "cut a chart out of a screenshot, or to shrink a huge photo before "
            "handing it to another tool."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path of the source image."},
                "dest_path": {"type": "string", "description": "Where to write the processed image."},
                "crop_bottom": {"type": "integer", "description": "Pixels to trim off the bottom. Default 0.", "default": 0},
                "crop_top": {"type": "integer", "description": "Pixels to trim off the top. Default 0.", "default": 0},
                "crop_left": {"type": "integer", "description": "Pixels to trim off the left. Default 0.", "default": 0},
                "crop_right": {"type": "integer", "description": "Pixels to trim off the right. Default 0.", "default": 0},
                "max_edge": {
                    "type": "integer",
                    "description": "Cap the longest edge at this many pixels. Default: no resize.",
                },
                "format": {
                    "type": "string",
                    "enum": ["jpeg", "png", "webp"],
                    "description": "Output format. Default: inferred from dest_path's extension.",
                },
                "quality": {
                    "type": "integer",
                    "description": "JPEG/WebP quality, 1-95. Default 85.",
                    "default": 85,
                },
            },
            "required": ["path", "dest_path"],
        },
    ),
    Tool(
        name="image_info",
        description=(
            "Read an image's format, mode, dimensions, byte size, alpha "
            "channel, and EXIF orientation without producing any copy or "
            "transfer. Cheap — use it to choose max_edge or crop values before "
            "calling read_image or process_image."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path of the local image file."},
            },
            "required": ["path"],
        },
    ),
    ]

    def list_tools(self) -> list[Tool]:
        """Withhold ``screenshot`` when the operator has switched it off.

        Screen capture is the one tool here that can send content the task never
        named — whatever happens to be on the user's monitors. An operator who
        sets ``screenshot_enabled: false`` means it should not be reachable, so
        it is dropped from the advertised list rather than left to fail on call.
        """
        tools = super().list_tools()
        if getattr(self.config, "screenshot_enabled", True):
            return tools
        return [t for t in tools if t.name != "screenshot"]

    # ------------------------------------------------------------------ #
    #  Tool: read_image
    # ------------------------------------------------------------------ #

    def _read_image(
        self,
        path: str,
        max_edge: int = DEFAULT_MAX_EDGE,
        quality: int = 85,
    ) -> dict[str, Any]:
        """Stage a downscaled copy of a local image and mint a URL for it."""
        if self.tickets is None:
            return err("Transfer channel is not available on this server.", "TransferUnavailable")

        try:
            resolved = self.guard.check(path)
        except PathGuardError as e:
            return err(str(e), "PathGuardError")

        if not resolved.exists():
            return err(f"File not found: {resolved}", "FileNotFound")
        if not resolved.is_file():
            return err(f"Not a regular file: {resolved}", "NotAFile")

        image, failure = self._load(resolved)
        if image is None:
            return failure or err(f"Cannot open image: {resolved}", "ImageOpenError")

        source_format = image.format or "unknown"
        original_size = image.size

        try:
            staged, meta = self._stage(image, max_edge=max_edge, quality=quality, prefix="read")
        except OSError as e:
            return err(f"Failed to write the processed image: {e}", "WriteError")

        return ok(
            path=str(resolved),
            **self._download_payload(staged),
            original={
                "width": original_size[0],
                "height": original_size[1],
                "format": source_format,
                "size_bytes": resolved.stat().st_size,
            },
            processed=meta,
        )

    # ------------------------------------------------------------------ #
    #  Tool: screenshot
    # ------------------------------------------------------------------ #

    def _screenshot(
        self,
        region: list[int] | None = None,
        max_edge: int = DEFAULT_MAX_EDGE,
        save_to: str | None = None,
    ) -> dict[str, Any]:
        """Capture every monitor, optionally crop, and mint a URL for the result."""
        # Checked here as well as in list_tools: a client holding a cached tool
        # list must not be able to reach the screen after the operator opted out.
        if not getattr(self.config, "screenshot_enabled", True):
            return err(
                "Screen capture is disabled on this server (screenshot_enabled: false).",
                "ToolDisabled",
            )
        if self.tickets is None:
            return err("Transfer channel is not available on this server.", "TransferUnavailable")

        keep_at: Path | None = None
        if save_to is not None:
            try:
                keep_at = self.guard.check(save_to)
            except PathGuardError as e:
                return err(str(e), "PathGuardError")

        try:
            capture = ImageGrab.grab(all_screens=True)
        except (OSError, RuntimeError) as e:
            return err(f"Screen capture failed: {e}", "CaptureError")

        screen_size = capture.size
        if region is not None:
            cropped, failure = _crop_region(capture, region)
            if cropped is None:
                return failure or err("Invalid region.", "InvalidRegion")
            capture = cropped

        # The capture leaves the machine, so it belongs in the audit trail even
        # when the transfer itself later fails.
        logger.info("Screen captured: %dx%d from a %dx%d desktop",
                    capture.width, capture.height, screen_size[0], screen_size[1])

        saved: str | None = None
        if keep_at is not None:
            fmt = _format_for(None, keep_at, "PNG")
            try:
                _encode(capture, fmt, 92, keep_at, create_parents=True)
            except (OSError, ValueError) as e:
                return err(f"Failed to save the capture to {keep_at}: {e}", "WriteError")
            saved = str(keep_at)

        try:
            staged, meta = self._stage(capture, max_edge=max_edge, quality=85, prefix="shot")
        except OSError as e:
            return err(f"Failed to write the processed capture: {e}", "WriteError")

        result = ok(
            **self._download_payload(staged),
            screen={"width": screen_size[0], "height": screen_size[1]},
            captured={"width": capture.width, "height": capture.height},
            region=list(region) if region is not None else None,
            processed=meta,
        )
        if saved:
            result["saved_to"] = saved
        return result

    # ------------------------------------------------------------------ #
    #  Tool: process_image
    # ------------------------------------------------------------------ #

    def _process_image(
        self,
        path: str,
        dest_path: str,
        crop_bottom: int = 0,
        crop_top: int = 0,
        crop_left: int = 0,
        crop_right: int = 0,
        max_edge: int | None = None,
        format: str | None = None,  # noqa: A002 — the argument name is part of the tool schema
        quality: int = 85,
    ) -> dict[str, Any]:
        """Crop, resize, and re-encode an image into ``dest_path``."""
        try:
            resolved = self.guard.check(path)
            destination = self.guard.check(dest_path)
        except PathGuardError as e:
            return err(str(e), "PathGuardError")

        if not resolved.exists():
            return err(f"File not found: {resolved}", "FileNotFound")
        if not resolved.is_file():
            return err(f"Not a regular file: {resolved}", "NotAFile")
        if destination.exists() and destination.is_dir():
            return err(f"Destination is a directory: {destination}", "NotAFile")

        crops = {
            "crop_top": crop_top,
            "crop_bottom": crop_bottom,
            "crop_left": crop_left,
            "crop_right": crop_right,
        }
        negative = [name for name, value in crops.items() if int(value) < 0]
        if negative:
            return err(f"Crop values must be >= 0: {', '.join(negative)}", "InvalidCrop")

        out_format = _format_for(format, destination, None)
        if out_format is None:
            return err(
                f"Unsupported output format {format!r}. Use 'jpeg', 'png', or 'webp', "
                "or give dest_path one of those extensions.",
                "UnsupportedFormat",
            )

        image, failure = self._load(resolved)
        if image is None:
            return failure or err(f"Cannot open image: {resolved}", "ImageOpenError")

        original_size = image.size
        left, top = int(crop_left), int(crop_top)
        right = image.width - int(crop_right)
        bottom = image.height - int(crop_bottom)
        if right <= left or bottom <= top:
            return err(
                f"Crop leaves nothing of a {image.width}x{image.height} image "
                f"(remaining box would be {right - left}x{bottom - top}).",
                "InvalidCrop",
            )
        if (left, top, right, bottom) != (0, 0, image.width, image.height):
            image = image.crop((left, top, right, bottom))

        image = _fit_within(image, max_edge)

        try:
            _encode(image, out_format, _clamp_quality(quality), destination, create_parents=True)
        except (OSError, ValueError) as e:
            return err(f"Failed to write {destination}: {e}", "WriteError")

        return ok(
            source_path=str(resolved),
            dest_path=str(destination),
            format=out_format,
            width=image.width,
            height=image.height,
            size_bytes=destination.stat().st_size,
            original={"width": original_size[0], "height": original_size[1]},
            cropped=any(int(v) > 0 for v in crops.values()),
            resized=(image.size != (right - left, bottom - top)),
        )

    # ------------------------------------------------------------------ #
    #  Tool: image_info
    # ------------------------------------------------------------------ #

    def _image_info(self, path: str) -> dict[str, Any]:
        """Report an image's header metadata without decoding or copying it."""
        try:
            resolved = self.guard.check(path)
        except PathGuardError as e:
            return err(str(e), "PathGuardError")

        if not resolved.exists():
            return err(f"File not found: {resolved}", "FileNotFound")
        if not resolved.is_file():
            return err(f"Not a regular file: {resolved}", "NotAFile")

        try:
            # Deliberately no .load(): Image.open reads only the header, which is
            # the whole point of this tool being cheap.
            with Image.open(resolved) as image:
                orientation = image.getexif().get(274)
                return ok(
                    path=str(resolved),
                    format=image.format or "unknown",
                    mode=image.mode,
                    width=image.width,
                    height=image.height,
                    size_bytes=resolved.stat().st_size,
                    # Presence of an alpha channel, not proof any pixel uses it —
                    # answering that would require decoding the whole image.
                    has_alpha=image.mode in ("RGBA", "LA", "PA") or "transparency" in image.info,
                    exif_orientation=int(orientation) if orientation else None,
                    animated=getattr(image, "n_frames", 1) > 1,
                )
        except (UnidentifiedImageError, OSError, ValueError) as e:
            return self._open_failure(resolved, e)

    # ------------------------------------------------------------------ #
    #  Helpers
    # ------------------------------------------------------------------ #

    def _load(self, path: Path) -> tuple[Image.Image | None, dict[str, Any] | None]:
        """Decode an image and apply its EXIF rotation.

        Returns ``(image, None)`` or ``(None, error_dict)`` — a caller forwards
        the error straight back as its tool result.
        """
        try:
            with Image.open(path) as handle:
                handle.load()
                source_format = handle.format
                image = ImageOps.exif_transpose(handle) or handle.copy()
        except (UnidentifiedImageError, OSError, ValueError) as e:
            return None, self._open_failure(path, e)

        if image.mode in EXOTIC_MODES:
            image = image.convert("RGB")
        # exif_transpose drops .format; downstream reporting still wants it.
        image.format = source_format
        return image, None

    def _open_failure(self, path: Path, exc: Exception) -> dict[str, Any]:
        """Turn a Pillow open failure into the most specific error available."""
        if _is_encrypted(path):
            return err(
                f"{path} is encrypted by this machine's DLP driver, not a readable image. "
                "The driver hands ciphertext to any process other than the protected "
                "application that wrote the file. Re-export or 'save as' a copy from the "
                "source application into %TEMP%, then point this tool at that copy.",
                "FileEncrypted",
            )
        return err(f"Cannot open image {path}: {exc}", "ImageOpenError")

    def _stage(
        self,
        image: Image.Image,
        *,
        max_edge: int | None,
        quality: int,
        prefix: str,
    ) -> tuple[Path, dict[str, Any]]:
        """Encode ``image`` into the staging dir, shrinking until it fits the cap.

        Candidates are rendered in memory: an encode that turns out too large
        would otherwise have to be cleaned off disk on every retry.
        """
        limit = getattr(self.config, "max_image_bytes", DEFAULT_MAX_IMAGE_BYTES)
        quality = _clamp_quality(quality)
        base_edge = max_edge if max_edge and max_edge > 0 else max(image.size)
        keeps_alpha = _uses_transparency(image)
        notes: list[str] = []

        fmt = "PNG" if keeps_alpha else "JPEG"
        payload, size, used_edge, used_quality, attempts = _search(image, fmt, base_edge, quality, limit)

        if len(payload) > limit and fmt == "PNG":
            # PNG is lossless, so the edge ladder is the only lever it has; when
            # that is exhausted, transferable beats faithful.
            fmt = "JPEG"
            notes.append("Transparency was flattened onto white — PNG could not be brought under the size limit.")
            payload, size, used_edge, used_quality, more = _search(image, fmt, base_edge, quality, limit)
            attempts += more

        if len(payload) > limit:
            notes.append(
                f"Still {len(payload)} bytes after {attempts} attempts, above the "
                f"{limit}-byte target; transferred anyway."
            )

        directory = self._staging_dir()
        staged = directory / f"{prefix}_{secrets.token_hex(8)}.{FORMAT_EXTENSIONS[fmt]}"
        staged.write_bytes(payload)

        meta: dict[str, Any] = {
            "width": size[0],
            "height": size[1],
            "format": fmt,
            "size_bytes": len(payload),
            "quality": used_quality if fmt != "PNG" else None,
            "max_edge_applied": used_edge,
            "size_limit_bytes": limit,
            "within_size_limit": len(payload) <= limit,
        }
        if notes:
            meta["notes"] = notes
        return staged, meta

    def _staging_dir(self) -> Path:
        """Return the scratch directory for derived images, swept of stale files.

        %TEMP% is expected to be one of the daemon's allowed paths, so a staged
        file is reachable by the transfer endpoint without widening the
        whitelist. These are derived artifacts, never the user's own files, so
        nothing here is worth keeping past the ticket that referenced it.
        """
        directory = Path(tempfile.gettempdir()) / STAGING_DIR_NAME
        directory.mkdir(parents=True, exist_ok=True)
        _sweep(directory)
        return directory

    def _transfer_url(self, kind: str, ticket_id: str) -> str:
        """Build the URL the remote agent should curl.

        Falls back to a relative path when ``public_base_url`` is unset — the
        daemon sits behind a tunnel and cannot learn its own public origin.
        """
        relative = f"/{kind}/{ticket_id}"
        base = self.config.public_base_url
        return f"{base}{relative}" if base else relative

    def _download_payload(self, staged: Path) -> dict[str, Any]:
        """Mint a one-time download ticket for a staged file and describe it."""
        ttl = max(1, min(int(self.config.transfer_ticket_ttl), 3600))
        ticket_id, ticket = self.tickets.mint("download", staged, ttl=ttl)
        url = self._transfer_url("download", ticket_id)

        payload: dict[str, Any] = {
            "url": url,
            "filename": staged.name,
            "mime_type": mimetypes.guess_type(staged.name)[0] or "application/octet-stream",
            "expires_in_seconds": ttl,
            "single_use": True,
            "curl": f'curl -sSL -H "{self._TUNNEL_HEADER}" -o "{staged.name}" "{url}"',
        }
        if not self.config.public_base_url:
            payload["warning"] = (
                "public_base_url is not configured, so 'url' is only a path. "
                "Prefix it with the daemon's public origin."
            )
        return payload


# ====================================================================== #
#  Module-level image helpers
# ====================================================================== #

def _clamp_quality(quality: int) -> int:
    """Keep quality inside the range where JPEG/WebP encoders behave."""
    try:
        return max(1, min(int(quality), 95))
    except (TypeError, ValueError):
        return 85


def _fit_within(image: Image.Image, max_edge: int | None) -> Image.Image:
    """Scale ``image`` down so its longest edge is at most ``max_edge``."""
    if not max_edge or max_edge <= 0:
        return image
    longest = max(image.size)
    if longest <= max_edge:
        return image
    scale = max_edge / longest
    target = (max(1, round(image.width * scale)), max(1, round(image.height * scale)))
    return image.resize(target, Image.Resampling.LANCZOS)


def _flatten(image: Image.Image) -> Image.Image:
    """Composite onto white, since JPEG has no alpha and drops it to black."""
    if image.mode == "P" or "transparency" in image.info:
        image = image.convert("RGBA")
    if image.mode in ("RGBA", "LA"):
        canvas = Image.new("RGB", image.size, (255, 255, 255))
        canvas.paste(image, mask=image.getchannel("A"))
        return canvas
    return image if image.mode == "RGB" else image.convert("RGB")


def _encode(
    image: Image.Image,
    fmt: str,
    quality: int,
    sink: Path | io.BytesIO,
    create_parents: bool = False,
) -> None:
    """Write ``image`` to a path or buffer in ``fmt``."""
    if create_parents and isinstance(sink, Path):
        sink.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "JPEG":
        _flatten(image).save(sink, "JPEG", quality=quality, optimize=True, progressive=True)
    elif fmt == "WEBP":
        image.save(sink, "WEBP", quality=quality, method=4)
    else:
        image.save(sink, "PNG", optimize=True)


def _uses_transparency(image: Image.Image) -> bool:
    """True only when pixels are actually see-through.

    Screen captures and many PNGs carry a fully opaque alpha band; keeping PNG
    for those costs several times the bytes of an equivalent JPEG.
    """
    probe = image
    if probe.mode == "P" or "transparency" in probe.info:
        probe = probe.convert("RGBA")
    if probe.mode not in ("RGBA", "LA", "PA"):
        return False
    return probe.getchannel("A").getextrema()[0] < 255


def _trials(fmt: str, base_edge: int, quality: int) -> Iterator[tuple[int, int]]:
    """Yield ``(edge, quality)`` candidates from best to smallest."""
    qualities = [quality] + [q for q in QUALITY_STEPS if q < quality]
    for factor in EDGE_FACTORS:
        edge = max(MIN_EDGE, int(base_edge * factor))
        if fmt == "PNG":
            yield edge, quality
        else:
            for step in qualities:
                yield edge, step


def _search(
    image: Image.Image,
    fmt: str,
    base_edge: int,
    quality: int,
    limit: int,
) -> tuple[bytes, tuple[int, int], int, int, int]:
    """Render candidates until one fits ``limit``; return the last one tried."""
    payload = b""
    size = image.size
    used_edge, used_quality, attempts = base_edge, quality, 0

    for edge, step in _trials(fmt, base_edge, quality):
        scaled = _fit_within(image, edge)
        buffer = io.BytesIO()
        _encode(scaled, fmt, step, buffer)
        payload, size = buffer.getvalue(), scaled.size
        used_edge, used_quality = edge, step
        attempts += 1
        if len(payload) <= limit:
            break

    return payload, size, used_edge, used_quality, attempts


def _crop_region(
    image: Image.Image,
    region: Any,
) -> tuple[Image.Image | None, dict[str, Any] | None]:
    """Apply a ``[x, y, width, height]`` crop, clamped to the image bounds."""
    if not isinstance(region, (list, tuple)) or len(region) != 4:
        return None, err("region must be [x, y, width, height].", "InvalidRegion")
    try:
        x, y, width, height = (int(value) for value in region)
    except (TypeError, ValueError):
        return None, err(f"region values must be integers, got {region!r}.", "InvalidRegion")
    if width <= 0 or height <= 0:
        return None, err(f"region width and height must be > 0, got {width}x{height}.", "InvalidRegion")

    box = (max(0, x), max(0, y), min(image.width, x + width), min(image.height, y + height))
    if box[2] <= box[0] or box[3] <= box[1]:
        return None, err(
            f"region {list(region)} lies outside the {image.width}x{image.height} capture.",
            "InvalidRegion",
        )
    return image.crop(box), None


def _format_for(requested: str | None, destination: Path, fallback: str | None) -> str | None:
    """Resolve the output format from the argument, then the extension."""
    if requested:
        return FORMAT_ALIASES.get(str(requested).strip().lower())
    return FORMAT_ALIASES.get(destination.suffix.lstrip(".").lower(), fallback)


def _is_encrypted(path: Path) -> bool:
    """True when the file starts with the DLP driver's ciphertext marker."""
    try:
        with path.open("rb") as handle:
            return handle.read(4) in ENCRYPTED_MARKERS
    except OSError:
        return False


def _sweep(directory: Path) -> None:
    """Delete staged files older than an hour so the directory stays bounded."""
    cutoff = time.time() - STAGING_MAX_AGE_SECONDS
    try:
        entries = list(directory.iterdir())
    except OSError:
        return
    for entry in entries:
        try:
            if entry.is_file() and entry.stat().st_mtime < cutoff:
                entry.unlink()
        except OSError:
            continue  # Locked by an in-flight transfer; the next sweep gets it.
