"""
engine/loader.py

Turns a path (unpacked directory, .zip, .crx, or .xpi) into an AnalysisContext
that every module operates on. Purely a reader: unzips into a temp directory
and parses text/JSON. Never executes anything from the extension.
"""

from __future__ import annotations
import json
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from .tokenizer import RuleSpec, FileScope, SourceIndex, build_scoped_index
from .logging_config import get_logger

log = get_logger("loader")

JS_LIKE_EXT = {".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx"}
TEXT_EXT = JS_LIKE_EXT | {".html", ".htm", ".css", ".json"}
SKIP_DIRS = {"node_modules", ".git", "__MACOSX"}

# .crx files are a small binary header followed by a standard zip payload.
# We don't need to validate signatures -- just strip the header and unzip.
CRX_MAGIC = b"Cr24"


@dataclass
class SourceFile:
    rel_path: str
    abs_path: Path
    text: str


@dataclass
class AnalysisContext:
    root: Path
    manifest_path: Path
    manifest: dict
    files: list[SourceFile] = field(default_factory=list)
    include_vendor: bool = False
    index: SourceIndex | None = None
    _tmpdir: tempfile.TemporaryDirectory | None = None
    _vendor_paths: set[str] = field(default_factory=set, init=False)

    def __post_init__(self) -> None:
        from .vendor_detect import is_vendor_file
        for f in self.files:
            if is_vendor_file(f.rel_path, f.text):
                self._vendor_paths.add(f.rel_path)

    @property
    def name(self) -> str:
        return self.manifest.get("name", self.root.name)

    @property
    def version(self) -> str:
        return str(self.manifest.get("version", "0.0.0"))

    @property
    def manifest_version(self) -> int | None:
        return self.manifest.get("manifest_version")

    def is_vendor(self, f: SourceFile) -> bool:
        return f.rel_path in self._vendor_paths

    @property
    def vendor_file_paths(self) -> list[str]:
        return sorted(self._vendor_paths)

    def js_files(self) -> list[SourceFile]:
        files = [f for f in self.files if Path(f.rel_path).suffix.lower() in JS_LIKE_EXT]
        if self.include_vendor:
            return files
        return [f for f in files if not self.is_vendor(f)]

    def all_js_files(self) -> list[SourceFile]:
        """Unfiltered -- for modules whose job IS to look at vendor code (e.g. supply-chain fingerprinting)."""
        return [f for f in self.files if Path(f.rel_path).suffix.lower() in JS_LIKE_EXT]

    def html_files(self) -> list[SourceFile]:
        return [f for f in self.files if Path(f.rel_path).suffix.lower() in (".html", ".htm")]

    def find(self, rel_path: str) -> SourceFile | None:
        for f in self.files:
            if f.rel_path == rel_path:
                return f
        return None

    def cleanup(self) -> None:
        if self._tmpdir is not None:
            self._tmpdir.cleanup()


def _strip_crx_header(data: bytes) -> bytes:
    """CRX2/CRX3 -> raw zip bytes."""
    if data[:4] != CRX_MAGIC:
        return data
    version = int.from_bytes(data[4:8], "little")
    if version == 2:
        pubkey_len = int.from_bytes(data[8:12], "little")
        sig_len = int.from_bytes(data[12:16], "little")
        header_len = 16 + pubkey_len + sig_len
    else:  # CRX3
        header_len_field = int.from_bytes(data[8:12], "little")
        header_len = 12 + header_len_field
    return data[header_len:]


def _materialize(target: Path) -> tuple[Path, tempfile.TemporaryDirectory | None]:
    """Return a directory containing the extension source, unzipping if needed."""
    if target.is_dir():
        return target, None

    suffix = target.suffix.lower()
    tmpdir = tempfile.TemporaryDirectory(prefix="godseye-ex-")
    dest = Path(tmpdir.name)

    data = target.read_bytes()
    if suffix == ".crx":
        data = _strip_crx_header(data)
        zip_path = dest / "payload.zip"
        zip_path.write_bytes(data)
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(dest)
        zip_path.unlink()
    elif suffix in (".xpi", ".zip"):
        with zipfile.ZipFile(target) as zf:
            zf.extractall(dest)
    else:
        tmpdir.cleanup()
        raise ValueError(f"Unsupported file type: {target.suffix}. Pass an unpacked directory, .crx, .xpi, or .zip.")

    return dest, tmpdir


def _find_manifest(root: Path) -> Path:
    direct = root / "manifest.json"
    if direct.is_file():
        return direct
    matches = sorted(root.rglob("manifest.json"), key=lambda p: len(p.parts))
    if not matches:
        raise FileNotFoundError(f"No manifest.json found under {root}")
    return matches[0]


def _build_scoped_index_with_shadows(
    scope_files: dict[FileScope, list],
    rule_specs: list[RuleSpec],
    shadow_map: dict[str, str],
) -> SourceIndex:
    """
    Like build_scoped_index but tokenizes shadow (unpacked) text while keeping
    the original SourceFile.text for display/context snippets. This is what
    allows the patterns to match hex-escaped and concatenated strings without
    corrupting the code snippets shown to the user.
    """
    from .tokenizer import FileIndex, MatchSpan, build_file_index as _build_fi

    file_objs: dict[str, object] = {}
    rules_for_file: dict[str, list[RuleSpec]] = {}

    for scope, files in scope_files.items():
        applicable = [r for r in rule_specs if r.scope == scope]
        if not applicable:
            continue
        for f in files:
            file_objs[f.rel_path] = f
            rules_for_file.setdefault(f.rel_path, [])
            rules_for_file[f.rel_path].extend(applicable)

    index = SourceIndex()
    for rel_path, rules in rules_for_file.items():
        original_text = file_objs[rel_path].text
        shadow_text = shadow_map.get(rel_path, original_text)
        try:
            # Build index on shadow (for matching), but store original in FileIndex
            fi = _build_fi(rel_path, shadow_text, rules)
            fi.text = original_text  # restore original for snippet display
        except Exception:
            log.warning("tokenization failed for %s", rel_path, exc_info=True)
            fi = FileIndex(rel_path=rel_path, text=original_text)
        index.files[rel_path] = fi
        for rule_id, spans in fi.spans_by_rule.items():
            index._by_rule.setdefault(rule_id, []).extend(spans)
    return index


def load(target_path: str, include_vendor: bool = False, rule_specs: list[RuleSpec] | None = None) -> AnalysisContext:
    target = Path(target_path).expanduser().resolve()
    if not target.exists():
        raise FileNotFoundError(f"{target} does not exist")

    if target.is_file() and target.name == "manifest.json":
        root = target.parent
        tmpdir = None
    else:
        root, tmpdir = _materialize(target)

    manifest_path = _find_manifest(root)
    manifest_root = manifest_path.parent

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError as e:
        raise ValueError(f"manifest.json is not valid JSON: {e}") from e

    files: list[SourceFile] = []
    for path in sorted(manifest_root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in TEXT_EXT:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            log.debug("could not read %s, skipping", path)
            continue
        files.append(SourceFile(rel_path=str(path.relative_to(manifest_root)), abs_path=path, text=text))

    ctx = AnalysisContext(
        root=manifest_root,
        manifest_path=manifest_path,
        manifest=manifest,
        files=files,
        include_vendor=include_vendor,
        _tmpdir=tmpdir,
    )

    if rule_specs:
        from .string_unpacker import unpack as _unpack
        scope_files = {
            FileScope.JS_NONVENDOR: ctx.js_files(),
            FileScope.JS_ALL: ctx.all_js_files(),
            FileScope.HTML: ctx.html_files(),
        }
        shadow_map: dict[str, str] = {
            f.rel_path: _unpack(f.text) for f in ctx.files
        }
        ctx.index = _build_scoped_index_with_shadows(scope_files, rule_specs, shadow_map)

        # Inject alias spans: scan non-vendor JS for dangerous-function aliases
        from .alias_tracker import build_alias_spans
        for f in ctx.js_files():
            for span in build_alias_spans(f.rel_path, f.text):
                ctx.index._by_rule.setdefault(span.rule_id, []).append(span)
                if f.rel_path in ctx.index.files:
                    ctx.index.files[f.rel_path].spans_by_rule.setdefault(span.rule_id, []).append(span)
    else:
        ctx.index = SourceIndex()

    return ctx
