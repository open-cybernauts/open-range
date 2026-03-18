"""Sync checked-in repo docs into bundled package docs."""

from __future__ import annotations

from pathlib import Path


def _sync_docs(source_dir: Path, bundled_dir: Path) -> None:
    bundled_dir.mkdir(parents=True, exist_ok=True)
    source_docs = {path.name: path for path in source_dir.glob("*.md")}
    bundled_docs = {path.name: path for path in bundled_dir.glob("*.md")}

    for name, source_path in source_docs.items():
        bundled_path = bundled_dir / name
        bundled_path.write_text(
            source_path.read_text(encoding="utf-8"), encoding="utf-8"
        )

    for name, bundled_path in bundled_docs.items():
        if name not in source_docs:
            bundled_path.unlink()


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    _sync_docs(root / "docs", root / "src" / "open_range" / "_resources" / "docs")


if __name__ == "__main__":
    main()
