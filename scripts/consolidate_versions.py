#scripts/consolidate_versions.py
#!/usr/bin/env python3
"""
Consolidation script to fix Issue 4: File version confusion.

This script:
1. Finds all versioned technique files (v2, v3)
2. Identifies the most recent version
3. Copies it to the canonical filename
4. Archives old versions
5. Updates all scripts to use canonical filename

Usage:
    python consolidate_versions.py [--dry-run] [--backup-dir /path/to/backup]
"""

import argparse
import json
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple


# FIX: Correct path calculation
# scripts/consolidate_versions.py -> parents[0] = scripts/ -> parents[1] = repo_root/
REPO_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = REPO_ROOT / "data" / "processed" / "mitre"
SCRIPTS_DIR = REPO_ROOT / "scripts"

# Canonical filename (no version suffix)
CANONICAL_FILE = "techniques_full_enriched.jsonl"

# Files to update references in
SCRIPT_FILES = [
    SCRIPTS_DIR / "enrich_techniques_with_data_components.py",
    SCRIPTS_DIR / "postprocess_enriched_techniques.py",
    SCRIPTS_DIR / "build_mitre_chunks.py",  # if exists
]


def find_versioned_files() -> List[Tuple[Path, str]]:
    """Find all versioned technique files."""
    patterns = [
        "techniques_full_enriched_v*.jsonl",
    ]
    
    files: List[Tuple[Path, str]] = []
    
    for pattern in patterns:
        for path in DATA_DIR.glob(pattern):
            if path.name == CANONICAL_FILE:
                continue
            
            # Extract version
            name = path.stem
            if "_v" in name:
                version = name.split("_v")[-1]
            else:
                version = "unknown"
            
            files.append((path, version))
    
    return files


def get_most_recent_file(files: List[Tuple[Path, str]]) -> Optional[Path]:
    """Determine most recent file by modification time."""
    if not files:
        return None
    
    # Sort by modification time, newest first
    sorted_files = sorted(files, key=lambda x: x[0].stat().st_mtime, reverse=True)
    
    return sorted_files[0][0]


def count_records(jsonl_path: Path) -> int:
    """Count records in JSONL file."""
    count = 0
    try:
        with jsonl_path.open("r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    count += 1
    except Exception as e:
        print(f"[warn] Could not count records in {jsonl_path}: {e}")
    return count


def backup_files(files: List[Tuple[Path, str]], backup_dir: Path) -> None:
    """Backup versioned files before consolidation."""
    backup_dir.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    for path, version in files:
        backup_name = f"{path.stem}_{timestamp}{path.suffix}"
        backup_path = backup_dir / backup_name
        
        print(f"[backup] {path.name} -> {backup_path}")
        shutil.copy2(path, backup_path)


def update_script_references(dry_run: bool = False) -> None:
    """Update script files to use canonical filename."""
    canonical = CANONICAL_FILE
    
    patterns_to_replace = [
        "techniques_full_enriched_v2.jsonl",
        "techniques_full_enriched_v3.jsonl",
        "techniques_full_enriched_v4.jsonl",
    ]
    
    for script_path in SCRIPT_FILES:
        if not script_path.exists():
            print(f"\n[update] Skipping {script_path.name} (not found)")
            continue
        
        print(f"\n[update] Checking {script_path.relative_to(REPO_ROOT)}")
        
        try:
            content = script_path.read_text(encoding="utf-8")
            original_content = content
            
            for pattern in patterns_to_replace:
                if pattern in content:
                    print(f"  - Replacing '{pattern}' with '{canonical}'")
                    content = content.replace(pattern, canonical)
            
            if content != original_content:
                if not dry_run:
                    script_path.write_text(content, encoding="utf-8")
                    print(f"  ✓ Updated {script_path.name}")
                else:
                    print(f"  [dry-run] Would update {script_path.name}")
            else:
                print(f"  - No changes needed")
        
        except Exception as e:
            print(f"  [error] Failed to update {script_path.name}: {e}")


def consolidate_versions(
    dry_run: bool = False,
    backup_dir: Optional[Path] = None,
) -> None:
    """Main consolidation logic."""
    print(f"[consolidate] REPO_ROOT: {REPO_ROOT}")
    print(f"[consolidate] DATA_DIR: {DATA_DIR}")
    print(f"[consolidate] Searching for versioned files in {DATA_DIR}")
    
    if not DATA_DIR.exists():
        print(f"[ERROR] DATA_DIR does not exist: {DATA_DIR}")
        sys.exit(1)
    
    versioned_files = find_versioned_files()
    
    if not versioned_files:
        print("[consolidate] No versioned files found.")
        
        # List all files in DATA_DIR for debugging
        print("\n[consolidate] Files in DATA_DIR:")
        try:
            for f in sorted(DATA_DIR.glob("techniques_full_enriched*.jsonl")):
                print(f"  - {f.name}")
        except Exception as e:
            print(f"  [error] Could not list files: {e}")
        
        return
    
    print(f"\n[consolidate] Found {len(versioned_files)} versioned files:")
    for path, version in versioned_files:
        record_count = count_records(path)
        mtime = datetime.fromtimestamp(path.stat().st_mtime)
        print(f"  - {path.name} (v{version}, {record_count} records, modified: {mtime})")
    
    # Find most recent
    most_recent = get_most_recent_file(versioned_files)
    
    if not most_recent:
        print("[consolidate] Could not determine most recent file.")
        return
    
    print(f"\n[consolidate] Most recent file: {most_recent.name}")
    
    canonical_path = DATA_DIR / CANONICAL_FILE
    
    # Check if canonical already exists and is same as most recent
    if canonical_path.exists() and canonical_path.samefile(most_recent):
        print(f"\n[consolidate] ⚠️  Canonical file already exists and is the same as most recent.")
        print(f"[consolidate] Nothing to do except archive old versions.")
    
    # Backup if requested
    if backup_dir and not dry_run:
        backup_files(versioned_files, backup_dir)
    
    # Copy most recent to canonical
    if not dry_run:
        # Only copy if different or doesn't exist
        should_copy = True
        if canonical_path.exists():
            if canonical_path.samefile(most_recent):
                should_copy = False
                print(f"\n[consolidate] Canonical file is already up-to-date.")
            else:
                print(f"\n[consolidate] Backing up existing {CANONICAL_FILE}")
                backup_canonical = canonical_path.with_suffix(
                    f".backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
                )
                shutil.copy2(canonical_path, backup_canonical)
        
        if should_copy:
            print(f"[consolidate] Copying {most_recent.name} -> {CANONICAL_FILE}")
            shutil.copy2(most_recent, canonical_path)
            print(f"[consolidate] ✓ Created canonical file: {canonical_path}")
        
        # Archive old versions
        archive_dir = DATA_DIR / "archived_versions"
        archive_dir.mkdir(exist_ok=True)
        
        archived_count = 0
        for path, version in versioned_files:
            archive_name = f"{path.stem}_{datetime.now().strftime('%Y%m%d')}{path.suffix}"
            archive_path = archive_dir / archive_name
            
            # Skip if this is the canonical file itself
            if canonical_path.exists() and path.samefile(canonical_path):
                print(f"[consolidate] Skipping {path.name} (is canonical file)")
                continue
            
            print(f"[consolidate] Archiving {path.name} -> {archive_path.relative_to(DATA_DIR)}")
            shutil.move(str(path), str(archive_path))
            archived_count += 1
    else:
        print(f"\n[dry-run] Would copy {most_recent.name} -> {CANONICAL_FILE}")
        print(f"[dry-run] Would archive {len(versioned_files)} versioned files")
        archived_count = len(versioned_files)
    
    # Update script references
    print("\n" + "="*60)
    print("UPDATING SCRIPT REFERENCES")
    print("="*60)
    update_script_references(dry_run=dry_run)
    
    # Summary
    print("\n" + "="*60)
    print("CONSOLIDATION SUMMARY")
    print("="*60)
    if dry_run:
        print("[dry-run] No changes made. Run without --dry-run to apply.")
    else:
        print(f"✓ Canonical file: {CANONICAL_FILE}")
        if archived_count > 0:
            print(f"✓ Archived {archived_count} versioned files")
        else:
            print(f"✓ No files needed archiving")
        print(f"✓ Script references checked")
        print("\nRecommended next steps:")
        print("1. Verify canonical file: ls -lh data/processed/mitre/techniques_full_enriched.jsonl")
        print("2. If you regenerate chunks, re-index: python -m mitre_expert.rag.index_chroma")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Consolidate versioned technique files to canonical filename"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without making changes"
    )
    parser.add_argument(
        "--backup-dir",
        type=Path,
        default=None,
        help="Directory to backup files before consolidation"
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    
    backup_dir = args.backup_dir
    if backup_dir is None and not args.dry_run:
        backup_dir = DATA_DIR / "backups" / datetime.now().strftime("%Y%m%d_%H%M%S")
    
    try:
        consolidate_versions(
            dry_run=args.dry_run,
            backup_dir=backup_dir,
        )
    except Exception as e:
        print(f"\n[ERROR] Consolidation failed: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()