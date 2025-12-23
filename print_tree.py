# save as: print_tree.py  (run with: python print_tree.py)
from pathlib import Path

# change this if you want to start from another folder
ROOT = Path(__file__).resolve().parent  # current folder (where script is)

# folders to skip (optional)
SKIP_DIRS = {".git", ".venv", "__pycache__", ".idea", ".mypy_cache", ".pytest_cache"}

def print_tree(root: Path, prefix: str = ""):
    # sort entries so output is stable
    entries = sorted(root.iterdir(), key=lambda p: (p.is_file(), p.name.lower()))

    # last entry marker for nice tree drawing
    entries_count = len(entries)
    for i, entry in enumerate(entries):
        connector = "└── " if i == entries_count - 1 else "├── "

        if entry.is_dir():
            if entry.name in SKIP_DIRS:
                continue

            print(f"{prefix}{connector}{entry.name}/")
            # extend prefix for children of this dir
            new_prefix = prefix + ("    " if i == entries_count - 1 else "│   ")
            print_tree(entry, new_prefix)
        else:
            print(f"{prefix}{connector}{entry.name}")

if __name__ == "__main__":
    print(f"Root: {ROOT}")
    print_tree(ROOT)
