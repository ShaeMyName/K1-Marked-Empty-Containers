# Marked Empty Containers (KOTOR 1)

Appends " (empty)" to the floating hover name of any container or lootable corpse that currently holds nothing. Now you can tell an empty footlocker from a full one at a glance without stopping to open it.
- Shows the moment you first see an initially-empty container.
- Updates live the instant you loot one empty, while you're still hovering over it.
- Covers lootable corpses too (KOTOR stores them as "Remains" containers).

## Install

1. Close KOTOR completely (the .exe can't be edited while it's running).
2. Copy these three files into your KOTOR folder, next to `swkotor.exe` (typically `C:\Program Files (x86)\Steam\steamapps\common\swkotor\`):
   - `MarkEmptyContainers.exe`
   - `Apply Container Patch.bat`
   - `Revert Container Patch.bat`
3. Double-click `Apply Container Patch.bat`. It prints `SUCCESS` and makes a backup. Launch the game and enjoy.

## Uninstall / Revert

1. Close KOTOR.
2. Double-click `Revert Container Patch.bat`. This restores `swkotor.exe` exactly as it was (from the backup it made: `swkotor.exe.MarkEmpty.bak`).

## Building from source

The patcher is one file [`src/markempty.py`](src/markempty.py) and uses only the Python standard library (`sys`, `os`, `struct`, `shutil`). Nothing to install to run it.

### Option A: run it directly (no build, no exe)

With KOTOR closed, from your KOTOR folder (the one containing `swkotor.exe`):
```
python "path\to\markempty.py" apply
python "path\to\markempty.py" revert
```

It patches the `swkotor.exe` in the current folder and makes a backup, exactly like the `.bat` files do.

### Option B: build the standalone `MarkEmptyContainers.exe`

Requirements: Windows (the output is a Windows `.exe`; PyInstaller does not cross-compile) and Python 3.x. Then:
```
python -m pip install --upgrade pyinstaller
python -m PyInstaller --onefile --name MarkEmptyContainers src/markempty.py
```

The exe appears in `dist\MarkEmptyContainers.exe`. Copy it next to `swkotor.exe` together with the two `.bat` files and use them as described above.