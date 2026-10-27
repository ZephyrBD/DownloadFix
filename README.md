# Download Fix

A small local compatibility adjuster for PCL.

## Requirements

- **Python 3.8 or newer**

## Usage

1. Download `DownloadFix.py` from this repository.
2. Put `DownloadFix.py` and `Plain Craft Launcher 2.exe` in the same directory.
3. Run it.

```bash
python ./DownloadFix.py
```

You may also pass a path:

```bat
python DownloadFix.py "E:\PCL\Plain Craft Launcher 2.exe"
```

### Options

| Option       | Description                                          |
| ------------ | ---------------------------------------------------- |
| `-o out.exe` | Output file (default: `<name> (Patched).exe`)        |
| `--force`    | Overwrite an existing output file                    |
| `--inspect`  | Print analysis only, without modifying anything      |
| `--in-place` | Write back into the original file (a `.bak` is made) |

## Notes

- Tested against PCL 2.99.0.0 and 2.99.0.1; it may stop working after later PCL updates.
- The adjusted copy keeps working with the official "check for updates": updates are fetched as the full package instead of the incremental patch.

## License & Attribution

- PCL is developed by LTCatt: <https://github.com/Meloong-Git/PCL>

- This repository is an unofficial third-party tool. It is not affiliated with, nor does it represent, the PCL project.

- This repository contains no part of PCL, neither source code nor binaries. It only adjusts your local copy — please do not redistribute PCL itself, whether adjusted or not. Check the laws of your region and the PCL license before use.

- The **MIT LICENSE** of this repository covers only the original code herein (`DownloadFix.py`, `PatchModpack.cs`); it does not cover any PCL-related strings referenced by that code, whose rights remain with their original author.
