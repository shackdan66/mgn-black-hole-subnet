import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent / "src"))

from naclmaker.cli import run


if __name__ == "__main__":
    run()
