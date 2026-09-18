import argparse
from pathlib import Path
import subprocess
import sys
import time


def run(mode, output, text=None):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    with (output / "console.log").open("w") as console:
        process = subprocess.Popen(
            [sys.executable, "-m", "arplab.attack", "--mode", mode,
             "--duration", "30", "--output", str(output)]
            + (["--text=" + text] if text is not None else []),
            stdout=console, stderr=subprocess.STDOUT,
        )
        try:
            while process.poll() is None:
                if (output / "stop").exists():
                    process.terminate()
                    break
                time.sleep(0.1)
        finally:
            if process.poll() is None:
                process.terminate()
            code = process.wait()
            (output / "exit-code").write_text(str(code))
    return code


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("relay", "modify", "drop"))
    parser.add_argument("output")
    parser.add_argument("--text")
    args = parser.parse_args()
    sys.exit(run(args.mode, args.output, args.text))
