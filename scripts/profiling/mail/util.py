import sys


def log(msg, line_break=True):
    sys.stdout.write(msg)
    if line_break:
        sys.stdout.write("\n")
    sys.stdout.flush()
