import sys
import threading

t = None

def print_dot():
    global t
    print(".", end="", file=sys.stderr)
    sys.stderr.flush()
    if t:
        t.cancel()
    t = threading.Timer(1, print_dot)
    t.daemon = True
    t.start()

def exit(r):
    t.cancel()
    sys.exit(r)
