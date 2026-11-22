import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
for path in (os.path.dirname(HERE), HERE, os.path.join(os.path.dirname(os.path.dirname(HERE)), "inference")):
    if path not in sys.path:
        sys.path.insert(0, path)
