"""Make the example's own modules and the yukti core importable in tests."""

import os
import sys

_HERE = os.path.dirname(__file__)
_SRC = os.path.abspath(os.path.join(_HERE, "..", "..", "src"))
for p in (_HERE, _SRC):
    if p not in sys.path:
        sys.path.insert(0, p)
