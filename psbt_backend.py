"""Select the PSBT backend: the pure-Python py_spdk (default) or the Rust spdk_psbt.

Set BIP375_PSBT_BACKEND=spdk to use the Rust/UniFFI extension. Both expose the
same API, so `just test-parity` can generate with each and compare the output.
"""

import os

BACKEND = os.environ.get("BIP375_PSBT_BACKEND", "py")

if BACKEND == "spdk":
    from importlib.metadata import version as _version
    from spdk_psbt import *  # noqa: F401,F403

    BACKEND_LABEL = f"spdk_psbt {_version('spdk_psbt')}"
elif BACKEND == "py":
    from py_spdk import *  # noqa: F401,F403

    BACKEND_LABEL = "py_spdk (pure Python)"
else:
    raise ImportError(f"Unknown BIP375_PSBT_BACKEND: {BACKEND!r} (expected 'py' or 'spdk')")
