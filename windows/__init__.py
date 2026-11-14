"""Windows trade — credential and persistence tradecraft (port of
Windows-Hacking-Scripts-With-Python).

The scripts here run **on** the Windows host (they use ``ctypes`` and ``netsh``)
and can also be pointed at a mounted image for offline triage.
"""

from omni.windows import browsers, dpapi, persist, recon, wifi

__all__ = ["browsers", "dpapi", "persist", "recon", "wifi"]

