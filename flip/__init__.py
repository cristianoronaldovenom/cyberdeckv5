"""Flipper trade — file formats and firmware helper (Private-Unleashed ports).

The heavy RF math lives in :mod:`omni.rf`; this package adds the on-disk
``.sub`` / ``.ir`` / ``.ibtn`` formats and firmware bundle helpers.
"""

from omni.flip import files, firmware, ir, ibutton

__all__ = ["files", "firmware", "ir", "ibutton"]

