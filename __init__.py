"""OMNI ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â one Linux/Kali box, seven hacking trades.

Consolidated toolkit built from:

  * Private-Unleashed-2.0-FlipperZero-Firmware  -> omni.rf   (CC1101 sub-GHz stack)
  * PhoneSploit-Pro                             -> omni.android (ADB takeover)
  * unbekannt-framework                         -> omni.pentest (module shell)
  * Mobile-Device-Hacker-Toolkit                -> omni.mobile (Frida/MobSF/jadx)
  * Windows-Hacking-Scripts-With-Python         -> omni.windows (credential harvest)
  * newsyc + MarcoSero/HackerNews               -> omni.news  (HN client)
  * flipperc0d3r firmware assets                -> omni.flip  (Flipper file formats)

Everything is pure standard-library Python and runs on Kali/Debian/Arch without
a build step. Hardware-specific subsystems degrade to demo mode when the
device (CC1101, ADB phone, Flipper, PN532) is absent.

Educational / authorized testing use only.
"""

__version__ = "1.4.2"
__toolkit__ = "OMNI"

#: codename shown in banners
CODENAME = "thirteen-trades"






