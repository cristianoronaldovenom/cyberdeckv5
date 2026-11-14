"""App inventory and lifecycle: list, start, stop, install, uninstall, extract."""

from __future__ import annotations

import os

from omni.core import console
from omni.core.module import Option
from omni.android.modules._base import AndroidModule


class ListApps(AndroidModule):
    NAME = "android.apps"
    DESCRIPTION = "List third-party packages (or all installed)"
    OPTIONS = (Option("ALL", "include system apps", "false",
                      choices=("true", "false")),)

    def execute(self) -> list[str]:
        packages = self.adb().packages(third_party_only=not self.get_bool("ALL"))
        console.table(["#", "package"], [[str(i), p] for i, p in
                                         enumerate(packages, 1)])
        return packages


class Running(AndroidModule):
    NAME = "android.running"
    DESCRIPTION = "List foreground/visible activities"

    def execute(self) -> list[str]:
        rows = self.adb().running_packages()
        console.table(["#", "package"], [[str(i), p] for i, p in
                                         enumerate(rows, 1)])
        return rows


class StartApp(AndroidModule):
    NAME = "android.start"
    DESCRIPTION = "Launch an app by package name"
    OPTIONS = (Option("PACKAGE", "package name", required=True),)

    def execute(self) -> str:
        pkg = self.get("PACKAGE")
        self.adb().start_app(pkg)
        return pkg


class StopApp(AndroidModule):
    NAME = "android.stop"
    DESCRIPTION = "Force-stop an app"
    OPTIONS = (Option("PACKAGE", "package name", required=True),)

    def execute(self) -> str:
        pkg = self.get("PACKAGE")
        self.adb().force_stop(pkg)
        return pkg


class ClearApp(AndroidModule):
    NAME = "android.clear"
    DESCRIPTION = "Wipe an app's data"
    OPTIONS = (Option("PACKAGE", "package name", required=True),)

    def execute(self) -> str:
        pkg = self.get("PACKAGE")
        self.adb().clear_data(pkg)
        return pkg


class InstallApk(AndroidModule):
    NAME = "android.install"
    DESCRIPTION = "Install a local APK"
    OPTIONS = (Option("APK", "path to .apk", required=True),)

    def execute(self) -> str:
        apk = os.path.expanduser(self.get("APK"))
        if not os.path.isfile(apk):
            raise FileNotFoundError(apk)
        res = self.adb().install(apk)
        if "Success" not in res.text:
            raise RuntimeError(res.text[:300])
        console.ok("installed")
        return apk


class UninstallApk(AndroidModule):
    NAME = "android.uninstall"
    DESCRIPTION = "Uninstall an app"
    OPTIONS = (Option("PACKAGE", "package name", required=True),)

    def execute(self) -> str:
        pkg = self.get("PACKAGE")
        res = self.adb().uninstall(pkg)
        if "Success" not in res.text:
            raise RuntimeError(res.text[:300])
        return pkg


class ExtractApk(AndroidModule):
    NAME = "android.extract"
    DESCRIPTION = "Pull an installed APK for offline reversing"
    OPTIONS = (Option("PACKAGE", "package name (blank = all third-party)",
                      ""),)

    def execute(self) -> list[str]:
        from omni.android import media
        client = self.adb()
        saved = media.extract_apks(client, self.get("PACKAGE") or None)
        if not saved:
            raise RuntimeError("nothing extracted")
        return saved
