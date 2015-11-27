# -*- coding: utf-8 -*-
# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class VolMalfind1(Signature):
    name = "volatility_malfind_1"
    description = "Malfind检测到被注入的进程"
    severity = 2
    alert = False
    categories = ["generic"]
    authors = ["Thorsten Sick"]
    minimum = "0.5"

    def run(self):
        if ("volatility" in self.results and
            "malfind" in self.results["volatility"]):
            if len(self.results["volatility"]["malfind"]["data"]):
                self.data.append(
                    {"data": self.results["volatility"]["malfind"]["data"]})
                return True

        return False


class VolMalfind2(Signature):
    name = "volatility_malfind_2"
    description = "Malfind检测到超过3个被注入的进程"
    severity = 3
    alert = False   # Very suspicious, but has detection on clean files
    categories = ["generic"]
    authors = ["Thorsten Sick"]
    minimum = "0.5"
    families = ["ZBot", "Paelvo", "Sinowal"]

    def run(self):
        pids = set()
        if ("volatility" in self.results and
            "malfind" in self.results["volatility"]):
            for a in self.results["volatility"]["malfind"]["data"]:
                pids.add(a["process_id"])
            if len(pids) > 3:
                self.data.append(
                    {"data": self.results["volatility"]["malfind"]["data"]})
                return True

        return False


class VolLdrModules1(Signature):
    name = "volatility_ldrmodules_1"
    description = "更改PEB以隐藏加载的模块，DLL很可能没有被LoadLibrary加载"
    severity = 3
    alert = False   # Skype seems to do that...
    categories = ["generic"]
    authors = ["Thorsten Sick"]
    minimum = "0.5"

    # http://mnin.blogspot.de/2011/06/examining-stuxnets-footprint-in-memory.html

    def run(self):
        exceptions = ["csrss.exe"]

        res = False
        if ("volatility" in self.results and
            "ldrmodules" in self.results["volatility"]):
            for d in self.results["volatility"]["ldrmodules"]["data"]:
                if (not d["dll_in_init"] and
                    not d["dll_in_load"] and
                    not d["dll_in_mem"] and
                    not d["process_name"].lower() in exceptions):
                    self.data.append({"unlinked": d})
                    res = True

        return res


class VolLdrModules2(Signature):
    name = "volatility_ldrmodules_2"
    description = "更改PEB以隐藏加载的模块，而不是路径名，DLL很可能没有被LoadLibrary加载"
    severity = 3
    alert = True
    categories = ["generic"]
    authors = ["Thorsten Sick"]
    minimum = "0.5"

    # http://mnin.blogspot.de/2011/06/examining-stuxnets-footprint-in-memory.html

    def run(self):
        res = False
        if ("volatility" in self.results and
            "ldrmodules" in self.results["volatility"]):
            for d in self.results["volatility"]["ldrmodules"]["data"]:
                if d["process_name"] == "":
                    self.data.append({"unlinked": d})
                    res = True

        return res


class VolDevicetree1(Signature):
    name = "volatility_devicetree_1"
    description = "设备驱动器没有名称"
    severity = 3
    alert = True
    categories = ["generic"]
    authors = ["Thorsten Sick"]
    families = ["Zero access"]
    minimum = "0.5"

    # http://mnin.blogspot.de/2011/10/zeroaccess-volatility-and-kernel-timers.html

    def run(self):
        res = False
        if ("volatility" in self.results and
            "devicetree" in self.results["volatility"]):
            for d in self.results["volatility"]["devicetree"]["data"]:
                if d["driver_name"] == "":
                    self.data.append({"unnamed_driver": d})
                    res = True

        return res


class VolSvcscan1(Signature):
    name = "volatility_svcscan_1"
    description = "停止了防火墙服务"
    severity = 3
    alert = True
    categories = ["generic"]
    authors = ["Thorsten Sick"]
    families = ["Zero access"]
    minimum = "0.5"

    def run(self):
        res = False
        if ("volatility" in self.results and
            "svcscan" in self.results["volatility"]):
            for s in self.results["volatility"]["svcscan"]["data"]:
                if (s["service_name"] == "SharedAccess" and
                    s["service_state"] == "SERVICE_STOPPED"):
                    self.data.append({"stopped_service": s})
                    res = True

        return res


class VolSvcscan2(Signature):
    name = "volatility_svcscan_2"
    description = "停止了安全中心服务"
    severity = 3
    alert = True
    categories = ["generic"]
    authors = ["Thorsten Sick"]
    families = ["Zero access"]
    minimum = "0.5"

    def run(self):
        res = False
        if ("volatility" in self.results and
            "svcscan" in self.results["volatility"]):
            for s in self.results["volatility"]["svcscan"]["data"]:
                if (s["service_name"] == "wscsvc" and
                    s["service_state"] == "SERVICE_STOPPED"):
                    self.data.append({"stopped_service": s})
                    res = True

        return res


class VolSvcscan3(Signature):
    name = "volatility_svcscan_3"
    description = "停止了应用层网关服务"
    severity = 3
    alert = True
    categories = ["generic"]
    authors = ["Thorsten Sick"]
    families = ["Zero access"]
    minimum = "0.5"

    def run(self):
        res = False
        if ("volatility" in self.results and
            "svcscan" in self.results["volatility"]):
            for s in self.results["volatility"]["svcscan"]["data"]:
                if (s["service_name"] == "ALG" and
                    s["service_state"] == "SERVICE_STOPPED"):
                    self.data.append({"stopped_service": s})
                    res = True

        return res


class VolModscan1(Signature):
    name = "volatility_modscan_1"
    description = "内核模块没有名称"
    severity = 3
    alert = True
    categories = ["generic"]
    authors = ["Thorsten Sick"]
    families = ["Zero access"]
    minimum = "0.5"

    def run(self):
        res = False
        if ("volatility" in self.results and
            "modscan" in self.results["volatility"]):
            for m in self.results["volatility"]["modscan"]["data"]:
                if m["kernel_module_name"] == "":
                    self.data.append({"mysterious_kernel_module": m})
                    res = True

        return res


class VolHandles1(Signature):
    name = "volatility_handles_1"
    description = "在其他进程中有很多线程"
    severity = 2
    alert = False
    categories = ["generic"]
    authors = ["Thorsten Sick"]
    minimum = "0.5"

    def run(self):
        threads = set()

        if ("volatility" in self.results and
            "handles" in self.results["volatility"]):
            for h in self.results["volatility"]["handles"]["data"]:
                if h["handle_type"] == "Thread":
                    w1, t1, w2, p1 = h["handle_name"].split(" ")
                    t1 = int(t1)
                    p1 = int(p1)
                    if p1 != h["process_id"]:
                        threads.add("%d -> %d/%d" % (h["process_id"], p1, t1))

        if len(threads) > 5:
            self.data.append({"injections": list(threads)})
            return True

        return False
