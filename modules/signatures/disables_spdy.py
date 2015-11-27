# -*- coding: utf-8 -*-
# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class DisablesSPDY(Signature):
    name = "disables_spdy"
    description = "尝试禁止火狐（Firefox）浏览器的SPDY服务以增强网络信息窃取的能力"
    severity = 3
    weight = 2
    categories = ["generic"]
    authors = ["Optiv"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    filter_apinames = set(["NtWriteFile"])

    def on_call(self, call, process):
        buf = self.get_argument(call, "Buffer")
        if "network.http.spdy.enabled" in buf and "false" in buf:
            return True
