# -*- coding: utf-8 -*-
# Copyright (C) 2014 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class RemovesZoneIdADS(Signature):
    name = "removes_zoneid_ads"
    description = "尝试删除从因特网下载文件的证据"
    severity = 3
    categories = ["generic"]
    authors = ["Optiv"]
    minimum = "1.0"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    filter_apinames = set(["DeleteFileA","DeleteFileW"])

    def on_call(self, call, process):
        if call["api"].startswith("DeleteFile") and self.get_argument(call, "FileName").endswith(":Zone.Identifier"):
            self.data.append({"file" : self.get_argument(call, "FileName") })
            return True

        return None
