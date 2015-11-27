# -*- coding: utf-8 -*-
# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class RansomwareRecyclebin(Signature):
    name = "ransomware_recyclebin"
    description = "清空回收站，常见于勒索软件（ransomware）"
    severity = 3
    categories = ["ransomware"]
    authors = ["Optiv"]
    minimum = "1.2"

    def run(self):
        if self.check_delete_file(pattern="C:\\\\RECYCLER\\\\.*", regex=True):
            return True
        return False