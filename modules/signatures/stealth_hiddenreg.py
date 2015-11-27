# -*- coding: utf-8 -*-
# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class StealthHiddenReg(Signature):
    name = "stealth_hiddenreg"
    description = "尝试修改Windows桌面进程以防止隐藏文件被显示"
    severity = 3
    categories = ["stealth"]
    authors = ["Optiv"]
    minimum = "1.2"

    def run(self):
        reg_indicators = [
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\Advanced\\\\Hidden$",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\Advanced\\\\ShowSuperHidden$",
        ]

        for indicator in reg_indicators:
            reg_match = self.check_write_key(pattern=indicator, regex=True, all=True)
            if reg_match:
                return True
        return False
