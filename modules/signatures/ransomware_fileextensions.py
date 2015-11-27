# -*- coding: utf-8 -*-
from lib.cuckoo.common.abstracts import Signature

class RansomwareExtensions(Signature):
    name = "ransomware_extensions"
    description = "对加密文件附加常见勒索软件文件扩展名"
    severity = 3
    categories = ["ransomware"]
    authors = ["Kevin Ross"]
    minimum = "1.2"

    def run(self):
        indicators = [
            ".*\.aaa$",
            ".*\.abc$",
            ".*\.ccc$",
            ".*\.ecc$",
            ".*\.exx$",
            ".*\.ezz$",
        ]

        for indicator in indicators:
            results = self.check_write_file(pattern=indicator, regex=True, all=True)
            if results and len(results) > 15:
                return True

        return False
