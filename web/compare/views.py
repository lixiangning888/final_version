# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import sys

from django.conf import settings
from django.template import RequestContext
from django.shortcuts import render_to_response
from django.views.decorators.http import require_safe

from web import until

sys.path.append(settings.CUCKOO_PATH)

import lib.cuckoo.common.compare as compare
from lib.cuckoo.common.config import Config

import pprint
pp = pprint.PrettyPrinter()

enabledconf = dict()
confdata = Config("reporting").get_config()
for item in confdata:
    if confdata[item]["enabled"] == "yes":
        enabledconf[item] = True
    else:
        enabledconf[item] = False

if enabledconf["mongodb"]:
    import pymongo
    results_db = pymongo.MongoClient(settings.MONGO_HOST, settings.MONGO_PORT)[settings.MONGO_DB]

if enabledconf["elasticsearchdb"]:
    from elasticsearch import Elasticsearch
    baseidx = Config("reporting").elasticsearchdb.index
    fullidx = baseidx + "-*"
    es = Elasticsearch(
             hosts = [{
                 "host": settings.ELASTIC_HOST,
                 "port": settings.ELASTIC_PORT,
             }],
             timeout = 60
         )

@require_safe
def left(request, left_id):
    decrpt_task_id = until.decrpt(left_id)
    if enabledconf["mongodb"]:
        left = results_db.analysis.find_one({"info.id": int(decrpt_task_id)}, {"target": 1, "info": 1})
    if enabledconf["elasticsearchdb"]:
        hits = es.search(
                   index=fullidx,
                   doc_type="analysis",
                   q="info.id: \"%s\"" % decrpt_task_id
                )["hits"]["hits"]
        if hits:
            left = hits[-1]["_source"]
        else:
            left = None
    if not left:
        return render_to_response("error.html",
                                  {"error": "No analysis found with specified ID"},
                                  context_instance=RequestContext(request))
    else:
        if "info" in left:
           left["info"]["base64id"] = left_id

    # Select all analyses with same file hash.
    if enabledconf["mongodb"]:
        records = results_db.analysis.find(
            {
                "$and": [
                    {"target.file.md5": left["target"]["file"]["md5"]},
                    {"info.id": {"$ne": int(decrpt_task_id)}}
                ]
            },
            {"target": 1, "info": 1}
        )
        compare_element = []

        for single_record in records:
          new = single_record

          new["info"]["base64id"] = until.encrpt(new["info"]["id"])
          compare_element.append(new)

    if enabledconf["elasticsearchdb"]:
        records = list()
        results = es.search(
                      index=fullidx,
                      doc_type="analysis",
                      q="target.file.md5: \"%s\" NOT info.id: \"%s\"" % (
                            left["target"]["file"]["md5"], decrpt_task_id)
                  )["hits"]["hits"]
        for item in results:
            records.append(item["_source"])

    return render_to_response("compare/left.html",
                              {"left": left, "records": compare_element},
                              context_instance=RequestContext(request))

@require_safe
def hash(request, left_id, right_hash):
    print "inside hash function"
    if enabledconf["mongodb"]:
        left = results_db.analysis.find_one({"info.id": int(left_id)}, {"target": 1, "info": 1})
    if enabledconf["elasticsearchdb"]:
        hits = es.search(
                   index=fullidx,
                   doc_type="analysis",
                   q="info.id: \"%s\"" % left_id
               )["hits"]["hits"]
        if hits:
            left = hits[-1]["_source"]
        else:
            left = None
    if not left:
        return render_to_response("error.html",
                                  {"error": "No analysis found with specified ID"},
                                  context_instance=RequestContext(request))

    # Select all analyses with same file hash.
    if enabledconf["mongodb"]:
        records = results_db.analysis.find(
            {
                "$and": [
                    {"target.file.md5": right_hash},
                    {"info.id": {"$ne": int(left_id)}}
                ]
            },
            {"target": 1, "info": 1}
        )
    if enabledconf["elasticsearchdb"]:
        records = list()
        results = es.search(
                      index=fullidx,
                      doc_type="analysis",
                      q="target.file.md5: \"%s\" NOT info.id: \"%s\"" % (
                            right_hash, left_id)
                  )["hits"]["hits"]
        for item in results:
            records.append(item["_source"])

    # Select all analyses with specified file hash.
    return render_to_response("compare/hash.html",
                              {"left": left, "records": records, "hash": right_hash},
                              context_instance=RequestContext(request))

@require_safe
def both(request, left_id, right_id):
    if enabledconf["mongodb"]:
        decrpt_left = until.decrpt(left_id)
        decrpt_right = until.decrpt(right_id)
        print "compare both decrpt_left is %s and md5 is %s;" %  (decrpt_left,left_id)
        print "compare both decrpt_right is %s and md5 is %s;" %  (decrpt_right,right_id)
        left = results_db.analysis.find_one({"info.id": int(decrpt_left)}, {"target": 1, "info": 1})
        if "info" in left:
          left["info"]["base64id"] = left_id


        right = results_db.analysis.find_one({"info.id": int(decrpt_right)}, {"target": 1, "info": 1})
        if "info" in right:
          right["info"]["base64id"] = right_id
        print right
        # Execute comparison.
        counts = compare.helper_percentages_mongo(results_db, decrpt_left, decrpt_right)
    if enabledconf["elasticsearchdb"]:
        left = es.search(
                   index=fullidx,
                   doc_type="analysis",
                   q="info.id: \"%s\"" % left_id
               )["hits"]["hits"][-1]["_source"]
        right = es.search(
                    index=fullidx,
                    doc_type="analysis",
                    q="info.id: \"%s\"" % right_id
                )["hits"]["hits"][-1]["_source"]
        counts = compare.helper_percentages_elastic(es, left_id, right_id, fullidx)

    return render_to_response("compare/both.html",
                              {"left": left, "right": right, "left_counts": counts[decrpt_left],
                               "right_counts": counts[decrpt_right]},
                               context_instance=RequestContext(request))
