# -*- coding: utf-8 -*-
"""
Created on Sat Oct 14 18:13:45 2017

@author: babraham
"""
"""
Fields:
src ip
dest ip
# flows
avg. client-srver size
avg. server-client size
avg. flow interval
avg. flow duration
"""
import os
import re
import numpy as np
from bisect import bisect_left

class httpFlow():
    def __init__(self, srcip, dstip, dstport, stime, cs_bytes, sc_bytes):
        self.times = [stime]
        self.intervals = []
        self.srcip = srcip
        self.dstip = dstip
        self.dstport = dstport
        self.flowct = 1
        self.mean_cs_bytes = cs_bytes
        self.mean_sc_bytes = sc_bytes
        self.mean_fint = 0
    def insert_flow(self, startTime, cs_bytes, sc_bytes):
        self.mean_cs_bytes = (self.flowct* self.mean_cs_bytes + cs_bytes) / (self.flowct+1)
        self.mean_sc_bytes = (self.flowct* self.mean_sc_bytes + sc_bytes) / (self.flowct+1)
        self.insert_time(startTime)
        self.mean_fint = np.mean(self.intervals)
        self.flowct +=1
        #FINISH
    def insert_time(self, t):
        insert_idx = 0
        try:
            if len(self.times) == 1:
                if t > self.times[0]:
                    insert_idx = 1
            else: insert_idx = bisect_left(self.times, t)
            self.times.insert(insert_idx, t)
            self.update_intvls(insert_idx)
        except:
            print "idx: " + str(insert_idx) + ", times: " + str(self.times) + ", intvls: " + str(self.intervals)
    def update_intvls(self, idx):
        if idx == 0:
            self.intervals.insert(0, self.times[1] - self.times[0])
        elif idx == len(self.times) -1:
            self.intervals.append(self.times[idx] - self.times[idx-1])
        else:
            self.intervals.insert(idx, 0)
            self.intervals[idx -1] = self.times[idx] - self.times[idx-1]
            self.intervals[idx] = self.times[idx+1] - self.times[idx]
        self.mean_fint = np.mean(self.intervals)        
    def __hash__(self):
        return str(self.srcip)+str(self.dstip)+str(self.dstport)
    def stats(self):
        return {"flowct": self.flowct, "mean_cs_size":self.mean_cs_bytes, "mean_sc_size":self.mean_sc_bytes, "avgFlowIntvl": self.mean_fint}
    def __str__(self):
        retStr = "src ip: " + str(self.srcip) + ", dest ip: " + str(self.dstip) + '\n'
        retStr += str(self.stats()) + '\n'
        retStr += "flow times: " + str(self.times) + '\nflow intervals: ' + str(self.intervals) + '}'
        return retStr   
        
ftest = 'lenovo_bro_logs/http.csv'

ft2 = '/Users/babraham/Desktop/Bro-http-logs/em1_http_1hr.csv'        
def bro_to_traces(fname, output_name = 'http_traces.csv'):
    traces = readTraces(fname)
    exportTraces(traces, output_name)

def readTraces(fname):
    f = open(fname, 'r') 
    lines = f.readlines()
    fields = lines[0].split(',')
    print "fields: " + str(fields)
    imp_fields = ['ts', 'id.orig_h', 'id.resp_h', 'id.resp_p', 'host', 'request_body_len', 'response_body_len']
    print "imp fields: " + str(imp_fields)
    fdict = {t:fields.index(t) for t in imp_fields}
    flowDict = dict()
    for l in lines[1:]:
        lsplit = l.split(',')
        startTime = float(lsplit[fdict['ts']])
        print str(startTime)
        srcIp = lsplit[fdict['id.orig_h']]
        destIp = lsplit[fdict['id.resp_h']]
        destPt = lsplit[fdict['id.resp_p']]
        cs_size = int(re.sub('-','0',lsplit[fdict['request_body_len']]))
        sc_size = int(re.sub('-','0',lsplit[fdict['response_body_len']]))
        flowId = str(srcIp)+str(destIp)+str(destPt)
        if flowId not in flowDict:
            hFlow = httpFlow(srcIp, destIp, destPt, startTime, cs_size, sc_size)
            flowDict[hFlow.__hash__()] = hFlow
        else:
            flowDict[flowId].insert_flow(startTime, cs_size, sc_size)
    return flowDict
    
def exportTraces(data, outfilename='http_traces.csv'):
    out = open(outfilename, 'w')
    out.write('src_host, dest_host, dest_port, avgFlowInterval, flowCount, mean_request_size, mean_response_size\n')
    for v in data.values():
        record = [v.srcip, v.dstip, v.dstport]
        stats = sorted(v.stats().items())
        for s in stats:
            record.append(str(s[1]))
        print str(record)
        out.write(",".join(record) + '\n')
    out.close()
        
        



    
    

