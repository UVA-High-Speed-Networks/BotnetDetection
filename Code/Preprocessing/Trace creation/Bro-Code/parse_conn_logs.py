# -*- coding: utf-8 -*-
"""
Created on Fri Nov 17 13:48:02 2017

@author: babraham
"""
from bisect import bisect_left
import numpy as np
from collections import Counter
import pandas as pd


flags = ['s','h','a','d','f','r','c','t','i','q']
flags_upper = [f.upper() for f in flags]
fkeys = flags + flags_upper
empty_flags = dict([(k, 0) for k in fkeys])
metric_dict = {'src_bytes': 0,
             'src_pkts': 0,
             'dest_bytes': 0,
             'dest_pkts': 0,
             'intvl': 0, 
             'duration': 0}

class ConnFlow():
    def __init__(self, rec):
        self.uid = rec['uid']
        self.startTime = float(rec['ts'])
        self.srcIP = rec['id.orig_h']
        self.destIP = rec['id.resp_h']
        self.destPt = int(rec['id.resp_p'])
        self.src_bytes = int(rec['orig_bytes'])
        self.dest_bytes = int(rec['resp_bytes'])
        self.protocol = rec['proto']
        self.duration = float(rec['duration'])
        self.src_pkts = int(rec['orig_pkts'])
        self.dest_pkts = int(rec['resp_pkts'])
        self.tot_bytes = self.src_bytes + self.dest_bytes
        self.tot_pks = self.src_pkts + self.dest_pkts
        self.parseHistory(rec['history'])
    def parseHistory(self, hist_str):
        self.flags = dict([(k,0) for k in empty_flags.keys()])
        for f in hist_str:
            self.flags[f]=1
    def __str__(self):
        return str(self.__dict__)
    def hashval(self):
        return '|'.join([str(self.srcIP), str(self.destIP), str(self.destPt), self.protocol])


class ConnTrace():
    def __init__(self, cflow):
        self.startTime = cflow.startTime
        self.srcIP = cflow.srcIP
        self.destIP = cflow.destIP
        self.destPt = cflow.destPt
        self.protocol = cflow.protocol
        self.means = dict([(k,0) for k in metric_dict.keys()])
        self.stdevs = dict([(k,0) for k in metric_dict.keys()])
        self.flagcts = dict([(k, 0) for k in empty_flags.keys()])
        self.times = []
        self.intervals = []
        self.flowct = 0
        self.addFlow(cflow)

    def addFlow(self, cf):
        self.startTime = min(self.startTime, cf.startTime)
        self.updateMeans(cf)
        if self.flowct >= 1: self.updateStDevs(cf)
        self.insert_time(cf.startTime)
        for k in self.flagcts.keys(): self.flagcts[k] +=cf.flags[k] 
        self.flowct +=1
        
    def updateMeans(self, cf):
        self.means['src_bytes'] = (float(self.flowct* self.means['src_bytes'] + cf.src_bytes)) / float(self.flowct+1)
        self.means['dest_bytes'] = (float(self.flowct* self.means['dest_bytes'] + cf.dest_bytes)) / float(self.flowct+1)
        self.means['src_pkts'] = (float(self.flowct* self.means['src_pkts'] + cf.src_pkts)) / float(self.flowct+1)
        self.means['dest_pkts'] = (float(self.flowct* self.means['dest_pkts'] + cf.dest_pkts)) / float(self.flowct+1)
        self.means['duration'] = (float(self.flowct* self.means['duration'] + cf.duration)) / float(self.flowct+1)        
    
    def updateStDevs(self, cf):
        self.stdevs['src_bytes'] = (float(self.flowct* self.stdevs['src_bytes'] + abs(cf.src_bytes-self.means['src_bytes']))) / float(self.flowct+1)
        self.stdevs['dest_bytes'] = (float(self.flowct* self.stdevs['dest_bytes'] +abs(cf.dest_bytes-self.means['dest_bytes']))) / float(self.flowct+1)
        self.stdevs['src_pkts'] = (float(self.flowct* self.stdevs['src_pkts'] + abs(cf.src_pkts-self.means['src_pkts']))) / float(self.flowct+1)
        self.stdevs['dest_pkts'] = (float(self.flowct* self.stdevs['dest_pkts'] + abs(cf.dest_pkts-self.means['dest_pkts']))) / float(self.flowct+1)
        self.stdevs['duration'] = (float(self.flowct* self.stdevs['duration'] + abs(cf.duration-self.means['duration']))) / float(self.flowct+1)        
    
    def insert_time(self, t):
        insert_idx = 0
        try:
            if len(self.times) == 1 and t > self.times[0]: insert_idx = 1
            else: insert_idx = bisect_left(self.times, t)
            self.times.insert(insert_idx, t)
            self.update_intvls(insert_idx)
        except:
            pass
            #print "idx: " + str(insert_idx) +", t: " + str(t) +  ", times: " + str(self.times) + ", intvls: " + str(self.intervals)
    
    def hashval(self):
        return '|'.join([str(self.srcIP), str(self.destIP), str(self.destPt), self.protocol])
    
    def update_intvls(self, idx):
        if idx == 0:
            self.intervals.insert(0, self.times[1] - self.times[0])
        elif idx == len(self.times) -1:
            self.intervals.append(self.times[idx] - self.times[idx-1])
        else:
            self.intervals.insert(idx-1, 0)
            self.intervals[idx -1] = self.times[idx] - self.times[idx-1]
            self.intervals[idx] = self.times[idx+1] - self.times[idx]
        self.means['intvl'] = np.mean(self.intervals)
        self.stdevs['intvl'] = np.std(self.intervals)
        
    def __str__(self):
        retstr = 'flowct: ' + str(self.flowct) + ' , ' +  self.__hash__() + '\n' + 'means: ' + str(self.means) + '\n' + 'stdevs: '+ str(self.stdevs)
        retstr += '\ntimes: ' + str(self.times) + '\nintvls: ' + str(self.intervals)
        retstr += '\nflags: ' + str(self.flagcts)
        return str(retstr)
    def getOutput(self):
        info = [self.srcIP, self.destIP, self.destPt, self.protocol, self.startTime]
        stats = [self.flowct]
        fields = ['srcIP', 'destIP', 'destPt', 'protocol', 'startTime', 'flowct']
        for k in sorted(self.means.keys()):
            stats.append(self.means[k])
            stats.append(self.stdevs[k])
            fields.append('mean_'+k)
            fields.append('stdev_'+k)
        [stats.append(self.flagcts[k]) for k in sorted(self.flagcts.keys())]
        [fields.append(k) for k in sorted(self.flagcts.keys())]
        return fields, info + stats

lf = '/Users/babraham/Desktop/pcap/zeus_bro_output/bro_paper_output/conn.log'
st = '/Users/babraham/Desktop/pcap/zeus_bro_output/bro_paper_output/short_trace.csv'
st2 = '/Users/babraham/Desktop/pcap/zeus_bro_output/bro_paper_output/short_trace_2.csv'
mt = '/Users/babraham/Desktop/pcap/zeus_bro_output/bro_paper_output/med_trace.csv'
lt = '/Users/babraham/Desktop/pcap/zeus_bro_output/bro_paper_output/large_trace.csv'
test = '/Users/babraham/Desktop/pcap/zeus_bro_output/bro_paper_output/test.csv'

def readTraceFlows(f):
    df = pd.DataFrame.from_csv(f)
    return [ConnFlow(row) for i, row in df.iterrows()]

def parse_conn(logfile, outputDir=""):
    f = open(logfile, 'r')
    lines = f.readlines()
    fieldlist = []
    if len(outputDir) > 0 and not outputDir.endswith('/'): outputDir += '/'
    for l in lines[1:10]:
        if '#fields' in l: fieldlist = l.split('\t')
    fields = {fieldlist[i]:i-1 for i in range(len(fieldlist))}
    imp_fields = ['uid', 'ts', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'orig_bytes', 'orig_pkts', 'proto', 'resp_bytes', 'resp_pkts', 'history', 'duration', 'service']
    imp_inds = [fields[fi] for fi in imp_fields]
    recs = []
    for l in lines[8:len(lines)-2]:
        lsplit = l.split('\t')
        values = [lsplit[i] for i in imp_inds]
        for i in range(len(values)):
            if values[i] == '-': values[i] = '0'
        rec = dict(zip(imp_fields, values))
        recs.append(rec)
    return [imp_fields, recs]
    
def export_con(lf):
    res = parse_conn(lf)
    df = pd.DataFrame(res[1], columns=res[0])
    df.to_csv('conn_formatted.csv')

def getTraces(lf):
    data = parse_conn(lf)
    trDict = dict()
    out = open('traces.csv', 'w')
    flows = [ConnFlow(d) for d in data[1]]
    for f in flows:
        if f.hashval() not in trDict: trDict[f.hashval()] = ConnTrace(f)
        else: trDict[f.hashval()].addFlow(f)
    fields = list(trDict.values())[0].getOutput()[0]
    out.write(','.join(fields) + '\n')
    for v in trDict.values():
        row = v.getOutput()[1]
        row = [str(r) for r in row]
        out.write(','.join(row) + '\n')
    out.close()
    return trDict
        
            
    

getTraces(r"C:\Users\abhij\Desktop\UVa Coursework\Capstone\Conn logs\conn_malacious_35_1.log")