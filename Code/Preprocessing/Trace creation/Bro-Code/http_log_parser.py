# -*- coding: utf-8 -*-
"""
Created on Tue Oct 10 00:03:05 2017

@author: babraham
"""
import re
import subprocess as sp


def parse_http(logfile, outputDir=""):
    f = open(logfile, 'r')
    lines = f.readlines()
    fieldlist = []
    if len(outputDir) > 0 and not outputDir.endswith('/'): outputDir += '/'
    for l in lines[1:10]:
        if '#fields' in l: fieldlist = l.split('\t')
    fields = {fieldlist[i]:i-1 for i in range(len(fieldlist))}
    imp_fields = ['ts', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'host', 'request_body_len', 'proxied','method', 'orig_filenames', 'resp_filenames', 'response_body_len', 'status_code', 'status_msg', 'tags', 'user_agent', 'uri', 'version']
    
    imp_inds = [fields[fi] for fi in imp_fields]
    recs = []
    for l in lines[8:len(lines)-2]:
        rec = []
        lsplit = l.split('\t')
        [rec.append(lsplit[i]) for i in imp_inds]
        recs.append(rec)
    return [imp_fields, recs]
    
def hcsort(x): return x[1]

def makeCountDict(data):
    counts = {}
    for r in data.values:
        r = str(r[0])
        if r not in counts: counts[r] = 1
        else: counts[r] += 1
    sorted_counts = sorted(counts.items(), key=hcsort, reverse=True)
    return sorted_counts
    
def getCounts(df, dnslookup = False):
    countdic, dest_host_cts, dest_port_cts, src_host_cts, src_port_cts = {}, {},{},{},{}
    resp_h = df.loc[:,['id.resp_h']]
    resp_p = df.loc[:,['id.resp_p']]
    src_h = df.loc[:,['id.orig_h']]
    src_p = df.loc[:,['id.orig_p']]
    collist = {"respHosts": resp_h,"respHosts": resp_p,"srcHosts":src_h,"srcPorts":src_p}
    for k,v in collist.items():
        countdic[k] = makeCountDict(v)
    hosts_sorted = sorted(countdic['srcHosts'], keys=hcsort, reverse=True)
    if dnslookup: 
        dnames = []
        for h in hosts_sorted[:100]: 
            try:
                res = sp.check_output(['nslookup', h[0]])
                dnames.append(re.findall('name = (.*?)\\n', res)[0])
            except: dnames.append('')
        
        data = []        
        for i in range(len(dnames)):
            if dnames[i] != '':
                print dnames[i]
                data.append((hosts_sorted[i][0], dnames[i], hosts_sorted[i][1]))
        #df = pd.DataFrame(data, columns = ['IP Addr.', 'Domain Name', 'Visists'])
        #df2 = df.head(20)
        #df2.to_csv('/Users/babraham/Desktop/dhcp/top_20_em2.csv')
    return data
