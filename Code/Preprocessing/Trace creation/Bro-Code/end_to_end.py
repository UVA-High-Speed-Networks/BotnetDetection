# -*- coding: utf-8 -*-
"""
Created on Fri Oct 13 16:51:20 2017

@author: babraham
"""

import time
import os
import re
import http_bro_to_flow as btf
import http_log_parser as htlp
import sys

#Usage: python end_to_end.py pcap_file_name
def main():
    fname = sys.argv[1]
    output_dir = re.sub('\.pcap', '', fname) + '_bro_output'
    pcap_to_bro(fname, output_dir)
    parse_http_log('http.log')
    btf.bro_to_traces('http_output.csv')    
    
def pcap_to_bro(pcap_file, output_dir = None):   
    bro_folder = re.sub('\.pcap', '', pcap_file) + '_bro_output'
    if output_dir is None:
	bro_dir = "./" + bro_folder
    else: bro_dir = output_dir
    if bro_dir not in os.listdir('.'):
	print('making bro directory')
	os.system('mkdir ' + bro_dir)
    else:
	print('bro dir already made - cur dir: ' + str(os.getcwd()))
    print "bro dir: " + str(bro_dir)
    os.chdir('./' + bro_dir)
    os.system('bro -r ../' + pcap_file)

def parse_http_log(log_name):
    fname = log_name
    print "fname: " + str(fname)
    outname = "./" + re.sub('\.log', '.csv', fname)
    outname = re.sub('http', 'http_output', outname)
    print "outname: " + str(outname)
    res = htlp.parse_http(fname)
    out = open(outname, 'w')
    fields, recs = res[0], res[1]
    out.write(fields[0])
    for f in fields[1:]: out.write(',' + f)
    out.write('\n')
    for r in recs:
        out.write(str(r[0]))
        for rf in r[1:]:
            out.write(','+str(rf))
        out.write('\n')
    out.close()

def experiment():
    PCAP_FILE = 'output.pcap'
    INTERFACE = 'em1'
    SUBNET = '199.111.160.0/19'
    DURATION = 5 #duration of capture in seconds
    BRO_DIR = 'bro_output'
    HTTP_FILE = 'http_output.csv'
    #run tcpdump for DURATION seconds
    tcpcmd = 'timeout ' + float(DURATION) + ' tcpdump -i ' + INTERFACE + ' net ' + SUBNET + ' -nn -w ' + PCAP_FILE
    os.system(tcpcmd)
    time.sleep(DURATION)
    #run bro on pcap file
    if BRO_DIR not in os.listdir('.'):
        os.system('mkdir ' + BRO_DIR)
    os.system('cd ' + BRO_DIR)
    os.system('bro -r ' + PCAP_FILE)
    #parse bro log and save as HTTP_FILE
    if HTTP_FILE not in os.listdir('.'):
        os.system('touch ' + HTTP_FILE)   
    os.system('python parse_http_log.py ' + HTTP_FILE)

if __name__ == '__main__':
    main()

