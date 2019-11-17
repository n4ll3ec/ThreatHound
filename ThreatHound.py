#!/usr/bin/env python3
# -*- coding:utf-8 -*-
"""
@author n4ll3ec

"""

import sys
import os
import argparse
import requests
import re
import json
import threading
import traceback
from multiprocessing import Pool, Process
from datetime import datetime
from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
from color import cprint, cprint_cyan, cprint_yellow, cprint_red, FgColor


# MISP相关全局变量
MISP_SERVER = 'https://10.28.94.11:8443'
MISP_API_KEY = 'KwKGjLgfAy3Rva27oEPSA9LfavavWEv6UgmWgvgX'
threat_feeds_db = [
    {'feed_id': 5, 'feed_name': 'emergingthreats compromised ips', 'feed_url': 'http://rules.emergingthreats.net/blockrules/compromised-ips.txt'},
    {'feed_id': 6, 'feed_name': 'appspot malware domain lists', 'feed_url': 'https://panwdbl.appspot.com/lists/mdl.txt'},
    {'feed_id': 7, 'feed_name': 'Tor exit nodes', 'feed_url':  'https://www.dan.me.uk/torlist/?exit'},
    {'feed_id': 8, 'feed_name': 'Tor ALL nodes', 'feed_url': 'https://www.dan.me.uk/torlist/'},
    {'feed_id': 9, 'feed_name': 'cybercrime tracker', 'feed_url': 'http://cybercrime-tracker.net/all.php'},
    {'feed_id': 11, 'feed_name': 'dynamic dns providers', 'feed_url': 'http://dns-bh.sagadc.org/dynamic_dns.txt'},
    {'feed_id': 12, 'feed_name': 'snort ip filter', 'feed_url': 'http://labs.snort.org/feeds/ip-filter.blf '},
    {'feed_id': 17, 'feed_name': 'pop3gropers', 'feed_url': 'https://home.nuug.no/~peter/pop3gropers.txt'},
    {'feed_id': 18, 'feed_name': 'ransomware tracker', 'feed_url': 'https://ransomwaretracker.abuse.ch/feeds/csv/'},
    {'feed_id': 19, 'feed_name': 'Feodo ip blocklist', 'feed_url': 'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt'},
    {'feed_id': 20, 'feed_name': 'hosts-file malwarebytes', 'feed_url': 'https://hosts-file.net/psh.txt'},
    {'feed_id': 21, 'feed_name': 'hosts-file emd', 'feed_url': 'https://hosts-file.net/emd.txt'},
    {'feed_id': 22, 'feed_name': 'OpenPhish', 'feed_url': 'https://openphish.com/feed.txt'},
    {'feed_id': 23, 'feed_name': 'firefol blocklist', 'feed_url': 'https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset'},
    {'feed_id': 24, 'feed_name': 'c2 ip blocklist', 'feed_url': 'http://osint.bambenekconsulting.com/feeds/c2-ipmasterlist-high.txt '},
    {'feed_id': 25, 'feed_name': 'c2 domain blocklist', 'feed_url': 'http://osint.bambenekconsulting.com/feeds/c2-dommasterlist-high.txt '},
    {'feed_id': 26, 'feed_name': 'ci-badguys', 'feed_url': 'http://cinsscore.com/list/ci-badguys.txt '},
    {'feed_id': 27, 'feed_name': 'alienvault otx', 'feed_url': 'http://reputation.alienvault.com/reputation.generic'},
    {'feed_id': 28, 'feed_name': 'blocklist de', 'feed_url': 'https://lists.blocklist.de/lists/all.txt '},
    {'feed_id': 29, 'feed_name': 'VNC RFB', 'feed_url': 'https://dataplane.org/vncrfb.txt'},
    {'feed_id': 30, 'feed_name': 'sshpwauth', 'feed_url': 'https://dataplane.org/sshpwauth.txt'},
    {'feed_id': 31, 'feed_name': 'sipregistration', 'feed_url': 'https://dataplane.org/sipregistration.txt'},
    {'feed_id': 32, 'feed_name': 'sipquery', 'feed_url': 'https://dataplane.org/sipquery.txt'},
    {'feed_id': 33, 'feed_name': 'sipinvitation', 'feed_url': 'https://dataplane.org/sipinvitation.txt '},
    {'feed_id': 34, 'feed_name': 'known malicious DGAs', 'feed_url': 'http://osint.bambenekconsulting.com/feeds/dga-feed-high.csv'},
    {'feed_id': 35, 'feed_name': 'VXvault url list', 'feed_url': 'http://vxvault.net/URL_List.php'},
    {'feed_id': 36, 'feed_name': 'abuse.ch ssl blacklist', 'feed_url': 'https://sslbl.abuse.ch/blacklist/sslipblacklist.csv'},
    {'feed_id': 39, 'feed_name': 'cybercrime tracker', 'feed_url': 'http://cybercrime-tracker.net/ccamgate.php '},
    {'feed_id': 40, 'feed_name': 'hpHosts', 'feed_url': 'https://hosts-file.net/grm.txt'},
    {'feed_id': 41, 'feed_name': 'greensnow blocklist', 'feed_url': 'https://blocklist.greensnow.co/greensnow.txt'},
    {'feed_id': 43, 'feed_name': 'CoinBlockerLists', 'feed_url': 'https://gitlab.com/ZeroDot1/CoinBlockerLists/raw/master/list.txt?inline=false'},
    {'feed_id': 44, 'feed_name': 'CoinBlockerLists Additional list', 'feed_url':
        'https://gitlab.com/ZeroDot1/CoinBlockerLists/raw/master/list_optional.txt?inline=false'},
    {'feed_id': 45, 'feed_name': 'CoinBlockerLists Browser Mining', 'feed_url':
        'https://gitlab.com/ZeroDot1/CoinBlockerLists/raw/master/list_browser.txt?inline=false'},
    {'feed_id': 46, 'feed_name': 'CoinBlockerLists Mining Server', 'feed_url':
        'https://gitlab.com/ZeroDot1/CoinBlockerLists/raw/master/MiningServerIPList.txt?inline=false'},
    {'feed_id': 47, 'feed_name': 'URLHaus Malware URLs', 'feed_url': 'https://10.28.94.11:8443/feeds/previewIndex/47'},
    {'feed_id': 48, 'feed_name': 'CyberCure ip blocklist', 'feed_url': 'http://api.cybercure.ai/feed/get_ips?type=csv '},
    {'feed_id': 49, 'feed_name': 'CyberCure url blocklist', 'feed_url': 'http://api.cybercure.ai/feed/get_url?type=csv '},
    {'feed_id': 51, 'feed_name': 'ip spam list', 'feed_url': 'http://www.ipspamlist.com/public_feeds.csv'},
    {'feed_id': 52, 'feed_name': 'securitygive iplist', 'feed_url': 'https://mirai.security.gives/data/ip_list.txt'},
    {'feed_id': 53, 'feed_name': 'malsilo url list', 'feed_url': 'https://malsilo.gitlab.io/feeds/dumps/url_list.txt'},
    {'feed_id': 54, 'feed_name': 'malsilo iplist', 'feed_url': 'https://malsilo.gitlab.io/feeds/dumps/ip_list.txt'},
    {'feed_id': 55, 'feed_name': 'banarydefense ip banlist', 'feed_url': 'https://www.binarydefense.com/banlist.txt'},
    {'feed_id': 56, 'feed_name': 'DigitalSide Threat-Intel', 'feed_url': 'https://osint.digitalside.it/Threat-Intel/digitalside-misp-feed/'},
    {'feed_id': 57, 'feed_name': 'emerging-Block-IPs', 'feed_url': 'https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt'},
    {'feed_id': 58, 'feed_name': 'fastintercept threatlist', 'feed_url': 'https://threatlists.intercept.sh/threatlist_7d_weekly_sample.csv'},
    {'feed_id': 59, 'feed_name': 'IPsum', 'feed_url': 'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt'},
    {'feed_id': 60, 'feed_name': 'Malc0de DNS Sinkhole', 'feed_url': 'http://malc0de.com/bl/IP_Blacklist.txt'},
    {'feed_id': 61, 'feed_name': 'malwaredomainlist iplist', 'feed_url': 'https://www.malwaredomainlist.com/hostslist/ip.txt'},
    {'feed_id': 62, 'feed_name': 'malwaredomains Malware Domains', 'feed_url': 'http://mirror1.malwaredomains.com/files/immortal_domains.txt'},
    {'feed_id': 63, 'feed_name': 'NoThink SSH blacklists', 'feed_url': 'http://www.nothink.org/blacklist/blacklist_ssh_year.txt'},
    {'feed_id': 64, 'feed_name': 'NoThink SNMP blacklists', 'feed_url': 'http://www.nothink.org/blacklist/blacklist_snmp_year.txt'},
    {'feed_id': 66, 'feed_name': 'RansomwareTracker Domain Blocklist', 'feed_url': 'https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt'},
    {'feed_id': 67, 'feed_name': 'RansomwareTracker URL Blocklist', 'feed_url': 'https://ransomwaretracker.abuse.ch/downloads/RW_URLBL.txt'},
    {'feed_id': 68, 'feed_name': 'RansomwareTracker IP Blocklist', 'feed_url': 'https://ransomwaretracker.abuse.ch/downloads/RW_IPBL.txt'},
    {'feed_id': 69, 'feed_name': 'REScure IP Blacklist', 'feed_url': 'https://rescure.fruxlabs.com/rescure_blacklist.txt'},
    {'feed_id': 70, 'feed_name': 'REScure Domain Blacklist', 'feed_url': 'https://rescure.fruxlabs.com/rescure_domain_blacklist.txt'},
    {'feed_id': 71, 'feed_name': 'Rutgers Blacklisted IPs', 'feed_url': 'https://report.rutgers.edu/DROP/attackers'},
    {'feed_id': 72, 'feed_name': 'Talos IP Blacklist', 'feed_url': 'https://talosintelligence.com/documents/ip-blacklist'},
    {'feed_id': 73, 'feed_name': '1st Dual Threat', 'feed_url': 'https://iocfeed.mrlooquer.com/feed.csv'},
    {'feed_id': 74, 'feed_name': 'BBcan177 DNS Blacklist', 'feed_url': 'https://gist.githubusercontent.com/BBcan177/4a8bf37c131be4803cb2/raw'},
    {'feed_id': 75, 'feed_name': 'BBcan177 Malicious IPs', 'feed_url': 'https://gist.githubusercontent.com/BBcan177/bf29d47ea04391cb3eb0/raw/'},
    {'feed_id': 77, 'feed_name': 'Feodo Suricata C2 IPs', 'feed_url': 'https://feodotracker.abuse.ch/blocklist/?download=ipblocklist'},
    {'feed_id': 78, 'feed_name': 'Darklist', 'feed_url': 'http://www.darklist.de/raw.php'},
    {'feed_id': 79, 'feed_name': 'Dictionary SSH Attacks', 'feed_url':
        'http://charles.the-haleys.org/ssh_dico_attack_hdeny_format.php/hostsdeny.txt'},
    {'feed_id': 80, 'feed_name': 'joewein Domains Blacklist', 'feed_url': 'http://www.joewein.net/dl/bl/dom-bl.txt'},
    {'feed_id': 81, 'feed_name': 'LinuxTracker Hancitor IPs', 'feed_url':
        'https://raw.githubusercontent.com/LinuxTracker/Blocklists/master/HancitorIPs.txt'},
    {'feed_id': 82, 'feed_name': 'Malware Domains List', 'feed_url': 'https://www.malwaredomainlist.com/mdlcsv.php'},
    {'feed_id': 83, 'feed_name': 'Monero Miner', 'feed_url': 'https://raw.githubusercontent.com/Hestat/minerchk/master/hostslist.txt'},
    {'feed_id': 84, 'feed_name': 'NoCoin', 'feed_url': 'https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt'},
    {'feed_id': 85, 'feed_name': 'DShield Suspicious Domains', 'feed_url': 'https://secure.dshield.org/feeds/suspiciousdomains_Low.txt'},
    {'feed_id': 86, 'feed_name': 'Suspicious DynamicDNS Providers', 'feed_url': 'http://dns-bh.sagadc.org/dynamic_dns.txt'},
    {'feed_id': 87, 'feed_name': 'abuse.ch URLhaus List', 'feed_url': 'https://urlhaus.abuse.ch/downloads/text/'},
]
REPUTATION_DB_PATH = 'ReputationDB' 
# 并发性能设置
CPU_CORES = 6
MAX_LINES = 1000000

# OTX全局变量设置
OTX_SERVER = 'https://otx.alienvault.com/'
OTX_API_KEY = 'AlienVault API Key'

# 其他全局设置
cache_mode = True
local_mode = False
online_mode = False
detect_results = []
failed_ips = []


class misp_threat_intelligence():
    def __init__(self, server, api_key, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.server = server 
        self.api_key = api_key
        self.feed_entities = []
        self.feed_name = ''

    def retrieve_feed_name_by_id(self, feed_id):
        self.feed_id = int(feed_id)
        feed_ids = [f['feed_id'] for f in threat_feeds_db]
        feed_names = [f['feed_name'] for f in threat_feeds_db]
        feed_name_dic = dict(zip(feed_ids, feed_names))

        if feed_id in feed_name_dic.keys():
            self.feed_name = feed_name_dic[feed_id]
        
        return self.feed_name

    def fetch_feed_content(self, feed_id):
        self.feed_id = int(feed_id)
        self.retrieve_feed_name_by_id(self.feed_id)

        req_header = dict()
        req_header['ACCEPT'] = 'application/json'
        req_header['Content-Type'] = 'application/json'
        req_header['Authorization'] = MISP_API_KEY

        cprint_cyan("Fetching threat from feed{}-{}".format(self.feed_id, self.feed_name))

        feeds_preview_url = MISP_SERVER + '/feeds/previewIndex/{}/page:'.format(self.feed_id)
        try:
            rep = requests.get(feeds_preview_url, headers=req_header, verify=False)
            self.feed_entities = json.loads(rep.content)
            feed_entity_num = len(self.feed_entities)
            cprint_cyan("feed{}-{}中共获取到{}条数据".format(self.feed_id, self.feed_name, feed_entity_num))
        except Exception as e:
            cprint_red("feed请求失败")
            # cprint_red(e)

        return self.feed_entities


class otx_reputation(object):
    """
    AlienVault OTX威胁情报数据库 
    """
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.otx = OTXv2(OTX_API_KEY, OTX_SERVER)
        self.alerts = []
        self.results = []
        self.entity_num = 0
        self.outfile_dic = {}

    @staticmethod
    def getValue(results, keys):
        if type(keys) is list and len(keys) > 0:

            if type(results) is dict:
                key = keys.pop(0)
                if key in results:
                    return otx_reputation.getValue(results[key], keys)
                else:
                    return None
            else:
                if type(results) is list and len(results) > 0:
                    return otx_reputation.getValue(results[0], keys)
                else:
                    return results
        else:
            return results

    def detect_ip(self, ip):
        try:
            result = self.otx.get_indicator_details_by_section(IndicatorTypes.IPv4, ip, 'general')
            validation = otx_reputation.getValue(result, ['validation'])

            if not validation:
                pulses = otx_reputation.getValue(result, ['pulse_info', 'pulses'])
                if pulses:
                    for pulse in pulses:
                        if 'name' in pulse:
                            self.alerts.append('In pulse: ' + pulse['name'])
        except Exception as e:
            print("{}为保留IP".format(ip))

    def detect_domain(self, domain):
        result = self.otx.get_indicator_details_by_section(IndicatorTypes.HOSTNAME, domain, 'general')

        validation = otx_reputation.getValue(result, ['validation'])
        if not validation:
            pulses = otx_reputation.getValue(result, ['pulse_info', 'pulses'])
            if pulses:
                for pulse in pulses:
                    if 'name' in pulse:
                        self.alerts.append('In pulse: ' + pulse['name'])

        result = self.otx.get_indicator_details_by_section(
            IndicatorTypes.DOMAIN, domain, 'general')

        validation = otx_reputation.getValue(result, ['validation'])
        if not validation:
            pulses = otx_reputation.getValue(result, ['pulse_info', 'pulses'])
            if pulses:
                for pulse in pulses:
                    if 'name' in pulse:
                        self.alerts.append('In pulse: ' + pulse['name'])

    def check_alerts(self, target):
        if len(self.alerts) > 0:
            cprint_red('{} 被识别为潜在恶意IP'.format(target))
            # cprint_red(str(self.alerts))
        else:
            cprint_cyan('{} 未知或非恶意IP'.format(target))

        # 将IP威胁事件格式化为字典形式
        entity_dic = {}
        # alerts_dic = {}
        alerts_lst = []

        idx = 1
        for item in self.alerts:
            key = 'pulse' + str(idx)
            value = item.split(':')[1].strip()
            # alerts_dic[key] = value
            alerts_lst.append(value)
            idx += 1
        #
        entity_dic['ip'] = target 
        entity_dic['alerts'] = alerts_lst
        entity_dic['alerts_total'] = len(alerts_lst)
        entity_dic['sequence'] = self.entity_num

        self.results.append(entity_dic)
        json_str = json.dumps(entity_dic, sort_keys=False, indent=4)
        print(json_str)
        print()

    def save_result(self, content, outfile='otx_malicious_ip.json'):
        try:
            with open(outfile, 'a') as f:
                json.dump(content, f )
                f.writelines('\n')
        except Exception as e:
            print(e)
            print("保存至文件失败")
        return f 

def print_banner():
    logo = r""" 
         _____ _                    _   _   _                       _
        |_   _| |__  _ __ ___  __ _| |_| | | | ___  _   _ _ __   __| |
          | | | '_ \| '__/ _ \/ _` | __| |_| |/ _ \| | | | '_ \ / _` |
          | | | | | | | |  __/ (_| | |_|  _  | (_) | |_| | | | | (_| |
          |_| |_| |_|_|  \___|\__,_|\__|_| |_|\___/ \__,_|_| |_|\__,_|
        """
    cprint_red(logo)
    cprint()


def arg_parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('ipfile', nargs='?', help="IP列表文件，每行一个IP")
    mode_exclu_args_group = parser.add_mutually_exclusive_group()
    mode_exclu_args_group.add_argument('--fetch', dest='feed_id', nargs='*', default="all", help="获取id为n的feed数据，格式:n, n m或all")
    mode_exclu_args_group.add_argument('--local', action='store_true', help='使用本地缓存feed数据进行查询',)
    mode_exclu_args_group.add_argument('--online', action='store_true', default=False, help="在线联网查询")
    target_exclu_args_group = parser.add_mutually_exclusive_group()
    target_exclu_args_group.add_argument('--ip', help="对单个IP进行查询")
    target_exclu_args_group.add_argument('--domain', help="对单个域名进行查询")
    parser.add_argument('--type', dest='query_type', metavar='query_type', choices=['ip', 'domain'], help="在线联网查询的类型，选项:ip,domain")
    parser.add_argument('--list', action='store_true', help="显示已添加feed列表信息")
    parser.add_argument('--output', help="查询结果保存至外部文件")
    parser.add_argument('--db', help='包含IP信誉数据库文件的目录', default="ReputationDB")

    args = vars(parser.parse_args())
    return args


def download_feeds(feed_id):
    # 新建misp查询实例
    misp_instance = misp_threat_intelligence(MISP_SERVER, MISP_API_KEY)

    # 下载并缓存IP威胁情报数据，首先从内部MISP平台下载IP威胁情报
    feed_name = misp_instance.retrieve_feed_name_by_id(feed_id) 
    feed_content = misp_instance.fetch_feed_content(feed_id)
    feed_filename = feed_name.replace(' ', '_') + '.data'
    outFile = '{}{}{}'.format(REPUTATION_DB_PATH, os.sep, feed_filename)
    # 保存feed数据至缓存数据文件
    save_file(feed_content, outFile)


def query_type_parse(items):
    if not type(items) == list:
        items = [items]

    item_list = []
    ip_pattern_str = r"((\d{1,3}\.){3}\d{1,3})"
    domain_pattern_str = r"(https?://)?(www\.)?(.*)"
    ip_pattern = re.compile(ip_pattern_str)
    domain_pattern = re.compile(domain_pattern_str)

    for item in items:
        item = item.strip()
        m = re.search(ip_pattern, item)
        if m is not None:
            item_list.append(m.group(1))
        else:
            m = re.search(domain_pattern, item)
            if m is not None:
                item_list.append(m.group(3))
            else:
                failed_ips.append(item)

    return item_list


def parse_input_file(inputfile):
    item_list = []
    
    try:
        with open(inputfile, "r") as fd:
            content_lines = fd.readlines()
    except:
        cprint_red("文件{}打开失败".format(inputfile))
        sys.exit(1)

    # 读取ip列表文件，集合去重后生成ip列表
    content_lines = list(set(content_lines))
    content_length = len(content_lines)
    cprint_cyan("[*] Input file contains [{}] items".format(content_length))

    # 将文件分块处理
    chunk_size = MAX_LINES
    # ip记录数小于能处理的最大记录数
    if content_length < MAX_LINES:
        # ip记录数小于cpu核心，则并发为1，否则将记录数平均分配至每个cpu核心
        if content_length/CPU_CORES < 1:
            chunk_size = 1
        else:
            chunk_size = content_length // CPU_CORES 
    tmp = []
    for index in range(0, content_length, chunk_size):
        # 将记录分成固定长度的小块，最后一块包含剩余的所有记录
        if index + chunk_size > content_length:
            tmp.append(content_lines[index:])
        else:
            tmp.append(content_lines[index:index+chunk_size])
            index += chunk_size 
    content_lines = tmp

    pool = Pool(CPU_CORES)
    rest = pool.map(query_type_parse, content_lines)
    for i in rest:
        item_list.extend(i)

    return item_list


def check_match(item, db):
    # 如果结果字典中不包含malicious条目，则初始化
    if item in db:
        cprint_red("Malicious item detected: {}".format(item))
        if item != "":
            detect_results.append(item)

def search_from_feeds(target_list):
    feed_lists = os.listdir(REPUTATION_DB_PATH)

    feed_threat_values = []
    cprint_cyan("Searching malicious ip from thread feeds ...")

    # 遍历所有feed数据，将威胁数据添加至列表
    for feed_file in feed_lists:
        if not os.path.isdir(feed_file):
            try:
                with open(REPUTATION_DB_PATH + os.sep + feed_file) as f:
                    feed_content = f.readlines()
            except Exception as e:
                cprint_red("Open feed data failed")

        for line in feed_content:
            feed_entity = json.loads(line)
            try:
                feed_threat_values.append(feed_entity['value'])
            except KeyError as e:
                pass
            except TypeError as e:
                # cprint_red(e)
                continue

    feed_threat_total = len(feed_threat_values)
    cprint_cyan('total {} data in all feeds'.format(feed_threat_total))

    for item in target_list:
        item = item.strip()
        check_match(item, feed_threat_values)
    

def print_flaged_item():
    item_total = len(detect_results)
    
    cprint_red('###### Malicious objects ######')
    for item in detect_results:
        cprint_red('{}'.format(item))
    print()
    cprint_red("Total: {}".format(item_total))

    if len(failed_ips) > 0:
        print("###### FAILED TO PROCESS ######")
        for ip in failed_ips:
            cprint_yellow('%s' % ip)


def save_file(content, outfile='malicious_items.txt'):
    try:
        with open(outfile, 'w') as f:
            for line in content:
                f.writelines(json.dumps(line))
                f.writelines("\n")
    except Exception as e:
        cprint_red(e)


def timer(func):
    def wrapper():
        start_time = datetime.now()
        func()
        end_time = datetime.now() - start_time
        cprint_cyan("Total execution time (%d.%d)" % (end_time.seconds, end_time.microseconds))

    return wrapper


@timer
def main():
    try:
        print_banner()

        args = arg_parse()
        if args['list']:
            for f in threat_feeds_db:
                cprint_cyan("{}. {} - {}\n".format(f['feed_id'], f['feed_name'], f['feed_url']))
            sys.exit(1)
        if args['feed_id']:
            cache_mode = True

        if args['ip']:
            target_ip = args['ip']
        elif args['domain']:
            target_domain = args['domain']
        elif args['ipfile']: 
            inputFile = args['ipfile']

        if args['output']:
            save_file_flag = True
            output_file = args['output']

        if args['local']:
            local_mode = True
            online_mode = False
            cache_mode = False
        elif args['online']:
            online_mode = True         
            local_mode = False
            cache_mode = False
        else:
            cache_mode = True
            local_mode = False
            online_mode = False

        if args['db']:
            REPUTATION_DB_PATH = args['db']
            if not os.path.isdir(REPUTATION_DB_PATH):
                os.mkdir(REPUTATION_DB_PATH)

        # cache模式,先下载feed情报数据
        if cache_mode:
            #  
            if 'all' in args['feed_id']:
                feed_ids = [ f['feed_id'] for f in threat_feeds_db ]

                for f_id in feed_ids:
                    download_handler = threading.Thread(name='download_feeds', target=download_feeds, args=[f_id])
                    download_handler.setDaemon(True)
                    download_handler.start()
                    download_handler.join()
            else:
                if len(args['feed_id']) == 1:
                    start_id = int(args['feed_id'][0])
                    stop_id = start_id + 1
                elif len(args['feed_id']) == 2:
                    start_id = int(args['feed_id'][0])
                    stop_id = int(args['feed_id'][1]) + 1 
                else:
                    cprint_red('Invaild feed id!')
                    sys.exit(1)

                for f_id in range(start_id, stop_id, 1):
                    download_handler = threading.Thread(name='download', target=download_feeds, args=[f_id])
                    download_handler.setDaemon(True)
                    download_handler.start()
                    download_handler.join()
            
            # 如果缓存数据，但未指定ip或ipfile，则缓存完后退出
            if not ('target_ip' in locals() and 'target_domain' in locals() and 'inputFile' in locals()):
                sys.exit(0)

        # 离线查询模式直接进行情报搜索
        if local_mode:
            try:
                if 'target_ip' in locals():
                    target_list = [target_ip]
                elif 'target_domain' in locals():
                    target_list = [target_domain]
                else:
                    target_list = parse_input_file(inputFile)
                
                # 针对目标进行低信誉ip检索
                search_from_feeds(target_list)
                # detecting_threat_from_feeds(target_list)
                print_flaged_item()
                if 'save_file_flag' in locals():
                    save_file(detect_results, output_file)
            except:
                cprint_red("Error")
                traceback.print_exc()

        # AlienVault OTX进行在线查询
        if online_mode:
            query_type = args['query_type']

            otx = otx_reputation()
            if 'target_ip' in locals():
                otx.detect_ip(target_ip)
                otx.check_alerts(target_ip)
                content = otx.results.pop()
                otx.entity_num += 1

                if 'save_file_flag' in locals():
                    otx.save_result(content, outfile=output_file)

            if 'target_domain' in locals():
                otx.detect_domain(target_domain)
                otx.check_alerts(target_domain)
                content = otx.results.pop()
                otx.entity_num += 1

                if 'save_file_flag' in locals():
                    otx.save_result(content, outfile=output_file)

            if 'inputFile' in locals():
                target_list = parse_input_file(inputFile)
                if query_type is None:
                    cprint_red("Please specify --type options when using online query mode!")
                    sys.exit(1)
                if query_type.upper() == 'IP':
                    for ip in target_list:
                        ip = ip.strip()
                        otx.detect_ip(ip)
                        otx.check_alerts(ip)
                        content = otx.results.pop()
                        if 'save_file_flag' in locals():
                            otx.save_result(content, outfile=output_file)
                        # ip处理结束即重置ip的情报计数
                        otx.alerts = [] 
                        otx.entity_num += 1
                elif query_type.upper() == 'DOMAIN':
                    for domain in target_list:
                        domain = domain.strip()
                        otx.detect_domain(domain)
                        otx.check_alerts(domain)
                        content = otx.results.pop()
                        if 'save_file_flag' in locals():
                            otx.save_result(content, outfile=output_file)
                        # ip处理结束即重置ip情报数
                        otx.alerts = [] 
                        otx.entity_num += 1
    except:
        pass
        # traceback.print_exc()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt as e:
        cprint_red("Exit ...")
