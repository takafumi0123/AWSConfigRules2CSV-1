import re
import sys
import requests
import csv
import os
import json
import yaml
from pathlib import Path
from bs4 import BeautifulSoup

# AWS Document(https://docs.aws.amazon.com/config/latest/developerguide/) サイトからAWS Configのマネージドルールのリストを取得するツールです。
# 各マネージドルールが所属するConformance Pack/Security Standard情報もリストします。
#
# 使い方
# インターネットに接続できる環境で実行して下さい。
# 実行すると、カレントディレクトリにCSVファイル(UTF-8)を出力します。
# 
# 制限事項
# Documentが一定のルールで作成されていない場合、取得漏れが発生することがあります。
# 英語サイトを前提に作成しています。
#
lang ="" # English
#lang = "/ja_jp" # Japanese
id_key="Identifier:"
trigger_key="Trigger type:"
region_key="AWS Region:"
aws_doc_config_base_url = "https://docs.aws.amazon.com" + lang + "/config/latest/developerguide/"
aws_doc_config_managed_rules_uri = "https://docs.aws.amazon.com" + lang + "/config/latest/developerguide/managed-rules-by-aws-config.html"
aws_doc_comformancepack_template_url="https://docs.aws.amazon.com/config/latest/developerguide/conformancepack-sample-templates.html"

# get conformance pack yaml code from aws document
def get_comformance_pack_list():

    # retrieve links from comformance pack website.
    comformancePack_link_page = requests.get(aws_doc_comformancepack_template_url)
    comformancePack_link_page.encoding = 'utf-8'

    soup = BeautifulSoup(comformancePack_link_page.text, 'lxml')

    # get config rules pages's from <a> tag
    conformancePack_link_list = soup.find(id="main-col-body").find_all("a")
    pack_list = {}
    # make  a list of config rules for each comformance pack
    for conformancePack_link in conformancePack_link_list:

        conformancePack_uri = aws_doc_config_base_url + conformancePack_link.get('href')
        conformancePack_detail = requests.get(conformancePack_uri)
        conformancePack_detail.encoding = 'utf-8'
        soup2 = BeautifulSoup(conformancePack_detail.text, 'lxml')

        # ExampleとCustomルールは調査から除外する。
        if ('Example' in soup2.h1.text) or ('Custom' in soup2.h1.text):
            continue

        print('---- creating conformance packlist ----- ' + conformancePack_uri)
        
        # retrieve a link of github that has cloudformation templete.
        element=soup2.find(text=re.compile("The template is available on GitHub"))
        if element:
            githubURL=element.parent.a.get("href")
            #for document bug
            githubURL=fixGithubURL(githubURL)
            comformance_github=requests.get(githubURL)
            uri = BeautifulSoup(comformance_github.text, 'lxml').find(id="raw-url").get("href")
         
            yamlURL="https://github.com"+uri
            yaml_data=requests.get(yamlURL)
            yaml_data.encoding = 'utf-8'
            soup4 = BeautifulSoup(yaml_data.text, 'lxml')
            pack_name = del_spaces(element.parent.a.text)
            # Create Rule List
            r=analyzeComformancePackYAML(yaml_data.text)

            pack_list[pack_name] = r
    print('Conformance Pack list created')
    return(pack_list)
def fixGithubURL(url):
    url=url.replace("Operational-Best-Practices-for-CIS-AWS-FB-v1.4-Level1.yaml","Operational-Best-Practices-for-CIS-AWS-v1.4-Level1.yaml")
    url=url.replace("Operational-Best-Practices-for-CIS-AWS-FB-v1.4-Level2.yaml","Operational-Best-Practices-for-CIS-AWS-v1.4-Level2.yaml")
    return url
    
# retrieve AWS Config Idetifier from YAML( Cloudformation template) in Github    
def analyzeComformancePackYAML(text):
    r = []
    d = yaml.safe_load(text)
    for rule in d.get('Resources'):
        try:
            r_name = d.get('Resources').get(rule).get(
                'Properties').get('Source').get('SourceIdentifier')
            r.append(r_name)
        except:
            print('ERROR')
            
    return r

def del_spaces(s):
    # delete indent, tab, sequential spaces
    return(s.replace('\n' , ' ').replace('\t' , ' ').replace('  ' , '').strip())

# For CIS Standard  
def get_securityhub_cis_list():
    url = "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html"
    return security_standard_parser(url)
# For PCIDSS Standard  
def get_securityhub_pci_list():
    url = "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-pci-controls.html"
    return security_standard_parser(url)
# For AWS Best Practice Standard  
def get_securityhub_abp_list():
    url = "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-fsbp-controls.html"
    return security_standard_parser(url)
    
# 
def security_standard_parser(b_uri):
    page = requests.get(b_uri)
    page.encoding = 'utf-8'
    soup = BeautifulSoup(page.text, 'lxml')
    # get config rules pages
    rulesList = soup.find(id="main-content").find_all("h2")
    rule_IDs={}
    for rule in rulesList:
        ruleName = del_spaces(rule.text)
        ##Severity/Config RuleId Search
        id=None
        for i in range(12):
            if "AWS Config rule:" in rule.next_sibling.next_sibling.text:
                id=rule.next_sibling.next_sibling.text.split(":")[1]
                id=del_spaces(id)   
                break
            rule=rule.next_sibling.next_sibling
        if id is None or id =="None" or id.startswith("None."):
            rule_IDs[ruleName]="None"
        else:
            rule_IDs[ruleName]=id
    return rule_IDs


def dumpCSV(file_name,header,data):
    with open(file_name, 'w') as f:
        writer = csv.DictWriter(f, header)
        writer.writeheader()
        writer.writerows(data)
        print('CSV file is created!  ' + file_name)

def dumpCSVbyArray(file_name,header,list_data):
    data=[]
    for key in list_data:
        data.append({"Standard Rule Name":key,"RuleID":list_data.get(key)})
    dumpCSV(file_name,header,data)
#
# main
#
package_list={}
standard_list={}
#package_list = get_comformance_pack_list()
temp_header={"RuleID","Standard Rule Name"}
temp_list=get_securityhub_cis_list()
dumpCSVbyArray("cis.csv",temp_header,temp_list)
standard_list["security_hub_cis"]= temp_list.values()


temp_list= get_securityhub_pci_list()
dumpCSVbyArray("pci.csv",temp_header,temp_list)
standard_list["security_hub_pci"]=temp_list.values()

temp_list=get_securityhub_abp_list()
dumpCSVbyArray("abp.csv",temp_header,temp_list)
standard_list["security_hub_abp"]= temp_list.values()

# create csv header
csv_header_list = ["rule_name", "description", "identifier","trigger","region"]
package_names = []
standard_names=[]
if len(package_list) > 0:
    package_names = list(package_list.keys())
    csv_header_list.extend(package_names)
if len(standard_list) > 0:
    standard_names = list(standard_list.keys())
    csv_header_list.extend(standard_names)

# create config rule list 
r = requests.get(aws_doc_config_managed_rules_uri)
r.encoding = 'utf-8'

soup = BeautifulSoup(r.text, 'lxml')
rules = []

# get config rules pages
link_list = soup.find(id="main-col-body").find_all("a")

# create config rule list
for page in link_list:
    c_uri = aws_doc_config_base_url + page.get('href')
    r2 = requests.get(c_uri)
    r2.encoding = 'utf-8'
    soup2 = BeautifulSoup(r2.text, 'lxml')
    description = soup2.find(id="main-col-body").p.text.strip()

    # delete indent, tab, sequential spaces
    description = del_spaces(description)
    rune_name=soup2.h1.text

    # 識別子をmain-col-bodyの２つ目の<p>から切り出す→要修正ポイント１
    print('---- creating rule list ---- ' + soup2.h1.text)
    identifier=None
    trigger=None
    region=None
    targetPList=soup2.find(id="main-col-body").find_all("p")
    for ptag_item in targetPList:
        
        if identifier == None and id_key in ptag_item.text.strip():
            identifier =  ptag_item.text.strip().replace(id_key,"")
            # delete indent, tab, sequential spaces
            identifier = del_spaces(identifier)
            # delete single space
            identifier = identifier.replace(' ', '')
#            identifier = identifier.replace('CLOUD_TRAIL', 'CLOUDTRAIL')
        if trigger == None and  trigger_key in ptag_item.text.strip():
            trigger =  ptag_item.text.strip().replace(trigger_key,"")
            # delete indent, tab, sequential spaces
            trigger = del_spaces(trigger)
            # delete single space
            trigger = trigger.replace(' ', '')
        if region == None and region_key in ptag_item.text.strip():
            region =  ptag_item.text.strip().replace(region_key,"")

            # delete indent, tab, sequential spaces
            region = del_spaces(region)

            # delete single space
            region = region.replace(' ', '')
            # 識別子が取得できたらブレークして結果を出力
            break

    # ルール情報をリストに出力する。
    this_rule = {'rule_name': soup2.h1.text, 'description': description, 'identifier': identifier,'region': region,'trigger': trigger}

    # 各Config Rulesの識別子が各パッケージ(or Standard)で利用されているRule群に含まれているかどうかをリストに追加する。
    for package_name in package_names:
        if identifier in package_list.get(package_name):
            this_rule[package_name] = 'YES'
        else:
            this_rule[package_name] = '-'
            
    for package_name in standard_names:
        if rune_name in standard_list.get(package_name):
            this_rule[package_name] = 'YES'
        else:
            this_rule[package_name] = '-'
            
    # 作成したリストを追加
    rules.append(this_rule)

# output csv 2 current disk
dumpCSV("aws_config_managed_rules.csv",csv_header_list,rules)
print("The number of AWS Config Rules is "+str(len(rules)))