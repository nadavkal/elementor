from datetime import datetime
import requests
from urllib.parse import urlencode
import pandas as pd
from collections import Counter
from time import sleep
from random import randint
import os


class Reputation(object):
    def __init__(self,stale_threshold=15):
        self.in_mem = {}
        self.stale_threshold = stale_threshold
        self.conn = 'db connection'

    @staticmethod
    def __get_site(url):
        base_url = f"https://www.virustotal.com/ui/search?limit=20&relationships%5Bcomment%5D=author%2Citem&query={url.encode('utf-8')}"
        headers = {"accept": "application/json",
        "accept-encoding": "gzip, deflate, br",
        "accept-ianguage": "en-US,en;q=0.9,es;q=0.8",
        "accept-language": "en-US,en;q=0.9,he-IL;q=0.8,he;q=0.7",
        "content-type": "application/json",
        "referer": "https://www.virustotal.com/",
        "sec-ch-ua": '"Google Chrome";v="87", " Not;A Brand";v="99", "Chromium";v="87"',
        "sec-ch-ua-mobile": "?0",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36",
        "x-app-version": "20201216t121016",
        "x-tool": "vt-ui-main",
        "x-vt-anti-abuse-header": "MTg2NDMzMDI3MjYtWkc5dWRDQmlaU0JsZG1scy0xNjA4NjIxOTU5Ljk1OA="}
        r = requests.get(base_url,headers=headers)
        if r.status_code != 200 or not r.json().get('data'):
            base_url = f"https://www.virustotal.com/gui/domain/{url}/detection"
            r = requests.get(base_url,headers=headers)
        return r

    @staticmethod
    def __extract_json(response):
        return response.json()

    @staticmethod
    def __extract_url_status(j):
        j = j.get('data',[{}])
        if not j:
            return {'error':'no data'}
        # getting categories
        categories = j[0].get('attributes',{}).get('categories',{})

        # get status data
        j = j[0].get('attributes',{}).get("last_analysis_results",{})
        j = Counter([x.get('result','n/a') for x in j.values()]).items(),key=lambda kv: kv[1],reverse=True)

        if j.get('malicious',0) >=1 or j.get('malware',0) >=1 or j.get('phishing',0) >=1:
            j.update({'status':'risk'})
        else:
            j.update{'status':'safe'}
        # adding categories to response
        j.update(categories)
        return j

    @staticmethod
    def __update_db(record):
        # un-implemented
        pass

    @staticmethod
    def __query_db(url):
        # un-implemented
        pass

    def query_url(self,url):

        #if in memory and has recently been updated
        if url in self.in_mem.keys() and (datetime.now() - self.in_mem.get(url).get('last_updated')).seconds < self.stale_threshold*60:
            return self.in_mem.get(url)

        #else query db
        #db_res = self.__query_db:
        #if db_res:
        #    return db_res

        #if not in db, go scrape
        response = self.__get_site(url)
        if response.status_code != 200:
            return {'error': response.status_code}
        j = self.__extract_json(response)
        j = self.__extract_url_status(j)
        j.update({'last_updated':datetime.now()})
        self.in_mem[url] = j
        #self.__update_db
        return {'url':url,'status':j}



if __name__ == "__main__":
    o = Reputation()
    #df = pd.read_csv('https://elementor-pub.s3.eu-central-1.amazonaws.com/Data-Enginner/Challenge1/request1.csv',header=None,names=['url'])
    for filename in os.listdir('/usr/sites')
    
        df = pd.read_csv('/usr/sites'+filename,header=None,names=['url'])
        df['status'] = df.url.apply(o.query_url)
        print(filename)
        print(df)