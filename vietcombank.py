
import hashlib
import requests
import json
import base64
import random
import string
import base64
import json
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import base64

class VietCombank:
    def __init__(self, username, password, account_number):
        self.is_login = False
        self.key_captcha = "CAP-6C2884061D70C08F10D6257F2CA9518C"
        self.file = f"data/{username}.txt"
        self.client_private_key = """-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQChzTDAxdKM8mtvlD5i9gETAGqSrHQnUozBmPaVSPAOCqx1USf4
yBRCkkLYO6mkHQqVQqRVsAZc6fAR2ObyBQ533YP96TEHiBoD/DxM2qBItgcDXXIi
jpe7NOGVTG0AC9h8lxeBs9QHci+7eFlDJb8G/qyrqFoxLmU6I4IzEvSaMwIDAQAB
AoGANpYhIoga1o5ajJQ4z+4qwpxbWAxyS2ngLthKKGcpBbO4JwQwNhBaNXNetdC7
FLDvhxeqlXYDT4llAsBoebIXBPPkiQloD9izdMnVGRiHd0vXYK/6qe4DN+iH22a8
PnEzW9WTRs5nVeknShAWsCBdZhhzxTZvUyce89Y5d/BoP6ECQQDWjJ/Kl5MopYLm
66Vi9d4BYKnp1aHdoJn0nIiztiIOIjUGxUs0pElRZxlqI5d5JCug/FAKUBc5dIgz
lXMCUoZLAkEAwQ+3zppGEsRyqitQfolrkgunqPjyPr300NdbBbHrzI1ZaC1jkF4H
n15r1EMlPGo+wd4M5454o++eZvuRnRPquQJAKcGWu+RCNM/5qR3Fw3vcqGH6z9LP
PQYr0IrCpE9XU27e6SFu4KD00A4DyT+CFIawoxVYMpmh24HNnFSC3LnY/wJBALfS
wH/usuPxuwA+Z9FkBVG02Tnxd6637d/f/eIJS+yjdcrU1OVEMtvS6rbcDBtfSkwL
opvkMwhdAqUpybcXnLkCQDDlsfnim3Xo1UYLfNoLbqv0mh6PVI9KMTeeshSYBRiT
+8el/OyYdXD4kwohbCvxkpMXqMF8tTl7qX22NLBSe7Y=
-----END RSA PRIVATE KEY-----"""
        self.url = {
    "getCaptcha": "https://vcbdigibiz.vietcombank.com.vn/w1/auth-service/v1/captcha/",
    "login": "https://vcbdigibiz.vietcombank.com.vn/w1/auth-service/v1/login",
    "authen-service": "https://vcbdigibiz.vietcombank.com.vn/w1/authen-service/v1/api-",
    "getHistories": "https://vcbdigibiz.vietcombank.com.vn/w1/auth-service/v1/account/history",
    "tranferOut": "https://vcbdigibiz.vietcombank.com.vn/w1/transferout-service/v1/maker/init-247-acc",
    "genOtpOut": "https://vcbdigibiz.vietcombank.com.vn/w1/napas-service/v1/transfer-gen-otp",
    "genOtpIn": "https://vcbdigibiz.vietcombank.com.vn/w1/transfer-service/v1/transfer-gen-otp",
    "confirmTranferOut": "https://vcbdigibiz.vietcombank.com.vn/w1/transferout-service/v1/maker/confirm-247-acc",
    "confirmTranferIn": "https://vcbdigibiz.vietcombank.com.vn/w1/transferin-service/v1/maker/confirm",
    "tranferIn": "https://vcbdigibiz.vietcombank.com.vn/w1/transferin-service/v1/maker/init",
    "getBanks": "https://vcbdigibiz.vietcombank.com.vn/w1/contact-service/v1/bank/list",
    "getAccountDeltail": "https://vcbdigibiz.vietcombank.com.vn/w1/bank-service/v1/get-account-detail",
    "getlistAccount": "https://vcbdigibiz.vietcombank.com.vn/w1/auth-service/v1/account/list",
    "getlistDDAccount": "https://vcbdigibiz.vietcombank.com.vn/w1/bank-service/v1/get-list-ddaccount"
}
        self.lang = 'vi'
        self._timeout = 60
        self.appVersion = ""
        self.DT = "WINDOWS"
        self.OV = "126.0.0.0"
        self.PM = "Edge"
        self.checkAcctPkg = "1"
        self.captcha1st = ""
        self.challenge = ""
        self.defaultPublicKey = "-----BEGIN PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAikqQrIzZJkUvHisjfu5Z\n\
CN+TLy//43CIc5hJE709TIK3HbcC9vuc2+PPEtI6peSUGqOnFoYOwl3i8rRdSaK1\n\
7G2RZN01MIqRIJ/6ac9H4L11dtfQtR7KHqF7KD0fj6vU4kb5+0cwR3RumBvDeMlB\n\
OaYEpKwuEY9EGqy9bcb5EhNGbxxNfbUaogutVwG5C1eKYItzaYd6tao3gq7swNH7\n\
p6UdltrCpxSwFEvc7douE2sKrPDp807ZG2dFslKxxmR4WHDHWfH0OpzrB5KKWQNy\n\
zXxTBXelqrWZECLRypNq7P+1CyfgTSdQ35fdO7M1MniSBT1V33LdhXo73/9qD5e5\n\
VQIDAQAB\n\
-----END PUBLIC KEY-----"
        self.clientPublicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCg+aN5HEhfrHXCI/pLcv2Mg01gNzuAlqNhL8ojO8KwzrnEIEuqmrobjMFFPkrMXUnmY5cWsm0jxaflAtoqTf9dy1+LL5ddqNOvaPsNhSEMmIUsrppvh1ZbUZGGW6OUNeXBEDXhEF8tAjl3KuBiQFLEECUmCDiusnFoZ2w/1iOZJwIDAQAB"
        self.clientPrivateKey = "-----BEGIN RSA PRIVATE KEY-----\n\
MIICXQIBAAKBgQCg+aN5HEhfrHXCI/pLcv2Mg01gNzuAlqNhL8ojO8KwzrnEIEuq\n\
mrobjMFFPkrMXUnmY5cWsm0jxaflAtoqTf9dy1+LL5ddqNOvaPsNhSEMmIUsrppv\n\
h1ZbUZGGW6OUNeXBEDXhEF8tAjl3KuBiQFLEECUmCDiusnFoZ2w/1iOZJwIDAQAB\n\
AoGAEGDV7SCfjHxzjskyUjLk8UL6wGteNnsdLGo8WtFdwbeG1xmiGT2c6eisUWtB\n\
GQH03ugLG1gUGqulpXtgzyUYcj0spHPiUiPDAPY24DleR7lGZHMfsnu20dyu6Llp\n\
Xup07OZdlqDGUm9u2uC0/I8RET0XWCbtOSr4VgdHFpMN+MECQQDbN5JOAIr+px7w\n\
uhBqOnWJbnL+VZjcq39XQ6zJQK01MWkbz0f9IKfMepMiYrldaOwYwVxoeb67uz/4\n\
fau4aCR5AkEAu/xLydU/dyUqTKV7owVDEtjFTTYIwLs7DmRe247207b6nJ3/kZhj\n\
gsm0mNnoAFYZJoNgCONUY/7CBHcvI4wCnwJBAIADmLViTcjd0QykqzdNghvKWu65\n\
D7Y1k/xiscEour0oaIfr6M8hxbt8DPX0jujEf7MJH6yHA+HfPEEhKila74kCQE/9\n\
oIZG3pWlU+V/eSe6QntPkE01k+3m/c82+II2yGL4dpWUSb67eISbreRovOb/u/3+\n\
YywFB9DxA8AAsydOGYMCQQDYDDLAlytyG7EefQtDPRlGbFOOJrNRyQG+2KMEl/ti\n\
Yr4ZPChxNrik1CFLxfkesoReXN8kU/8918D0GLNeVt/C\n\
-----END RSA PRIVATE KEY-----"
        if not os.path.exists(self.file):
            self.username = username
            self.password = password
            self.account_number = account_number
            self.sessionId = ""
            self.mobileId = ""
            self.clientId = ""
            self.cif = ""
            self.res = ""
            self.browserToken = ""
            self.browserId = ""
            self.E = ""
            self.tranId = ""
            self.browserId = hashlib.md5(self.username.encode()).hexdigest()
            self.save_data()
            
        else:
            self.parse_data()
    def save_data(self):
        data = {
            'username': self.username,
            'password': self.password,
            'account_number': self.account_number,
            'sessionId': getattr(self, 'sessionId', ''),
            'mobileId': getattr(self, 'mobileId', ''),
            'clientId': self.clientId,
            'cif': getattr(self, 'cif', ''),
            'E': getattr(self, 'E', ''),
            'res': getattr(self, 'res', ''),
            'tranId': getattr(self, 'tranId', ''),
            'browserToken': getattr(self, 'browserToken', ''),
            'browserId': self.browserId,
        }
        with open(self.file, 'w') as f:
            json.dump(data, f)

    def parse_data(self):
        with open(self.file, 'r') as f:
            data = json.load(f)
        self.username = data.get('username', '')
        self.password = data.get('password', '')
        self.account_number = data.get('account_number', '')
        self.sessionId = data.get('sessionId', '')
        self.mobileId = data.get('mobileId', '')
        self.clientId = data.get('clientId', '')
        self.token = data.get('token', '')
        self.accessToken = data.get('accessToken', '')
        self.authToken = data.get('authToken', '')
        self.cif = data.get('cif', '')
        self.res = data.get('res', '')
        self.tranId = data.get('tranId', '')
        self.browserToken = data.get('browserToken', '')
        self.browserId = data.get('browserId', '')
        self.E = data.get('E', '')
    def createTaskCaptcha(self, base64_img):
        url = "https://acbbiz.pay2world.vip/vcb/predict"

        payload = json.dumps({
        "image_base64": base64_img
        })
        headers = {
        'Content-Type': 'application/json'
        }

        response = requests.request("POST", url, headers=headers, data=payload)
        return response.json()
    def solveCaptcha(self):
        captchaToken = ''.join(random.choices(string.ascii_uppercase + string.digits, k=30))
        url = self.url['getCaptcha'] + captchaToken
        response = requests.get(url)
        base64_captcha_img = base64.b64encode(response.content).decode('utf-8')
        result = self.createTaskCaptcha(base64_captcha_img)
        # captchaText = self.checkProgressCaptcha(json.loads(task)['taskId'])
        if result['prediction']:
            captcha_value = result['prediction']
            return {"status": True, "key": captchaToken, "captcha": captcha_value}
        else:
            return {"status": False, "msg": "Error getTaskResult"}


    def encrypt_data(self, data):
        """
        https://vcbbiz1.pay2world.vip/vietcombank/encrypt_biz
        https://tcbbcp1.pay2world.vip/vietcombank/encrypt
        https://encrypt1.pay2world.vip/api.php?act=encrypt_viettin
        """
        
        url_1 = 'https://vcbbiz1.pay2world.vip/vietcombank/encrypt_biz'
        url_2 = 'https://babygroupvip.com/vietcombank/encrypt_biz'
        url_3 = 'https://vcbbiz2.pay2world.vip/vietcombank/encrypt_biz'
        
        payload = json.dumps(data)
        headers = {
            'Content-Type': 'application/json',
        }
        
        for _url in [url_1, url_2, url_3]:
            try:
                response = requests.request("POST", _url, headers=headers, data=payload, timeout=10)
                if response.status_code in [404, 502]:
                    continue
                return json.loads(response.text)
            except:
                continue
        return {}
    
    def decrypt_data(self, cipher):
        """
        https://vcbbiz1.pay2world.vip/vietcombank/encrypt_biz
        https://tcbbcp1.pay2world.vip/vietcombank/encrypt
        https://encrypt1.pay2world.vip/api.php?act=encrypt_viettin
        """
        
        url_1 = 'https://vcbbiz1.pay2world.vip/vietcombank/decrypt_biz'
        url_2 = 'https://babygroupvip.com/vietcombank/decrypt_biz'
        url_3 = 'https://vcbbiz2.pay2world.vip/vietcombank/decrypt_biz'
        
        payload = json.dumps(cipher)
        headers = {
            'Content-Type': 'application/json',
        }
        
        for _url in [url_1, url_2, url_3]:
            try:
                response = requests.request("POST", _url, headers=headers, data=payload, timeout=10)
                if response.status_code in [404, 502]:
                    continue
                return json.loads(response.text)
            except:
                continue
        return {}
    def curlPost(self, url, data):
        encryptedData = self.encrypt_data(data)
        headers = {
            'Accept': 'application/json',
            'Accept-Language': 'vi',
            'Connection': 'keep-alive',
            'Content-Type': 'application/json',
            'Origin': 'https://vcbdigibiz.vietcombank.com.vn',
            'Referer': 'https://vcbdigibiz.vietcombank.com.vn/login?returnUrl=',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0',
            # 'X-Request-ID': '171694395325454',  # Uncomment if needed
            'sec-ch-ua': '"Microsoft Edge";v="125", "Chromium";v="125", "Not.A/Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"'
        }
        response = requests.post(url, headers=headers, data=json.dumps(encryptedData))
        result = self.decrypt_data(response.json())
        return result

    def checkBrowser(self, type=1):
        param = {
            "DT": self.DT,
            "OV": self.OV,
            "PM": self.PM,
            "E": self.getE() or "",
            "browserId": self.browserId,
            "lang": self.lang,
            "mid": 3008,
            "cif": "",
            "clientId": "",
            "mobileId": "",
            "sessionId": "",
            "browserToken": self.browserToken,
            "user": self.username
        }
        result = self.curlPost(self.url['authen-service'] + "3008", param)
        print(result)
        if "tranId" in result["transaction"]:
            return self.chooseOtpType(result["transaction"]["tranId"], type)
        else:
            return {
                'code': 400,
                'success': True,
                'message': "checkBrowser failed",
                "param": param,
                'data': result or ""
            }

    def chooseOtpType(self, tranID, type=1):
        param = {
            "DT": self.DT,
            "OV": self.OV,
            "PM": self.PM,
            "E": self.getE() or "",
            "browserId": self.browserId,
            "lang": self.lang,
            "mid": 3010,
            "cif": "",
            "clientId": "",
            "mobileId": "",
            "sessionId": "",
            "browserToken": self.browserToken,
            "tranId": tranID,
            "type": type,  # 1 la sms,5 la smart
            "user": self.username
        }
        result = self.curlPost(self.url['authen-service'] + "3010", param)
        if result["code"] == "00":
            self.tranId = tranID
            self.saveData()
            self.challenge = result.get("challenge", "")
            return {
                    'code': 200,
                    'success': True,
                    'message': 'Thành công',
                "result": {
                    "browserToken": self.browserToken,
                    "tranId": result.get("tranId", ""),
                    "challenge": result.get("challenge", "")
                },
                "param": param,
                'data': result or ""
            }
        else:
            return {
                'code': 400,
                'success': False,
                'message': result["des"],
                "param": param,
                'data': result or ""
            }

    def submitOtpLogin(self, otp):
        param = {
            "DT": self.DT,
            "OV": self.OV,
            "PM": self.PM,
            "E": self.getE() or "",
            "browserId": self.browserId,
            "lang": self.lang,
            "mid": 3011,
            "cif": "",
            "clientId": "",
            "mobileId": "",
            "sessionId": "",
            "browserToken": self.browserToken,
            "tranId": self.tranId,
            "otp": otp,
            "challenge": self.challenge,
            "user": self.username
        }
        result = self.curlPost(self.url['authen-service'] + "3011", param)
        if result["data"]["code"] == "00":
            self.sessionId = result["sessionId"]
            self.mobileId = result["userInfo"]["mobileId"]
            self.clientId = result["userInfo"]["clientId"]
            self.cif = result["userInfo"]["cif"]
            session = {"sessionId": self.sessionId, "mobileId": self.mobileId, "clientId": self.clientId, "cif": self.cif}
            self.res = result
            self.saveData()
            
            if result["allowSave"]:
                sv = self.saveBrowser()
                if sv["code"] == "00":
                    self.is_login = True
                    return {
                        'code': 200,
                        'success': True,
                        'message': 'Thành công',
                        'saved_browser': True,
                        "d": sv,
                        'session': session,
                        'data': result or ""
                    }
                else:
                    return {
                        'code': 400,
                        'success': False,
                        'message': sv["des"],
                        "param": param,
                        'data': sv or ""
                    }
            else:
                return {
                        'code': 200,
                        'success': True,
                        'message': 'Thành công',
                        'saved_browser': False,
                        'session': session,
                        'data': result or ""
                    }
        else:
            return {
                'code': 500,
                'success': False,
                'message': result["des"],
                "param": param,
                'data': result or ""
            }

    def saveBrowser(self):
        param = {
            "DT": self.DT,
            "OV": self.OV,
            "PM": self.PM,
            "E": self.getE() or "",
            "browserId": self.browserId,
            "browserName": "Microsoft Edge 125.0.0.0",
            "lang": self.lang,
            "mid": 3009,
            "cif": self.cif,
            "clientId": self.clientId,
            "mobileId": self.mobileId,
            "sessionId": self.sessionId,
            "user": self.username
        }
        result = self.curlPost(self.url['authen-service'] + "3009", param)
        return result

    def doLogin(self):
        solveCaptcha = self.solveCaptcha()
        if not solveCaptcha["status"]:
            return solveCaptcha

        param = {
            "DT": self.DT,
            "OV": self.OV,
            "PM": self.PM,
            "appVersion": self.appVersion,
            "authenType": "PASSWORD",
            "captchaToken": solveCaptcha["key"],
            "captchaValue": solveCaptcha["captcha"],
            "cif": None,
            "lang": self.lang,
            "sessionId": self.sessionId,
            "pin": self.password,
            "user": self.username,
            "source": "IB"
        }
        result = self.curlPost(self.url['login'], param)
        print(result)
        if result['code'] == "00":
            self.sessionId = result['data']['sessionId']
            self.mobileId = result['data']['mobileOtp']
            self.clientId = result['data']['userInfo']['packageAccountNo']
            self.cif = result['data']['userInfo']['cif']
            session = {
                "sessionId": self.sessionId,
                "mobileId": self.mobileId,
                "clientId": self.clientId,
                "cif": self.cif
            }
            self.save_data()
            return {
                'code': 200,
                'success': True,
                'message': "success",
                'session': session,
                'data': result if result else ""
            }
        else:
            return {
                'code': 500,
                'success': False,
                'message': result['message'],
                "param": param,
                'data': result if result else ""
            }

    def saveData(self):
        data = {
            'username': self.username,
            'password': self.password,
            'account_number': self.account_number,
            'sessionId': self.sessionId,
            'mobileId': self.mobileId,
            'clientId': self.clientId,
            'cif': self.cif,
            'E': self.E,
            'res': self.res,
            'tranId': self.tranId,
            'browserToken': self.browserToken,
            'browserId': self.browserId,
        }
        with open(f"data/{self.username}.txt", "w") as file:
            json.dump(data, file)

    def parseData(self):
        with open(f"data/{self.username}.txt", "r") as file:
            data = json.load(file)
            self.username = data["username"]
            self.password = data["password"]
            self.account_number = data.get("account_number", "")
            self.sessionId = data.get("sessionId", "")
            self.mobileId = data.get("mobileId", "")
            self.clientId = data.get("clientId", "")
            self.token = data.get("token", "")
            self.accessToken = data.get("accessToken", "")
            self.authToken = data.get("authToken", "")
            self.cif = data.get("cif", "")
            self.res = data.get("res", "")
            self.tranId = data.get("tranId", "")
            self.browserToken = data.get("browserToken", "")
            self.browserId = data.get("browserId", "")
            self.E = data.get("E", "")

    def getE(self):
        ahash = hashlib.md5(self.username.encode()).hexdigest()
        imei = '-'.join([ahash[i:i+4] for i in range(0, len(ahash), 4)])
        return imei.upper()

    def getCaptcha(self):
        captchaToken = ''.join(random.choices(string.ascii_uppercase + string.digits, k=30))
        url = self.url['getCaptcha'] + captchaToken
        response = requests.get(url)
        result = base64.b64encode(response.content).decode('utf-8')
        return result

    def getlistAccount(self):
        param = {
                "DT": self.DT,
                "OV": self.OV,
                "PM": self.PM,
                "accountType": "ALL",
                "appVersion": self.appVersion,
                "isTrans": "0",
                "cif": self.cif,
                "user": self.username,
                "joinable": "1",
                "lang": self.lang,
                "sessionId": self.sessionId,
                "source": "IB"
            }
        result = self.curlPost(self.url['getlistAccount'], param)
        if 'data' in result and 'listAccount' in result['data']:
            for account in result['data']['listAccount']:
                if self.account_number == account['accountNo']:
                    if int(account['avaiableAmount']) < 0:
                        return {'code':448,'success': False, 'message': 'Blocked account with negative balances!',
                                'data': {
                                    'balance':int(account['avaiableAmount'])
                                }
                                }
                    else:
                        return {'code':200,'success': True, 'message': 'Thành công',
                                'data':{
                                    'account_number':self.account_number,
                                    'balance':int(account['avaiableAmount'])
                        }}
            return {'code':404,'success': False, 'message': 'account_number not found!'} 
        else: 
            return {'code':520 ,'success': False, 'message': 'Unknown Error!'} 

    def getlistDDAccount(self):
        param = {
            "DT": self.DT,
            "OV": self.OV,
            "PM": self.PM,
            "browserId": self.browserId,
            "E": self.getE() or "",
            "mid": 35,
            "cif": self.cif,
            "serviceCode": "0551",
            "user": self.username,
            "mobileId": self.mobileId,
            "clientId": self.clientId,
            "sessionId": self.sessionId
        }
        result = self.curlPost(self.url['getlistDDAccount'], param)
        return result

    def getAccountDeltail(self):
        param = {
            "DT": self.DT,
            "OV": self.OV,
            "PM": self.PM,
            "E": self.getE() or "",
            "browserId": self.browserId,
            "accountNo": self.account_number,
            "accountType": "D",
            "mid": 13,
            "cif": self.cif,
            "user": self.username,
            "mobileId": self.mobileId,
            "clientId": self.clientId,
            "sessionId": self.sessionId
        }
        result = self.curlPost(self.url['getAccountDeltail'], param)
        return result

    def getHistories(self, fromDate="16/06/2023", toDate="16/06/2023", account_number='', page=0,limit = 20):
        if not self.is_login:
                login = self.doLogin()
                if not login['success']:
                    return login
        param = {
            "DT": self.DT,
            "OV": self.OV,
            "PM": self.PM,
            "accountNo": account_number if account_number else self.account_number,
            "accountType": "D",
            "appVersion": self.appVersion,
            "cif": self.cif,
            "fromDate": fromDate,
            "isAlias": "0",
            "lang": self.lang,
            "sessionId": self.sessionId,
            "source": "IB",
            "toDate": toDate,
            "user": self.username,
        }
        result = self.curlPost(self.url['getHistories'], param)
        print(result)
        if result['code'] == '00' and 'data' in result and 'listHistory' in result['data']:
            return {'code':200,'success': True, 'message': 'Thành công',
                            'data':{
                                'transactions':result['data']['listHistory'],
                    }}
        else:
            return  {
                    "success": False,
                    "code": 503,
                    "message": "Service Unavailable!"
                }

    def getBanks(self):
        param = {
            "DT": self.DT,
            "OV": self.OV,
            "PM": self.PM,
            "E": self.getE() or "",
            "browserId": self.browserId,
            "lang": self.lang,
            "fastTransfer": "1",
            "mid": 23,
            "cif": self.cif,
            "user": self.username,
            "mobileId": self.mobileId,
            "clientId": self.clientId,
            "sessionId": self.sessionId
        }
        result = self.curlPost(self.url['getBanks'], param)
        return result

    def createTranferOutVietCombank(self, bankCode, account_number, amount, message):
        param = {
            "DT": self.DT,
            "OV": self.OV,
            "PM": self.PM,
            "E": self.getE() or "",
            "browserId": self.browserId,
            "lang": self.lang,
            "debitAccountNo": self.account_number,
            "creditAccountNo": account_number,
            "creditBankCode": bankCode,
            "amount": amount,
            "feeType": 1,
            "content": message,
            "ccyType": "1",
            "mid": 62,
            "cif": self.cif,
            "user": self.username,
            "mobileId": self.mobileId,
            "clientId": self.clientId,
            "sessionId": self.sessionId
        }
        result = self.curlPost(self.url['tranferOut'], param)
        return result

    def createTranferInVietCombank(self, account_number, amount, message):
        param = {
            "DT": self.DT,
            "OV": self.OV,
            "PM": self.PM,
            "E": "",
            "browserId": self.browserId,
            "lang": self.lang,
            "debitAccountNo": self.account_number,
            "creditAccountNo": account_number,
            "amount": amount,
            "activeTouch": 0,
            "feeType": 1,
            "content": message,
            "ccyType": "",
            "mid": 16,
            "cif": self.cif,
            "user": self.username,
            "mobileId": self.mobileId,
            "clientId": self.clientId,
            "sessionId": self.sessionId
        }
        result = self.curlPost(self.url['tranferIn'], param)
        return result

    def genOtpTranFer(self, tranId, type="OUT", otpType=5):
        if otpType == 1:
            solveCaptcha = self.solveCaptcha()
            if not solveCaptcha["status"]:
                return solveCaptcha
            param = {
                "DT": self.DT,
                "OV": self.OV,
                "PM": self.PM,
                "E": self.getE() or "",
                "lang": self.lang,
                "tranId": tranId,
                "type": otpType,  # 1 là SMS,5 là smart otp
                "captchaToken": solveCaptcha["key"],
                "captchaValue": solveCaptcha["captcha"],
                "browserId": self.browserId,
                "mid": 17,
                "cif": self.cif,
                "user": self.username,
                "mobileId": self.mobileId,
                "clientId": self.clientId,
                "sessionId": self.sessionId
            }
        else:
            param = {
                "DT": self.DT,
                "OV": self.OV,
                "PM": self.PM,
                "E": self.getE() or "",
                "lang": self.lang,
                "tranId": tranId,
                "type": otpType,  # 1 là SMS,5 là smart otp
                "mid": 17,
                "browserId": self.browserId,
                "cif": self.cif,
                "user": self.username,
                "mobileId": self.mobileId,
                "clientId": self.clientId,
                "sessionId": self.sessionId
            }

        if type == "IN":
            result = self.curlPost(self.url['genOtpIn'], param)
        else:
            result = self.curlPost(self.url['genOtpOut'], param)
        return result

    def confirmTranfer(self, tranId, challenge, otp, type="OUT", otpType=5):
        if otpType == 5:
            param = {
                "DT": self.DT,
                "OV": self.OV,
                "PM": self.PM,
                "E": self.getE() or "",
                "lang": self.lang,
                "tranId": tranId,
                "otp": otp,
                "challenge": challenge,
                "mid": 18,
                "cif": self.cif,
                "user": self.username,
                "browserId": self.browserId,
                "mobileId": self.mobileId,
                "clientId": self.clientId,
                "sessionId": self.sessionId
            }
        else:
            param = {
                "DT": self.DT,
                "OV": self.OV,
                "PM": self.PM,
                "E": self.getE() or "",
                "browserId": self.browserId,
                "lang": self.lang,
                "tranId": tranId,
                "otp": otp,
                "challenge": challenge,
                "mid": 18,
                "cif": self.cif,
                "user": self.username,
                "mobileId": self.mobileId,
                "clientId": self.clientId,
                "sessionId": self.sessionId
            }

        if type == "IN":
            result = self.curlPost(self.url['confirmTranferIn'], param)
        else:
            result = self.curlPost(self.url['confirmTranferOut'], param)
        return result