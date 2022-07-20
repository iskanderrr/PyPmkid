from pbkdf2 import PBKDF2
import hashlib, binascii, hmac

pmkid=''

def check(ssid,apmac,clmac,pmkid,psw):
        pmk = PBKDF2(psw, ssid, 4096).read(32)
        mm="PMK Name".encode()
        pmkid_ = hmac.new(pmk, mm+binascii.a2b_hex(apmac)+binascii.a2b_hex(clmac), hashlib.sha1).hexdigest()[:32]
        
        if pmkid_==pmkid:
            print('Key found! ['+psw+']')
        else:
            print('failed')
            print(pmkid_,pmkid)

'''
Exemple:
ssid = "Amit 2.4G"      
psw = "kolakola"
clmac = '341cf084d400'
apmac = '6814015a0e9c'
check(ssid,apmac,clmac,'e8eaa7538913d0f20b48b1e4dddd8dfd',psw)

'''
