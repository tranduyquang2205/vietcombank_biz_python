from vietcombank import VietCombank
import json

vcb = VietCombank('08864387951', 'Dqxkv2205.,', '0621000456871')

#OTP is required first login only, then youn can call action without it after login
login = vcb.doLogin()
print(login)

balance = vcb.getlistAccount()
print(balance)
        
# OTP is required first login only, then youn can call action without it after login
result = vcb.getHistories("15/01/2024", "15/01/2024", '0621000456871', 0)
print((result))
# account_number="0621000456871"
# amount="50000"
# message="123"
# result = vcb.createTranferInVietCombank(account_number, amount, message)
# print((result))