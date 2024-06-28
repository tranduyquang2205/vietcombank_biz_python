from vietcombank import VietCombank
import json

vcb = VietCombank('29486480S18', 'Jq789789@', '1047512964')

#OTP is required first login only, then youn can call action without it after login
# login = vcb.doLogin()
# print(login)

# balance = vcb.getlistAccount()
# print(balance)
        
# OTP is required first login only, then youn can call action without it after login
result = vcb.getHistories("2024-06-10", "2024-06-19", '1047512964', 0)
print((result))
# account_number="1047889848"
# amount="50000"
# message="123"
# result = vcb.createTranferInVietCombank(account_number, amount, message)
# print((result))