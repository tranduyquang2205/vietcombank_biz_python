from vietcombank import VietCombank
import json

vcb = VietCombank('29621713S06', 'Bsa4415##', '1048014329')

#OTP is required first login only, then youn can call action without it after login
login = vcb.doLogin()
print(login)

# balance = vcb.getlistAccount()
# print(balance)
        
# OTP is required first login only, then youn can call action without it after login
# result = vcb.getHistories("2024-06-10", "2024-06-19", '1047512964', 0)
# print((result))
# account_number="1047889848"
# amount="50000"
# message="123"
# result = vcb.createTranferInVietCombank(account_number, amount, message)
# print((result))