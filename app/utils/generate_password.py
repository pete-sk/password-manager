from random import randint


def generate_pswrd(length=16, lower=True, upper=True, numbers=True, special=True):
    lowchars = 'qwertyuiopasdfghjklzxcvbnm'
    upchars = 'QWERTYUIOPASDFGHJKLZXCVBNM'
    nums = '1234567890'
    specialchars = '!@#$%^&*()'

    scope = ''
    if lower:
        scope += lowchars
    if upper:
        scope += upchars
    if numbers:
        scope += nums
    if special:
        scope += specialchars

    psw = ''
    if not scope:
        pass
    else:
        for i in range(length):
            psw += scope[randint(0, len(scope)-1)]

    return psw
