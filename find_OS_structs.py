
sig_OS_CoreAsrConfigType_Tag = [
  [(32, 'IdleTask'),
   '*',
   (0, 'Thread'),
   (20, 'Core'),
   '*'
  ]
]


def find_struct_by_sig(sig,start,stop,step=4):
    R = []
    for cur in range(start,stop,step):
        prob = 0.0
        for c in sig:
            if check_cycle(c,address=cur):
                prob += 1./len(sig)
        if prob>0.2:
            R.append((cur,prob))
    return R

def check_cycle(c,address):
    if len(c)==0:
        return False
    x = address
    for y in c:
        if y=='*':
            try:
                x = getInt(toAddr(x))
                if x<0:
                    x = 1+(0xffffffff+x)
            except:
                x = None
                break
        else:
            x += y[0]
    return x==address


