from Crypto.Util.number import *
from gmpy2 import *
import hashlib
import hmac
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from random import *

def gen_proof(n,tags,c,k1,k2,gs):
    f=open("1315245.1315318.pdf",'rb')
    F=f.read()
    f.close()
    b_size=64   # 64B

    listF=list(F)
    X=[]
    for i in range(len(F)//100):
        x=randint(0,len(F)-1)
        while listF[x]==0:
            x=randint(0,len(F)-1)
        X.append(x)
        listF[x]=0
    F=b''
    for i in listF:
        F+=long_to_bytes(i)

    block_count=len(F)//b_size + (0 if len(F)%b_size==0 else 1)


    T=1
    temp=0
    for j in range(c):
        my_aes=AES.new(long_to_bytes(k1),mode=AES.MODE_ECB)
        i=my_aes.encrypt(pad(long_to_bytes(j),AES.block_size))
        i=bytes_to_long(i)%block_count

        my_sha256=hashlib.sha256
        my_hmac=hmac.new(long_to_bytes(k2),digestmod=my_sha256)
        my_hmac.update(long_to_bytes(j))
        a=int(my_hmac.hexdigest(),16)%n

        T=(T*(pow(tags[i],a,n)))%n

        block=bytes_to_long(F[i*b_size:(i+1)*b_size])%n

        temp=temp+block*a
    temp=pow(gs,temp,n)
    my_sha1=hashlib.sha1()
    my_sha1.update(str(temp).encode())
    rho=int(my_sha1.hexdigest(),16)
    return (T,rho)
n=348781342099805754146918328486407903782097571262727692501977554882377209510364325877768453896353289883904117323992264662663684806533385732760632797811025676492049864272852191746956413874982695730726777152957138760706517839193932215546119232501461555013832694916652996046474181803655935297057526232950719616361


tags=[]
with open("tags.txt","r") as file:
    fl=file.readline()
    while fl:
        tags.append(int(fl))
        fl=file.readline()

with open("chal.txt",'r') as file:
    c=int(file.readline())
    k1=int(file.readline())
    k2=int(file.readline())
    s=int(file.readline())
    gs=int(file.readline())

T,rho=gen_proof(n,tags,c,k1,k2,gs)
print(T)
print(rho)
"""with open("ch_proof.txt",'w') as file:
    file.write(str(T)+'\n')
    file.write(str(rho)+'\n')"""