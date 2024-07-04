from Crypto.Util.number import *
from gmpy2 import *
import hashlib
import hmac
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from random import *
import os

def KeyGen():
    while True:
        pp=getPrime(512)
        p=2*pp+1
        while not isPrime(p):
            pp=getPrime(512)
            p=2*pp+1

        qq=getPrime(512)
        q=2*qq+1
        while not isPrime(q):
            qq=getPrime(512)
            q=2*qq+1
        
        if pp!=qq:
            break
    n=p*q
    phi=(p-1)*(q-1)

    e=getPrime(1024)
    d=invert(e,phi)

    v=getRandomNBitInteger(128)

    g=e**2%n

    return (n,g,e,d,v)

def TagBlock(n,g,d,v):
    f=open("1315245.1315318.pdf",'rb')
    F=f.read()
    f.close()
    b_size=64   # 64B

    block_count=len(F)//b_size + (0 if len(F)%b_size==0 else 1)

    W=[]
    tags=[]
    for i in range(block_count):
        Wi=str(v)+str(i)
        W.append(Wi)

        block=bytes_to_long(F[i*b_size:(i+1)*b_size])

        my_md5=hashlib.md5()
        my_md5.update(Wi.encode())
        tags.append(pow((int(my_md5.hexdigest(),16)*pow(g,block,n))%n,d,n))
    return (W,tags)

def GenProof(n,g):
    c=randint(400,500)
    k1=getRandomNBitInteger(256)
    k2=getRandomNBitInteger(160)
    s=getRandomNBitInteger(16)
    return (c,k1,k2,s,pow(g,s,n))


def CheckProff(n,e,W,c,k1,k2,s,T,rho):
    tau=pow(T,e,n)
    block_count=len(W)
    for j in range(c):
        my_aes=AES.new(long_to_bytes(k1),mode=AES.MODE_ECB)
        i=my_aes.encrypt(pad(long_to_bytes(j),AES.block_size))
        i=bytes_to_long(i)%block_count

        my_sha256=hashlib.sha256
        my_hmac=hmac.new(long_to_bytes(k2),digestmod=my_sha256)
        my_hmac.update(long_to_bytes(j))
        a=int(my_hmac.hexdigest(),16)%n

        Wi=str(W[i])
        my_md5=hashlib.md5()
        my_md5.update(Wi.encode())
        hw=pow(int(my_md5.hexdigest(),16),a,n)
        tau=(tau*invert(hw,n))%n
    tau=pow(tau,s,n)
    my_sha1=hashlib.sha1()
    my_sha1.update(str(tau).encode())
    tau=int(my_sha1.hexdigest(),16)
    if tau==rho:
        return "success"
    else :
        return "failure"


if os.path.exists("./output/key.txt"):
    with open("./output/key.txt",'r') as file:
        n=int(file.readline())
        g=int(file.readline())
        e=int(file.readline())
        d=int(file.readline())
        v=int(file.readline())
else :
    n,g,e,d,v=KeyGen()
    with open("./output/key.txt",'w') as file:
        file.write(str(n)+'\n')
        file.write(str(g)+'\n')
        file.write(str(e)+'\n')
        file.write(str(d)+'\n')
        file.write(str(v)+'\n')

W=[]
tags=[]
if os.path.exists("./output/W.txt"):
    with open("./output/W.txt","r") as file:
        fl=file.readline()
        while fl:
            W.append(int(fl))
            fl=file.readline()
    with open("./output/tags.txt","r") as file:
        fl=file.readline()
        while fl:
            tags.append(int(fl))
            fl=file.readline()
else :
    W,tags=TagBlock(n,g,d,v)
    with open("./output/W.txt","w") as file:
        for i in W:
            file.write(str(i))
            file.write('\n')
    with open("./output/tags.txt","w") as file:
        for i in tags:
            file.write(str(i))
            file.write('\n')


if os.path.exists("./output/chal.txt"):
    with open("./output/chal.txt",'r') as file:
        c=int(file.readline())
        k1=int(file.readline())
        k2=int(file.readline())
        s=int(file.readline())
        gs=int(file.readline())
else :
    c,k1,k2,s,gs=GenProof(n,g)
    with open("./output/chal.txt",'w') as file:
        file.write(str(c)+'\n')
        file.write(str(k1)+'\n')
        file.write(str(k2)+'\n')
        file.write(str(s)+'\n')
        file.write(str(gs)+'\n')

def gen_proof(n,tags,c,k1,k2,gs,judge=0):
    f=open("1315245.1315318.pdf",'rb')
    F=f.read()
    f.close()
    b_size=64   # 64B

    if judge:
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

print("the server did not delete any thing:",end="")
T,rho=gen_proof(n,tags,c,k1,k2,gs)
print(CheckProff(n,e,W,c,k1,k2,s,T,rho))

print("the server deleted 1% of F(loop 100 times):",end="")
for i in range(100):
    T,rho=gen_proof(n,tags,c,k1,k2,gs,1)
    result=CheckProff(n,e,W,c,k1,k2,s,T,rho)
    if result=='success':
        print("success????")
        exit()
print("failure")