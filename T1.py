import socket
import rsa
import hashlib
import sys
import random
def hash(m):
    return hashlib.sha256(str(m).encode()).hexdigest()
def VrfyRSA(pk, n, sig, m):
    x = pow(sig, pk, n)
    return x == m
def SignRSA(sk, n, mes):
    return pow(mes, sk, n)
def EncRSA(pk, n, m):
    return pow(m, pk, n)
def DecRSA(sk, n, c):
    return pow(c, sk, n)

HOST = '127.0.0.1'
APORT = 50000
TPORT = 50001
VPORT = 50002
Aaddress = (HOST, APORT)
Taddress = (HOST, TPORT)
Vaddress = (HOST, VPORT)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)#UDP

skT = 41670293266680212911613942744365901824688457182545325745755571852314385640277561003061055970177856256749137679120883135204191932700878410774360778537146759930256972642685567094673714906086852202599922540696566983681843447118029464418618122423022303374936107057349575238852731413733925481811880679662551651073
nT = 151500388872651787062489901566487745916154855118854599656029230693727276806106208557506514208229566487216700104102147899249812864385746610835420130497562592585315425156628082727026984304939818868625409684223885542605510518199510199496776987552402123623695814405814791227642371015651886184434909013984131350563
pkT = 65537
CertT = 62234211574278407561863843420279631497585249042582301714857588559076936746053480759139529837253685667250572726233212003634577038580141887074922127431249974045949325879379015173710021520809309531001393758464974494680670575700049861082714368820013469860037495054667158730234594077217870367251681540548087553390

pkCert = 65537  
nCert = 106460729752036168105916381178474341247595425520394661988161810214747462705507433370673571214415148063991646624200418843920105542536486692379491997943902740539467523267804788711459532059924049782655724857503644303973606628932059884706993516808651531944588850975587203703350992449923997709115011828745180080291
#发布Cert的可信第三方

s.bind((HOST, TPORT))
IDCHID = {}
while True:
    # try:
    #     conn, addr = s.accept()
    # except:
    #     break
    # print('Connected by ', addr)
    data = s.recvfrom(1024)[0].decode()
    if data == "REQUEST":
        H = int(s.recvfrom(1024)[0].decode(), 16)
        print("hash(ID) : ", H)
        S = int(s.recvfrom(1024)[0].decode(), 10)
        print("Sig_skA(hash(ID)) : ", S)
        pkA = int(s.recvfrom(1024)[0].decode(), 10)
        print("pkA : ", pkA)
        nA = int(s.recvfrom(1024)[0].decode(), 10)
        print("nA : ", nA)
        CertA = int(s.recvfrom(1024)[0].decode(), 10)
        print("CertA : ", CertA)
        if VrfyRSA(pkCert, nCert, CertA, pkA) == 0 or VrfyRSA(pkA, nA, S, H) == 0:
            print("fail.")
            s.sendto("fail.".encode(), Aaddress)
            break
        IDC = random.randint(0, 100)
        IDCHID[IDC] = H
        break


while True:
    # try:
    #     s.connect((HOST, TPORT))
    # except Exception as e:
    #     print('Server not found or not open')
    #     continue
    print("send to V:")
    H = hash(IDC)
    print("hash(IDC) : ", H)
    s.sendto(str(H).encode(), Vaddress)
    S = SignRSA(skT, nT, int(H, 16))
    print("Sig_skT(hash(IDC)) : ", S)
    s.sendto(str(S).encode(), Vaddress)
    print("pkT : ", pkT)
    s.sendto(str(pkA).encode(), Vaddress)
    print("nT : ", nT)
    s.sendto(str(nT).encode(), Vaddress)
    print("CertT : ", CertT)
    s.sendto(str(CertT).encode(), Vaddress)    
    break
print("Stop the T....")


