import socket
import rsa
import hashlib
import sys
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
(pubkey, privkey) = rsa.newkeys(1024)
skA = 110003315278472341624156468630796342521951674805814493915738102474517253949708977271065805159326795564029174863735189128612890988734698784777207144672534853175100355837056714150851232746917065471087822391579360445485867128288595749763438970103864927970534274366491382826134131424980376690373407172905390323873
nA = 120034753136950413803235805605336328669016765097380361101493973058149138729638315741156171707072930417578755128947936895136580698113652252047016769800847371540862891140388074418912635518516113220153782943774314467361455644162808632731910083365929830070654679269967782128933944632730496979020581921269522475587
pkA = 65537
CertA = 62234211574278407561863843420279631497585249042582301714857588559076936746053480759139529837253685667250572726233212003634577038580141887074922127431249974045949325879379015173710021520809309531001393758464974494680670575700049861082714368820013469860037495054667158730234594077217870367251681540548087553390

pkCert = 65537  
nCert = 106460729752036168105916381178474341247595425520394661988161810214747462705507433370673571214415148063991646624200418843920105542536486692379491997943902740539467523267804788711459532059924049782655724857503644303973606628932059884706993516808651531944588850975587203703350992449923997709115011828745180080291
#发布Cert的可信第三方

s.bind((HOST, APORT))
legallist = {"X" : 1, "Y": 2}#合法投票者名单

while True:
    data = s.recvfrom(1024)[0].decode()
    if data == "REQUEST":
        pkV = int(s.recvfrom(1024)[0].decode(), 10)
        print('pkV : ', pkV)
        nV = int(s.recvfrom(1024)[0].decode(), 10)
        print('nV : ', nV)
        CertV = int(s.recvfrom(1024)[0].decode(), 10)
        print("CertV : ", CertV)
        if VrfyRSA(pkCert, nCert, CertV, pkV) == 0:
            print("fail.")
            s.sendto("fail.".encode(), Vaddress)
            break
        voter = "X"
        print("check the voter list...")
        print("the voter is X")
        ID = legallist[voter]
        print("the voter ID : ", ID)
        E = EncRSA(pkV, nV, ID)
        print("Enc_pkV(ID) : ", E)
        s.sendto(str(E).encode(), Vaddress)
        H = hash(E)
        S = SignRSA(skA, nA, int(H, 16))
        print("Sig_skA(hash(Enc(ID))) : ", S)
        s.sendto(str(S).encode(), Vaddress)
        print("pkA : ", pkA)
        s.sendto(str(pkA).encode(), Vaddress)
        print("nA : ", nA)
        s.sendto(str(nA).encode(), Vaddress)
        print("CertA : ", CertA)
        s.sendto(str(CertA).encode(), Vaddress)
    break

print("*" * 40)

while True:
    print("send to T:")
    s.sendto("REQUEST".encode(), Taddress)
    H = hash(ID)
    print("hash(ID) : ", H)
    s.sendto(str(H).encode(), Taddress)
    S = SignRSA(skA, nA, int(H, 16))
    print("Sig_skA(hash(ID)) : ", S)
    s.sendto(str(S).encode(), Taddress)
    print("pkA : ", pkA)
    s.sendto(str(pkA).encode(), Taddress)
    print("nA : ", nA)
    s.sendto(str(nA).encode(), Taddress)
    print("CertA : ", CertA)
    s.sendto(str(CertA).encode(), Taddress)    
    break
print("Stop the A....")         