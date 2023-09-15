import rsa
(pubkey, privkey) = rsa.newkeys(1024)
skCert = privkey.d
nCert = pubkey.n
pkCert = pubkey.e
print("skCert : ", skCert)
print("nCert : ", nCert)
print("pkCert : ", pkCert)
(pubkey, privkey) = rsa.newkeys(1024)
skA = privkey.d
nA = pubkey.n
pA = pubkey.e
CertA = pow(pA, skCert, nCert)
print("skA : ", skA)
print("nA : ", nA)
print("pkA : ", pA)
print("CertA : ", CertA)
(pubkey, privkey) = rsa.newkeys(1024)
skT = privkey.d
nT = pubkey.n
pT = pubkey.e
CertT = pow(pT, skCert, nCert)
print("skT : ", skT)
print("nT : ", nT)
print("pkT : ", pT)
print("CertT : ", CertT)
(pubkey, privkey) = rsa.newkeys(1024)
skV = privkey.d
nV = pubkey.n
pV = pubkey.e
CertV = pow(pV, skCert, nCert)
print("skV : ", skV)
print("nV : ", nV)
print("pkV : ", pV)
print("CertV : ", CertV)