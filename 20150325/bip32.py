import hashlib
import hmac
import ecc
import bitcoin

class BIP32:

    def __init__(self, privkey, pubkey, chaincode, depth, fingerprint, child_num, is_private, is_hard):
        self.chaincode = chaincode
        self.privkey = privkey
        self.pubkey = pubkey
        self.is_private = is_private
        self.depth = depth
        self.fingerprint = fingerprint
        self.child_num = child_num
        self.hard = is_hard

    @classmethod
    def from_seed(cls, seed):
        if 16 > len(seed) or len(seed) > 64: raise Exception('BIP32 init: invalid seed')
        I = hmac.new('Bitcoin seed', seed, hashlib.sha512).digest()
        Il = I[:32]
        Ir = I[32:]
        chaincode = Ir
        privkey = Il
        pubkey = bitcoin.privkeyToPubkey(Il)
        is_private = True
        depth = 0
        fingerprint = chr(0)*4
        child_num = 0
        is_hard = False
        return cls(privkey, pubkey, chaincode, depth, fingerprint, child_num, is_private, is_hard)

    @classmethod
    def from_xprv(cls, xprv):
        decoded = bitcoin.DecodeBase58Check(xprv)
        if decoded == None: raise Exception('BIP32.from_xprv: invalid xprv')
        if decoded[:4] != '0488ade4'.decode('hex'): raise Exception('BIP32.from_xprv: not proper xprv')
        depth = int(decoded[4:5].encode('hex'),16)
        fingerprint = decoded[5:9]
        child_num = int(decoded[9:13].encode('hex'),16)
        if child_num & 2**31:
            is_hard = True
            child_num = child_num & ((2**31) - 1)
        else:
            is_hard = False
        chaincode = decoded[13:45]
        privkey = decoded[46:]
        pubkey = bitcoin.privkeyToPubkey(decoded[46:])
        is_private = True
        return cls(privkey, pubkey, chaincode, depth, fingerprint, child_num, is_private, is_hard)

    @classmethod
    def from_xpub(cls, xpub):
        decoded = bitcoin.DecodeBase58Check(xpub)
        if decoded == None: raise Exception('BIP32.from_xpub: invalid xpub')
        if decoded[:4] != '0488b21e'.decode('hex'): raise Exception('BIP32.from_xpub: not proper xpub')
        depth = int(decoded[4:5].encode('hex'),16)
        fingerprint = decoded[5:9]
        child_num = int(decoded[9:13].encode('hex'),16)
        if child_num & 2**31:
            is_hard = True
            child_num = child_num & ((2**31) - 1)
        else:
            is_hard = False
        chaincode = decoded[13:45]
        privkey = None
        pubkey = decoded[45:]
        is_private = False
        return cls(privkey, pubkey, chaincode, depth, fingerprint, child_num, is_private, is_hard)

    def neuter(self):
        if self.privkey == None: raise Exception('BIP32.neuter: no private key to neuter')
        return BIP32(None, self.pubkey, self.chaincode, self.depth, self.fingerprint, self.child_num, False, self.hard)

    def derive(self, path):
        if path[0].lower() != 'm': raise Exception('BIP32.derive: not proper path')
        newHD = BIP32(self.privkey, self.pubkey, self.chaincode, self.depth, self.fingerprint, self.child_num, self.is_private, self.hard)
        paths = path.split('/')
        if newHD.is_private:
            ckd = newHD.privCKD
            nohard = False
        else:
            ckd = newHD.pubCKD
            nohard = True
        for x in paths:
            hardened = False
            if x.lower() == 'm': continue
            if x[-1:] == '\'':
                if nohard: raise Exception('BIP32.derive: hardened paths not allowed')
                hardened = True
                x = x[:-1]
            ckd(int(x), hardened)
        return newHD

    def privCKD(self, child_num, hardened = False):
        if child_num >= 2**31:
            raise Exception('BIP32.privCKD: child number too large')
        if hardened:
            child_num = child_num | 2**31
            data = chr(0) + self.privkey + ('%08x' % child_num).decode('hex')
        else:
            data = self.pubkey + ('%08x' % child_num).decode('hex')
        I = hmac.new(self.chaincode, data, hashlib.sha512).digest()
        Il = I[:32]
        Ir = I[32:]
        self.depth = self.depth + 1
        self.fingerprint = bitcoin.hash_160(self.pubkey)[:4]
        self.chaincode = Ir
        priv = (int(Il.encode('hex'),16) + int(self.privkey.encode('hex'),16)) % ecc.cN
        self.privkey = ('%064x' % priv).decode('hex')
        self.pubkey = bitcoin.privkeyToPubkey(self.privkey)
        self.is_private = True
        self.child_num = child_num & ((2**31) - 1)
        self.hard = hardened

    def pubCKD(self, child_num, hardened = False):
        if child_num >= 2**31:
            raise Exception('BIP32.pubCKD: child number too large')
        if hardened:
            raise Exception('BIP32.pubCKD: no hardened paths allowed')
        else:
            data = self.pubkey + ('%08x' % child_num).decode('hex')
        I = hmac.new(self.chaincode, data, hashlib.sha512).digest()
        Il = I[:32]
        Ir = I[32:]
        self.depth = self.depth + 1
        self.fingerprint = bitcoin.hash_160(self.pubkey)[:4]
        self.chaincode = Ir
        self.privkey = None
        
        pub = bitcoin.privkeyToPubkey(Il, False)
        point_1 = bitcoin.pubkeyToPoint(pub)
        point_2 = bitcoin.pubkeyToPoint(self.pubkey)
        point_3 = ecc.EC_add(point_1, point_2)
        
        self.pubkey = bitcoin.pointToPubkey(point_3)
        self.is_private = False
        self.child_num = child_num & ((2**31) - 1)
        self.hard = False

    def to_xprv(self):
        if self.privkey == None: raise Exception('BIP32.to_xprv: no private key available')
        data = '0488ade4'.decode('hex')
        data += ('%02x' % self.depth).decode('hex')
        data += self.fingerprint
        if self.hard:
            data += ('%08x' % (self.child_num | 2**31)).decode('hex')
        else:
            data += ('%08x' % self.child_num).decode('hex')
        data += self.chaincode
        data += chr(0) + self.privkey
        return bitcoin.EncodeBase58Check(data)

    def to_xpub(self):
        data = '0488b21e'.decode('hex')
        data += ('%02x' % self.depth).decode('hex')
        data += self.fingerprint
        if self.hard:
            data += ('%08x' % (self.child_num | 2**31)).decode('hex')
        else:
            data += ('%08x' % self.child_num).decode('hex')
        data += self.chaincode
        data += self.pubkey
        return bitcoin.EncodeBase58Check(data)

    def to_address(self):
        return bitcoin.pubkeyToAddress(self.pubkey)

    def to_WIFpriv(self):
        if self.privkey == None: raise Exception('BIP32.to_WIFpriv: no private key available')
        return bitcoin.privkeyToWIF(self.privkey)

