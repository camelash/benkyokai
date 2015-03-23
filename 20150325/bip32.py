import hashlib
import hmac
import ecc
import bitcoin

class BIP32:

    def __init__(self, data = None):
        if data == None: return
        if 16 > len(data) or len(data) > 64: raise Exception('BIP32 init: invalid seed')
        I = hmac.new('Bitcoin seed', data, hashlib.sha512).digest()
        Il = I[:32]
        Ir = I[32:]
        self.chaincode = Ir
        self.privkey = Il
        self.pubkey = bitcoin.privkeyToPubkey(Il)
        self.is_private = True
        self.depth = 0
        self.fingerprint = chr(0)*4
        self.child_num = 0
        self.hard = False

    def from_xprv(self, xprv):
        decoded = bitcoin.DecodeBase58Check(xprv)
        if decoded == None: raise Exception('BIP32.from_xprv: invalid xprv')
        if decoded[:4] != '0488ade4'.decode('hex'): raise Exception('BIP32.from_xprv: not proper xprv')
        self.depth = int(decoded[4:5].encode('hex'),16)
        self.fingerprint = decoded[5:9]
        self.child_num = int(decoded[9:13].encode('hex'),16)
        if self.child_num & 2**31:
            self.hard = True
            self.child_num = self.child_num & ((2**31) - 1)
        else:
            self.hard = False
        self.chaincode = decoded[13:45]
        self.privkey = decoded[46:]
        self.pubkey = bitcoin.privkeyToPubkey(decoded[46:])
        self.is_private = True
        return self

    def from_xpub(self, xpub):
        decoded = bitcoin.DecodeBase58Check(xpub)
        if decoded == None: raise Exception('BIP32.from_xpub: invalid xpub')
        if decoded[:4] != '0488b21e'.decode('hex'): raise Exception('BIP32.from_xpub: not proper xpub')
        self.depth = int(decoded[4:5].encode('hex'),16)
        self.fingerprint = decoded[5:9]
        self.child_num = int(decoded[9:13].encode('hex'),16)
        if self.child_num & 2**31:
            self.hard = True
            self.child_num = self.child_num & ((2**31) - 1)
        else:
            self.hard = False
        self.chaincode = decoded[13:45]
        self.privkey = None
        self.pubkey = decoded[45:]
        self.is_private = False
        return self

    def derive(self, path):
        if path[0].lower() != 'm': raise Exception('BIP32.derive: not proper path')
        paths = path.split('/')
        if self.is_private:
            ckd = self.privCKD
            nohard = False
        else:
            ckd = self.pubCKD
            nohard = True
        for x in paths:
            hardened = False
            if x.lower() == 'm': continue
            if x[-1:] == '\'':
                if nohard: raise Exception('BIP32.derive: hardened paths not allowed')
                hardened = True
                x = x[:-1]
            ckd(int(x), hardened)
        return self

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

