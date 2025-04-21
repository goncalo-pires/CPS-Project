from ecpy import EllipticCurve, FiniteField, MapToPoint, weil_pairing
import random
import hashlib
import binascii

# Private Key Generator
class IBE:

    def __init__(self):
        self.setup()

    def setup(self):
        # security parameter k (or p), 1024 bits, prime number. Congruent 2 mod 3.
        self.p = int("154842607334052426949720451504120838286563263886095369"
                     "789183831959881603008322501674271060619528663421007000"
                     "093142479960798534935790698857570305385834638724387256"
                     "060160141717681013107155447695217553597640367043482651"
                     "198314699285051662284280393022545338261662146835828160"
                     "652001972289614545295916851551746830913")
        # Just for testing purposes.
        #self.p = 56453

        self.q = (self.p + 1) // 6 # q is prime and > 3, p = 6q − 1
        self.F = FiniteField(self.p) # Field where we define the eliptic curve
        # E is an elliptic curve defined by the equation y^2 = x^3 + 1 over Fp
        self.E = EllipticCurve(self.F, 0, 1) # E = y^2 = x^3 + 1
        self.P = self.genP()
        self.s = random.randint(1, self.q-1) # Master key
        self.params = {
            "n": 1024, # Size of message space and hashes in bits.
            "p": self.p,
            "q": self.q,
            "F": self.F,
            "E": self.E,
            "P": self.P,
            "Ppub": self.s * self.P # Used on encryption
        }

    def extract(self, params, id):
        """
        Private Key Generator
        Takes as input params, master-key, and an arbitrary ID ∈ {0, 1}*
        Returns a private key.
        """
        Q_id = IBE.MapToPoint2(id, params)
        IBE.check_order(params, Q_id)
        return self.s * Q_id

    @staticmethod
    def encrypt(params, id, plaintext):
        """
        Takes as input params, ID, and a plaintext.
        Returns a ciphertext.
        """
        m = IBE.truncateBits(plaintext, params["n"])
        Q_id = IBE.MapToPoint2(id, params)
        IBE.check_order(params, Q_id)
        o = IBE.random_o(params)
        r = IBE.H1(params, o, m)
        # For performance, we could calculate the weil pairing only once
        # for a given id, and then use the already calculated value in
        # future encryptions
        g_id = weil_pairing(params["E"], Q_id, params["Ppub"], int(params["q"]))
        U = int(r) * params["P"]
        V = IBE.bin_to_int(o) ^ IBE.bin_to_int(IBE.H(params, g_id**int(r)))
        W = IBE.bin_to_int(m) ^ IBE.bin_to_int(IBE.G1(params, o))
        return [U,V,W]

    @staticmethod
    def decrypt(params, ciphertext, pk):
        """
        Takes as input params, public key ID, ciphertext, and a private key
        Returns a plaintext.
        """
        U = ciphertext[0]
        V = ciphertext[1]
        W = ciphertext[2]
        g = weil_pairing(params["E"], pk, U, params["q"])
        o = V ^ IBE.bin_to_int(IBE.H(params, g))
        o = IBE.int_to_bin(o, params["n"])
        m = W ^ IBE.bin_to_int(IBE.G1(params, o))
        m = IBE.int_to_bin(m, params["n"])
        r = IBE.H1(params, o, m)
        if((U-(r * params["P"])).is_infinity()):
            m = m.zfill(len(m) + (8-(len(m)%8)))
            return ''.join(chr(int(m[i:i+8], 2)) for i in range(0, len(m), 8))
        else:
            raise Exception("Ciphertext rejected...\n")

    def genP(self):
        """Returns point P of Fp, ord(P) = q"""
        i = 1
        while True:
            y = self.E.get_corresponding_y(i)
            if y != None:
                P = self.E(i, y)
                if (int(self.q) * P).is_infinity():
                    return P
            i += 1

    @staticmethod
    def MapToPoint2(id, params):
        """
        Algorithm for converting an arbitrary string ID ∈ {0, 1}*
        to a point Qid ∈ E/Fp of order q.
        """
        y = IBE.G(params, id)
        f = params["E"].field(y)
        x = IBE.cubic_root(params, f**2 - 1)
        return 6 * params["E"](x, y)

    @staticmethod
    def cubic_root(params, x):
        """
        Function taken from 'ecpy/utils/root.py' and adapted
        to our code. Calculate Cubic Residue of x.
        """
        F = x.field
        p = F.p
        m = F.degree()
        rho = 1
        pm = params["p"]**m
        r = (pm - 1) // 3
        rho = 1
        while rho ** r == 1:
            rho = params["F"](random.randint(1, params["p"] - 1))
            t = 1
        while True:
            r = 3**t
            if (pm - 1) % r == 0:
                t += 1
            else:
                t -= 1
                s = (pm - 1) // 3**t
                if (s + 1) % 3 == 0:
                    l = (s + 1) // 3
                    break
                elif (s - 1) % 3 == 0:
                    l = (s - 1) // 3
                    break
        a = rho ** s
        a_ = rho ** (3**(t - 1) * s)
        b = x ** s
        h = 1
        i = 1
        while i < t:
            d = b ** (3**(t - 1 - i))
            if d == 1:
                k = 0
            elif d == a_:
                k = 2
            else:
                k = 1
            b = b * (a * a * a)**k
            h = h * a**k
            a = a * a * a
            i += 1
        r = x**l * h
        if s == 3 * l + 1:
            r = 1 // r
        return r

    # Check if ord(x) = q
    @staticmethod
    def check_order(params, x):
        if not((x*params["q"]).is_infinity()):
            raise Exception("Invalid ID")

    # Message space = {0,1}^n
    @staticmethod
    def truncateBits(msg, n_):
        b = [bin(ord(x))[2:].zfill(8) for x in msg]
        return ''.join(x for x in b)[:n_].zfill(n_)

    # --> {0,1}^n
    @staticmethod
    def random_o(params):
        f = ''
        while len(f) < params["n"]:
            f += str(random.randint(0, 1))
        return f

    @staticmethod
    def bin_to_int(x):
        return int(x,2)

    @staticmethod
    def int_to_bin(x, n_):
        return bin(x)[2:].zfill(n_)

    @staticmethod
    def G(params, x):
        """
        Cryptographic hash function G : {0, 1}* --> Fp (in
        the security analysis we view G as a random oracle)
        """
        b = bin(int(binascii.hexlify(bytearray(x, 'utf-8')),16))[2:]
        return int(hashlib.sha512(b.encode('utf-8')).hexdigest(), 16) % params["p"]

    @staticmethod
    def H(params, x):
        """
        Cryptographic hash function H : Fp^2 --> {0, 1}^n for some n.
        (in the security analysis we view H as a random oracle)
        """
        j = ''
        # 513 because sha512 returns 512 bits. +1 is for when n=512, 't' must be 1.
        t = params["n"] // 513 + 1
        # For the hash to have len=n, we divide x in as many parts as necessary
        # and calculate the hash for each and concatenate the hashes.
        for i in range(0, t):
            j = j + (hashlib.sha512(bytearray(str(x)[i::t], 'utf-8')).hexdigest())
        return IBE.truncateBits(j, params["n"])

    # {0,1}^n --> {0,1}^n
    @staticmethod
    def G1(params, x):
        j = ''
        t = params["n"] // 513 + 1
        for i in range(0, t):
            j = j + (hashlib.sha512(bytearray(str(x)[i::t], 'utf-8')).hexdigest())
        return IBE.truncateBits(j, params["n"])

    # {0,1}^n * {0,1}^n --> Fq
    @staticmethod
    def H1(params, x, y):
        x = int(hashlib.sha512(x.encode('utf-8')).hexdigest(), 16)
        y = int(hashlib.sha512(y.encode('utf-8')).hexdigest(), 16)
        return (x * y) % params["q"]
