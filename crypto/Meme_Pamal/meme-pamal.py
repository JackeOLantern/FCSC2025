# # Ce solveur de “Même Pamal” en évitant tout logarithme discret : 
# il projette les points chiffrés hors du sous-groupe ⟨g⟩ en multipliant 
# par order et reconstruit le message par octet via un dictionnaire.
# Auteur(e) : JG

from sage.all import *
import json

p = 0x30a3e68152784af010971f2597a98fb81553d31ae62f4ce940caba292f23a4f62880eefa5a360252cf582cbe8d54d22edcc252d0deae126caf410a4cab70f5a3
K = GF(p)
E = EllipticCurve(K, [1, 0])
g = E(0x23e1561e7c14d3c5b583a5a4b982eee07b3c8e1bfed153e10ebf55ddb8937cbd90980af26d5b0b02361cab6407e7014be718ffa0f3dcbbb9df205b6752d1b1d6, 0x22f20178ff2162d5a11b72cf7f82fd2844c550dc9362940e1aa4972439dc3816c0638554464f048df333cf4b48424f898ebe1f6fca568f1b014cde01a819d49e)
order = 0x19164fffb26ed8881b6a3f615752ad3cbe09bb420b3b0f6ed504d93544f1f0e3

class memepamal:
    step = 128

    def __init__(self):
        self.keygen()

    def keygen(self):
        self.sk = randrange(0, order - 1)
        self.pk = g * self.sk

    def encode(m):
        assert m <= (p // memepamal.step), "Message too large to be encoded"
        x = m * memepamal.step 
        while True:
            try:
                point = E.lift_x(K(x))
                return point
            except:
                x += 1
                continue

    def decode(point):
        return int(point.x()) // memepamal.step
    
    def encrypt(m, pk):
        m = int.from_bytes(m, "little")
        t = memepamal.encode(m)
        r = randrange(0, order - 1)
        u = g * r
        v = t + (pk * r)
        return (u, v)
    
    def decrypt(self, u, v):
        t = v - u * self.sk
        m = memepamal.decode(t)
        return int.to_bytes(m, ceil(log(p, 256)))
    

elg = memepamal()
flag = open("../src/flag.txt", "rb").read()
encrypted = [memepamal.encrypt(bytes([i]), elg.pk) for i in flag]
dic = {
    "pk" : [int(_) for _ in elg.pk],
    "enc" : [([int(_) for _ in u], [int(_) for _ in v]) for (u,v) in encrypted]
}
print(json.dumps(dic, indent = 4))
