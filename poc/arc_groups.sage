from sagelib.groups import GroupP256
from util import to_bytes

G = GroupP256()

context_string = "ARCV1-P256"

def hash_to_group(x, info):
    dst = to_bytes("HashToGroup-") + to_bytes(context_string) + info
    return G.hash_to_group(x, dst)

def hash_to_scalar(x, info):
    dst = to_bytes("HashToScalar-") + to_bytes(context_string) + info
    return G.hash_to_scalar(x, dst)

GenG = G.generator()
GenH = hash_to_group(G.serialize(GenG), to_bytes("generatorH"))
