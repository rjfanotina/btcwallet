# import random
# private_key = (random.getrandbits(256)).to_bytes(32, byteorder="little", signed=False)
private_key = '68e374034c2b1edad5b95f57a811a765c7a40b49592c3f42a6d386776c3b8580'
private_key = bytes.fromhex(private_key)



# Attaching private key to SECP256k1 using ECDSA
import ecdsa
signing_key = ecdsa.SigningKey.from_string(private_key, curve = ecdsa.SECP256k1)

verifying_key = signing_key.get_verifying_key()

# Getting the compressed public key
x_cor = bytes.fromhex(verifying_key.to_string().hex())[:32]         # The first 32 bytes are the x cordinate.
y_cor = bytes.fromhex(verifying_key.to_string().hex())[32:]         # The last 32 bytes are the y cordinate.
if int.from_bytes(y_cor, byteorder="big", signed=True) % 2 == 0:    # We need to turn the y_cor (bytes) into a number.
    public_key = bytes.fromhex(f'02{x_cor.hex()}')
else:
    public_key = bytes.fromhex(f'03{x_cor.hex()}')
    
import hashlib

# Generating keyhash
sha256_1 = hashlib.sha256(public_key)

ripemd160 = hashlib.new("ripemd160")
ripemd160.update(sha256_1.digest())

keyhash = ripemd160.digest()

# Placing keyhash in a P2WPKH_VO script
P2WPKH_VO = bytes.fromhex(f'0014{keyhash.hex()}')

# Hashing P2WPKH_VO script
sha256_P2WPKH_VO = hashlib.sha256(P2WPKH_VO)

ripemd160_P2WPKH_VO = hashlib.new("ripemd160")
ripemd160_P2WPKH_VO.update(sha256_P2WPKH_VO.digest())

hashed_P2WPKH_VO = ripemd160_P2WPKH_VO.digest()

# Nesting hashed P2WPKH_VO inside a P2SH
P2SH_P2WPKH_V0 = bytes.fromhex(f'a9{hashed_P2WPKH_VO.hex()}87')

# Getting checksum
# checksum_full = hashlib.sha256(hashlib.sha256(bytes.fromhex(f'05{hashed_P2WPKH_VO.hex()}')).digest()).digest()
# Getting checksum testnet
checksum_full = hashlib.sha256(hashlib.sha256(bytes.fromhex(f'c4{hashed_P2WPKH_VO.hex()}')).digest()).digest()

checksum = checksum_full[:4]

# Assembling the nested address
# bin_addr = bytes.fromhex(f'05{hashed_P2WPKH_VO.hex()}{checksum.hex()}')
# Assembling the nested address testnet
bin_addr = bytes.fromhex(f'c4{hashed_P2WPKH_VO.hex()}{checksum.hex()}')


# Encode nested address in base58
import base58
nested_address = base58.b58encode(bin_addr)



print("Private key: "           + private_key.hex())
print("Verifiction key: "       + verifying_key.to_string().hex())
print("Compressed public key: " + public_key.hex())
print("keyhash: "               + keyhash.hex())
print("P2WPKH_V0: "             + P2WPKH_VO.hex())
print("Hashed P2WPKH_VO: "      + hashed_P2WPKH_VO.hex())
print("P2SH_P2WPKH_V0: "        + P2SH_P2WPKH_V0.hex())
print("Checksum: "              + checksum.hex())
print("Binary address: "        + bin_addr.hex())
print("Nested address: "        + nested_address.decode())