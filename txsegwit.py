import hashlib
import base58

my_addr             = '2MtSqcGq689G8ozH4rjaMuxHCHJmU975NzH'
last_tx             = 'fe9273a11f7e75bf6b49af16e3b15c726e15e3723fa2dd42f4896b9edeb250b3'
total_amount_send   = 0.000095

rest_amount_send    = 0.000089
priv_key            = '68e374034c2b1edad5b95f57a811a765c7a40b49592c3f42a6d386776c3b8580'
addr_dest           = '2NGZrVvZG92qGYqzTLjCAewvPZ7JE8S8VxE'
# pub_hash_dest       = base58.b58decode_check(addr_dest)[1:].hex()
pub_hash_dest       = 'a914ffd0dbb44402d5f8f12d9ba5b484a2c1bb47da4287'       

def dSHA256(raw):
    hash_1 = hashlib.sha256(raw).digest()
    hash_2 = hashlib.sha256(hash_1).digest()
    return hash_2

# version
version = (1).to_bytes(4, byteorder="little", signed=False)

# hashPrevOut + outpoint
txid = (bytes.fromhex(last_tx))[::-1]
index = (1).to_bytes(4, byteorder="little", signed=False)

outpoint = (
    txid
    + index
)

hashPrevOut = dSHA256(outpoint)

# hashSequence + sequence
sequence = bytes.fromhex("ffffffff")

hashSequence = dSHA256(sequence)

# value/amount
amount = (int(total_amount_send * 100000000)).to_bytes(8, byteorder="little", signed=True)

# hashOutput + output
value = (int(rest_amount_send * 100000000)).to_bytes(8, byteorder="little", signed=True)
pk_script = bytes.fromhex(pub_hash_dest)
pk_script_len = (len(pk_script)).to_bytes(1, byteorder="little", signed=False)

output = (
    value
    + pk_script_len
    + pk_script
)

hashOutput = dSHA256(output)

# nLockTime
nLockTime = (0).to_bytes(4, byteorder="little", signed=False)

# sighash
sighash = bytes.fromhex("01000000")

# ecdsa + scriptcode
import ecdsa

private_key = bytes.fromhex(priv_key)

signing_key = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1) # Don't forget to specify the curve

verifying_key = signing_key.get_verifying_key()

# Use this code block if the address you gave corresponds to the compressed public key
x_cor = bytes.fromhex(verifying_key.to_string().hex())[:32] # The first 32 bytes are the x coordinate
y_cor = bytes.fromhex(verifying_key.to_string().hex())[32:] # The last 32 bytes are the y coordinate
if int.from_bytes(y_cor, byteorder="big", signed=True) % 2 == 0: # We need to turn the y_cor into a number. 
    public_key = bytes.fromhex("02" + x_cor.hex())
else:
    public_key = bytes.fromhex("03" + x_cor.hex())

sha256_1 = hashlib.sha256(public_key)

ripemd160 = hashlib.new("ripemd160")
ripemd160.update(sha256_1.digest())

keyhash = ripemd160.digest()

scriptcode = bytes.fromhex(f"1976a914{keyhash.hex()}88ac")

bip_143 = (
    version
    + hashPrevOut
    + hashSequence
    + outpoint
    + scriptcode
    + amount
    + sequence
    + hashOutput
    + nLockTime
    + sighash
)

hashed_bip_143 = dSHA256(bip_143)

signature = signing_key.sign_digest(hashed_bip_143, sigencode=ecdsa.util.sigencode_der_canonize)

witness = (
    bytes.fromhex("02")
    + (len(signature)).to_bytes(1, byteorder="little", signed=False)
    + signature
    + bytes.fromhex("01")
    + (len(public_key)).to_bytes(1, byteorder="little", signed=False)
    + public_key
)

# redeemScript

redeemScript = bytes.fromhex(f"0014{keyhash.hex()}")
redeemScriptFull = (
    (len(redeemScript)+ 1).to_bytes(1, byteorder="little", signed=False)
    + (len(redeemScript)).to_bytes(1, byteorder="little", signed=False)
    + redeemScript
)

# tx in/out count
tx_in_count = (1).to_bytes(1, byteorder="little", signed=False)
tx_out_count = (1).to_bytes(1, byteorder="little", signed=False)


# marker & flag

marker = bytes.fromhex("00")
flag = bytes.fromhex("01")

final_tx = (
    version
    + marker
    + flag
    + tx_in_count
    + outpoint
    + redeemScriptFull
    + sequence
    + tx_out_count
    + output
    + witness
    + nLockTime
)

print(final_tx.hex())


