from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import base64

# 🔴 PASTE YOUR COMMIT HASH HERE
COMMIT_HASH = "PASTE_YOUR_40_CHAR_COMMIT_HASH_HERE"

# Load student private key
with open("student_private.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

# Sign commit hash (ASCII, NOT binary)
signature = private_key.sign(
    COMMIT_HASH.encode("utf-8"),
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# Load instructor public key
with open("instructor_public.pem", "rb") as f:
    instructor_public_key = serialization.load_pem_public_key(f.read())

# Encrypt signature
encrypted_signature = instructor_public_key.encrypt(
    signature,
    padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Output base64 (SINGLE LINE)
print(base64.b64encode(encrypted_signature).decode())
