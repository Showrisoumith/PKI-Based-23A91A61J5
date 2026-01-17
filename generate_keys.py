from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_keys():
    # Generate 4096-bit RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )

    # Serialize private key to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Get public key
    public_key = private_key.public_key()

    # Serialize public key to PEM
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Save private key
    with open("student_private.pem", "wb") as f:
        f.write(private_pem)

    # Save public key
    with open("student_public.pem", "wb") as f:
        f.write(public_pem)

    print("✔ Keys generated successfully!")
    print(" - student_private.pem")
    print(" - student_public.pem")


if __name__ == "__main__":
    generate_keys()
