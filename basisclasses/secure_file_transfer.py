from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

import hashlib
import os

class SecureFileTransfer:

    def __init__(self: object, file: str) -> None:
        self.file = file

    def generate_rsa_keys(self) -> tuple:
        """

        :return:
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def serialize_rsa_keys(self) -> None:
        """

        :return:
        """
        private_key, public_key = self.generate_rsa_keys()

        serialize_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        with open(os.path.join(os.getcwd(), "rsa_keys/serialize_private_key.pem"), "wb") as serialize_private_key_file:
            serialize_private_key_file.write(serialize_private_key)

        serialize_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open(os.path.join(os.getcwd(), "rsa_keys/serialize_public_key.pem"), "wb") as serialize_public_key_file:
            serialize_public_key_file.write(serialize_public_key)

        print('RSA keys generated successful')

    def encryption(self, message: bytes) -> bytes:
        """

        :param message:
        :return:
        """

        self.serialize_rsa_keys()

        with open(os.path.join(os.getcwd(), "rsa_keys/serialize_public_key.pem"), "rb") as public_key_file:
            serialized_public_key = public_key_file.read()

        public_key = serialization.load_pem_public_key(
            serialized_public_key,
            backend=default_backend()
        )

        encrypted = public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        with open(os.path.join(os.getcwd(), "messages/encrypted_message"), "wb") as encrypted_message_file:
            encrypted_message_file.write(encrypted)

        print('Message encrypted successful')

        return encrypted

    def decryption(self, encrypted_message: str) -> None:
        """

        :param encrypted_message:
        :return:
        """

        with open(os.path.join(os.getcwd(), "rsa_keys/serialize_private_key.pem"), "rb") as private_key_file:
            serialized_private_key = private_key_file.read()

        with open(encrypted_message, "rb") as encrypted_message_file:
            encrypted_message_ = encrypted_message_file.read()

        private_key = serialization.load_pem_private_key(
            serialized_private_key,
            password=None,
            backend=default_backend()
        )

        original_message = private_key.decrypt(
            encrypted_message_,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        with open(os.path.join(os.getcwd(), "messages/decrypted_message.txt"), "wb") as encrypted_message_file:
            encrypted_message_file.write(original_message)

        print('Message decrypted successful')

    def hashing(self, message) -> hash:
        """

        :param message:
        :return:
        """

        hash_obj = hashlib.sha256()
        hash_obj.update(message)

        with open(os.path.join(os.getcwd(), "messages/hashing.txt"), "wb") as hashing_message_file:
            hashing_message_file.write(hash_obj.digest())

        print('Hashing generated successful')

        return hash_obj.digest()

    def integrity_verification(self) -> bool:
        """

        :return:
        """

        with open(os.path.join(os.getcwd(), "messages/hashing.txt"), "rb") as hashing_file:
            hashing_read = hashing_file.read()

        with open(os.path.join(os.getcwd(), "messages/decrypted_message.txt"), "rb") as decrypted_message_file:
            decrypted_message_read = decrypted_message_file.read()

        hash_obj = hashlib.sha256()
        hash_obj.update(decrypted_message_read)

        if hashing_read == hash_obj.digest():
            return True
        else:
            return False

