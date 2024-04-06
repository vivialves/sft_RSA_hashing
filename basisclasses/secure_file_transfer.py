from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

import hashlib
import os


class SecureFileTransfer:

    def __init__(self: object,
                 plain_text: str,
                 private_key: bytes = 'default',
                 public_key: bytes = 'default',
                 encrypted_text: bytes = 'default',
                 decrypted_text: bytes = 'default',
                 hashing_text: bytes = 'default'
                 ) -> None:

        self.plain_text = plain_text
        self.private_key = private_key
        self.public_key = public_key
        self.encrypted_text = encrypted_text
        self.decrypted_text = decrypted_text
        self.hashing_text = hashing_text

    def generate_rsa_keys(self) -> tuple:
        """

        :return:
        """
        private_key_ = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key_ = private_key_.public_key()
        return private_key_, public_key_

    def serialize_rsa_private_key(self) -> bytes:
        """

        :return:
        """
        private_key_, public_key_ = self.generate_rsa_keys()

        serialize_private_key = private_key_.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        self.private_key = serialize_private_key
        # with open(os.path.join(os.getcwd(), "rsa_keys/serialize_private_key.pem"), "wb") as serialize_private_key_file:
            # serialize_private_key_file.write(serialize_private_key)

        print('Private key generated successfully')
        return self.private_key

    def serialize_rsa_public_key(self) -> bytes:
        """

        :return:
        """
        private_key_, public_key_ = self.generate_rsa_keys()
        serialize_public_key = public_key_.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.public_key = serialize_public_key
        # with open(os.path.join(os.getcwd(), "rsa_keys/serialize_public_key.pem"), "wb") as serialize_public_key_file:
            # serialize_public_key_file.write(serialize_public_key)
        print('Public key generated successfully')
        return self.public_key

    def encryption(self) -> bytes:
        """

        :return:
        """
        # serial_public_key = self.serialize_rsa_public_key()

        # with open(os.path.join(os.getcwd(), "rsa_keys/serialize_public_key.pem"), "rb") as public_key_file:
            # serialized_public_key = public_key_file.read()
        print(self.public_key)
        public_key = serialization.load_pem_public_key(
            self.public_key,
            backend=default_backend()
        )
        encrypted = public_key.encrypt(
            self.plain_text,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # with open(os.path.join(os.getcwd(), "messages/encrypted_message"), "wb") as encrypted_message_file:
            # encrypted_message_file.write(encrypted)
        self.encrypted_text = encrypted
        print('Message encrypted successful')
        return self.encrypted_text

    def decryption(self) -> None:
        """

        :return:
        """

        # with open(os.path.join(os.getcwd(), "rsa_keys/serialize_private_key.pem"), "rb") as private_key_file:
            # serialized_private_key = private_key_file.read()

        # with open(encrypted_message, "rb") as encrypted_message_file:
            # encrypted_message_ = encrypted_message_file.read()

        private_key = serialization.load_pem_private_key(
            self.private_key,
            password=None,
            backend=default_backend()
        )
        message_after_decryption = private_key.decrypt(
            self.encrypted_text,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        self.decrypted_text = message_after_decryption
        # with open(os.path.join(os.getcwd(), "messages/decrypted_message.txt"), "wb") as encrypted_message_file:
            # encrypted_message_file.write(original_message)
        print('Message decrypted successful')
        return self.decrypted_text

    def hashing(self) -> bytes:
        """

        :return:
        """
        hash_obj = hashlib.sha256()
        hash_obj.update(self.plain_text)
        self.hashing_text = hash_obj.digest()
        # with open(os.path.join(os.getcwd(), "messages/hashing.txt"), "wb") as hashing_message_file:
            # hashing_message_file.write(hash_obj.digest())
        print('Hashing generated successful')
        return self.hashing_text

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

