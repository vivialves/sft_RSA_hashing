from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

import hashlib


class SecureFileTransfer:

    private_key_nopem = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend())

    public_key_nopem = private_key_nopem.public_key()

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

    def serialize_rsa_private_key(self) -> bytes:
        """

        :return:
        """
        serialize_private_key = SecureFileTransfer.private_key_nopem.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        self.private_key = serialize_private_key
        print('Private key generated successfully')
        return self.private_key

    def serialize_rsa_public_key(self) -> bytes:
        """

        :return:
        """
        serialize_public_key = SecureFileTransfer.public_key_nopem.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.public_key = serialize_public_key
        print('Public key generated successfully')
        return self.public_key

    def encryption(self, serialized_public_key: bytes) -> bytes:
        """

        :param serialized_public_key:
        :return:
        """

        public_key = serialization.load_pem_public_key(
            serialized_public_key,
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
        print('Message encrypted successfully')
        return encrypted

    def decryption(self, encrypted_message: bytes, serialized_private_key: bytes) -> bytes:
        """

        :param encrypted_message:
        :param serialized_private_key:
        :return:
        """
        private_key = serialization.load_pem_private_key(
            serialized_private_key,
            password=None,
            backend=default_backend()
        )
        message_after_decryption = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        self.decrypted_text = message_after_decryption
        print('Message decrypted successfully')
        return self.decrypted_text

    def hashing(self) -> bytes:
        """

        :return:
        """

        hash_obj = hashlib.sha256()
        hash_obj.update(self.plain_text)
        self.hashing_text = hash_obj.digest()
        print('Hashing generated successfully')
        return self.hashing_text

    def integrity_verification(self, decrypted_message, hashing) -> bool:
        """
        Function that test integrity of hashing
        :return: Return True if hashing of decrypted message and the hashing of the message is the same.
        """
        hash_obj = hashlib.sha256()
        hash_obj.update(decrypted_message)

        if hashing == hash_obj.digest():
            return True
        else:
            return False

