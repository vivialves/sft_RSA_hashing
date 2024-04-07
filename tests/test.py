import unittest
import hashlib

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from sft_RSA_hashing.basisclasses.secure_file_transfer import SecureFileTransfer


class MyTestCase(unittest.TestCase):

    def test_serialize_rsa_private_key(self):
        serialize_private_key = SecureFileTransfer.private_key_nopem.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        function_test = SecureFileTransfer.serialize_rsa_private_key(self)
        self.assertEqual(serialize_private_key, function_test)

    def test_serialize_rsa_public_key(self):
        serialize_public_key = SecureFileTransfer.public_key_nopem.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        function_test = SecureFileTransfer.serialize_rsa_public_key(self)
        self.assertEqual(serialize_public_key, function_test)

    def test_encryption(self):
        enconde_text = 'message_test'.encode()

        serialize_public_key = SecureFileTransfer.public_key_nopem.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_key = serialization.load_pem_public_key(
            serialize_public_key,
            backend=default_backend()
        )
        encrypted = public_key.encrypt(
            enconde_text,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            ))

        function_test = SecureFileTransfer.encryption(self, serialize_public_key)
        self.assertEqual(encrypted, function_test)


    def test_decryption(self):
        enconde_text = 'message_test'.encode()

        serialize_public_key = SecureFileTransfer.public_key_nopem.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_key = serialization.load_pem_public_key(
            serialize_public_key,
            backend=default_backend()
        )
        encrypted_message = public_key.encrypt(
            enconde_text,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            ))
        serialize_private_key = SecureFileTransfer.private_key_nopem.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        private_key = serialization.load_pem_private_key(
            serialize_private_key,
            password=None,
            backend=default_backend()
        )
        message_after_decryption = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            ))

        function_test = SecureFileTransfer.decryption(self, encrypted_message, serialize_private_key)
        self.assertEqual(message_after_decryption, function_test)

    def test_hashing(self):
        hash_obj = hashlib.sha256()
        enconde_text = 'message_test'.encode()
        hash_obj.update(enconde_text)
        hash_test = hash_obj.digest()
        test_function = SecureFileTransfer.hashing(self)
        self.assertEqual(test_function, hash_test)

    def test_integrity_verification_true(self):
        encode_text_encryption = 'message_test'.encode()

        serialize_public_key = SecureFileTransfer.public_key_nopem.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_key = serialization.load_pem_public_key(
            serialize_public_key,
            backend=default_backend()
        )
        encrypted_message = public_key.encrypt(
            encode_text_encryption,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            ))
        serialize_private_key = SecureFileTransfer.private_key_nopem.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        private_key = serialization.load_pem_private_key(
            serialize_private_key,
            password=None,
            backend=default_backend()
        )
        message_after_decryption = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            ))
        hash_obj = hashlib.sha256()
        encode_text_hashing = 'message_test'.encode()
        hash_obj.update(encode_text_hashing)
        hash_test = hash_obj.digest()
        test_function = SecureFileTransfer.integrity_verification(self, message_after_decryption, hash_test)
        self.assertEqual(True, test_function)

    def test_integrity_verification_false_encode(self):
        encode_text_encryption = 'mes_test'.encode()

        serialize_public_key = SecureFileTransfer.public_key_nopem.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_key = serialization.load_pem_public_key(
            serialize_public_key,
            backend=default_backend()
        )
        encrypted_message = public_key.encrypt(
            encode_text_encryption,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            ))
        serialize_private_key = SecureFileTransfer.private_key_nopem.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        private_key = serialization.load_pem_private_key(
            serialize_private_key,
            password=None,
            backend=default_backend()
        )
        message_after_decryption = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            ))
        hash_obj = hashlib.sha256()
        encode_text_hashing = 'message_test'.encode()
        hash_obj.update(encode_text_hashing)
        hash_test = hash_obj.digest()
        test_function = SecureFileTransfer.integrity_verification(self, message_after_decryption, hash_test)
        self.assertEqual(False, test_function)

    def test_integrity_verification_false_encode(self):
        encode_text_encryption = 'message_test'.encode()

        serialize_public_key = SecureFileTransfer.public_key_nopem.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_key = serialization.load_pem_public_key(
            serialize_public_key,
            backend=default_backend()
        )
        encrypted_message = public_key.encrypt(
            encode_text_encryption,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            ))
        serialize_private_key = SecureFileTransfer.private_key_nopem.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        private_key = serialization.load_pem_private_key(
            serialize_private_key,
            password=None,
            backend=default_backend()
        )
        message_after_decryption = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            ))
        hash_obj = hashlib.sha256()
        encode_text_hashing = 'mess_test'.encode()
        hash_obj.update(encode_text_hashing)
        hash_test = hash_obj.digest()
        test_function = SecureFileTransfer.integrity_verification(self, message_after_decryption, hash_test)
        self.assertEqual(False, test_function)


if __name__ == '__main__':
    unittest.main()
