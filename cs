[33mcommit 5546c01389886fe35e58bca3b083aca45111ce79[m
Author: Viviane <vivialves.v@gmail.com>
Date:   Sat Apr 6 14:50:26 2024 -0400

    update database

[1mdiff --git a/basisclasses/secure_file_transfer.py b/basisclasses/secure_file_transfer.py[m
[1mindex c2bb984..03eda0d 100644[m
[1m--- a/basisclasses/secure_file_transfer.py[m
[1m+++ b/basisclasses/secure_file_transfer.py[m
[36m@@ -7,145 +7,154 @@[m [mfrom cryptography.hazmat.primitives.asymmetric import padding[m
 import hashlib[m
 import os[m
 [m
[32m+[m
 class SecureFileTransfer:[m
 [m
[31m-    def __init__(self: object, file: str) -> None:[m
[31m-        self.file = file[m
[32m+[m[32m    def __init__(self: object,[m
[32m+[m[32m                 plain_text: str,[m
[32m+[m[32m                 private_key: bytes = 'default',[m
[32m+[m[32m                 public_key: bytes = 'default',[m
[32m+[m[32m                 encrypted_text: bytes = 'default',[m
[32m+[m[32m                 decrypted_text: bytes = 'default',[m
[32m+[m[32m                 hashing_text: bytes = 'default'[m
[32m+[m[32m                 ) -> None:[m
[32m+[m
[32m+[m[32m        self.plain_text = plain_text[m
[32m+[m[32m        self.private_key = private_key[m
[32m+[m[32m        self.public_key = public_key[m
[32m+[m[32m        self.encrypted_text = encrypted_text[m
[32m+[m[32m        self.decrypted_text = decrypted_text[m
[32m+[m[32m        self.hashing_text = hashing_text[m
 [m
     def generate_rsa_keys(self) -> tuple:[m
         """[m
 [m
         :return:[m
         """[m
[31m-        private_key = rsa.generate_private_key([m
[32m+[m[32m        private_key_ = rsa.generate_private_key([m
             public_exponent=65537,[m
             key_size=2048,[m
             backend=default_backend()[m
         )[m
[31m-        public_key = private_key.public_key()[m
[31m-        return private_key, public_key[m
[32m+[m[32m        public_key_ = private_key_.public_key()[m
[32m+[m[32m        return private_key_, public_key_[m
 [m
[31m-    def serialize_rsa_keys(self) -> None:[m
[32m+[m[32m    def serialize_rsa_private_key(self) -> bytes:[m
         """[m
 [m
         :return:[m
         """[m
[31m-        private_key, public_key = self.generate_rsa_keys()[m
[32m+[m[32m        private_key_, public_key_ = self.generate_rsa_keys()[m
 [m
[31m-        serialize_private_key = private_key.private_bytes([m
[32m+[m[32m        serialize_private_key = private_key_.private_bytes([m
             encoding=serialization.Encoding.PEM,[m
             format=serialization.PrivateFormat.PKCS8,[m
             encryption_algorithm=serialization.NoEncryption()[m
         )[m
[32m+[m[32m        self.private_key = serialize_private_key[m
[32m+[m[32m        # with open(os.path.join(os.getcwd(), "rsa_keys/serialize_private_key.pem"), "wb") as serialize_private_key_file:[m
[32m+[m[32m            # serialize_private_key_file.write(serialize_private_key)[m
[32m+[m
[32m+[m[32m        print('Private key generated successfully')[m
[32m+[m[32m        return self.private_key[m
 [m
[31m-        with open(os.path.join(os.getcwd(), "rsa_keys/serialize_private_key.pem"), "wb") as serialize_private_key_file:[m
[31m-            serialize_private_key_file.write(serialize_private_key)[m
[32m+[m[32m    def serialize_rsa_public_key(self) -> bytes:[m
[32m+[m[32m        """[m
 [m
[31m-        serialize_public_key = public_key.public_bytes([m
[32m+[m[32m        :return:[m
[32m+[m[32m        """[m
[32m+[m[32m        private_key_, public_key_ = self.generate_rsa_keys()[m
[32m+[m[32m        serialize_public_key = public_key_.public_bytes([m
             encoding=serialization.Encoding.PEM,[m
             format=serialization.PublicFormat.SubjectPublicKeyInfo[m
         )[m
[32m+[m[32m        self.public_key = serialize_public_key[m
[32m+[m[32m        # with open(os.path.join(os.getcwd(), "rsa_keys/serialize_public_key.pem"), "wb") as serialize_public_key_file:[m
[32m+[m[32m            # serialize_public_key_file.write(serialize_public_key)[m
[32m+[m[32m        print('Public key generated successfully')[m
[32m+[m[32m        return self.public_key[m
 [m
[31m-        with open(os.path.join(os.getcwd(), "rsa_keys/serialize_public_key.pem"), "wb") as serialize_public_key_file:[m
[31m-            serialize_public_key_file.write(serialize_public_key)[m
[31m-[m
[31m-        print('RSA keys generated successful')[m
[31m-[m
[31m-    def encryption(self, message: bytes) -> bytes:[m
[32m+[m[32m    def encryption(self) -> bytes:[m
         """[m
 [m
[31m-        :param message:[m
         :return:[m
         """[m
[32m+[m[32m        # serial_public_key = self.serialize_rsa_public_key()[m
 [m
[31m-        self.serialize_rsa_keys()[m
[31m-[m
[31m-        with open(os.path.join(os.getcwd(), "rsa_keys/serialize_public_key.pem"), "rb") as public_key_file:[m
[31m-            serialized_public_key = public_key_file.read()[m
[31m-[m
[32m+[m[32m        # with open(os.path.join(os.getcwd(), "rsa_keys/serialize_public_key.pem"), "rb") as public_key_file:[m
[32m+[m[32m            # serialized_public_key = public_key_file.read()[m
[32m+[m[32m        print(self.public_key)[m
         public_key = serialization.load_pem_public_key([m
[31m-            serialized_public_key,[m
[32m+[m[32m            self.public_key,[m
             backend=default_backend()[m
         )[m
[31m-[m
         encrypted = public_key.encrypt([m
[31m-            message,[m
[32m+[m[32m            self.plain_text,[m
             padding.OAEP([m
                 mgf=padding.MGF1(algorithm=hashes.SHA256()),[m
                 algorithm=hashes.SHA256(),[m
                 label=None[m
             )[m
         )[m
[31m-[m
[31m-        with open(os.path.join(os.getcwd(), "messages/encrypted_message"), "wb") as encrypted_message_file:[m
[31m-            encrypted_message_file.write(encrypted)[m
[31m-[m
[32m+[m[32m        # with open(os.path.join(os.getcwd(), "messages/encrypted_message"), "wb") as encrypted_message_file:[m
[32m+[m[32m            # encrypted_message_file.write(encrypted)[m
[32m+[m[32m        self.encrypted_text = encrypted[m
         print('Message encrypted successful')[m
[32m+[m[32m        return self.encrypted_text[m
 [m
[31m-        return encrypted[m
[31m-[m
[31m-    def decryption(self, encrypted_message: str) -> None:[m
[32m+[m[32m    def decryption(self) -> None:[m
         """[m
 [m
[31m-        :param encrypted_message:[m
         :return:[m
         """[m
 [m
[31m-        with open(os.path.join(os.getcwd(), "rsa_keys/serialize_private_key.pem"), "rb") as private_key_file:[m
[31m-            serialized_private_key = private_key_file.read()[m
[32m+[m[32m        # with open(os.path.join(os.getcwd(), "rsa_keys/serialize_private_key.pem"), "rb") as private_key_file:[m
[32m+[m[32m            # serialized_private_key = private_key_file.read()[m
 [m
[31m-        with open(encrypted_message, "rb") as encrypted_message_file:[m
[31m-            encrypted_message_ = encrypted_message_file.read()[m
[32m+[m[32m        # with open(encrypted_message, "rb") as encrypted_message_file:[m
[32m+[m[32m            # encrypted_message_ = encrypted_message_file.read()[m
 [m
         private_key = serialization.load_pem_private_key([m
[31m-            serialized_private_key,[m
[32m+[m[32m            self.private_key,[m
             password=None,[m
             backend=default_backend()[m
         )[m
[31m-[m
[31m-        original_message = private_key.decrypt([m
[31m-            encrypted_message_,[m
[32m+[m[32m        message_after_decryption = private_key.decrypt([m
[32m+[m[32m            self.encrypted_text,[m
             padding.OAEP([m
                 mgf=padding.MGF1(algorithm=hashes.SHA256()),[m
                 algorithm=hashes.SHA256(),[m
                 label=None[m
             )[m
         )[m
[31m-[m
[31m-        with open(os.path.join(os.getcwd(), "messages/decrypted_message.txt"), "wb") as encrypted_message_file:[m
[31m-            encrypted_message_file.write(original_message)[m
[31m-[m
[32m+[m[32m        self.decrypted_text = message_after_decryption[m
[32m+[m[32m        # with open(os.path.join(os.getcwd(), "messages/decrypted_message.txt"), "wb") as encrypted_message_file:[m
[32m+[m[32m            # encrypted_message_file.write(original_message)[m
         print('Message decrypted successful')[m
[32m+[m[32m        return self.decrypted_text[m
 [m
[31m-    def hashing(self, message) -> hash:[m
[32m+[m[32m    def hashing(self) -> bytes:[m
         """[m
 [m
[31m-        :param message:[m
         :return:[m
         """[m
[31m-[m
         hash_obj = hashlib.sha256()[m
[31m-        hash_obj.update(message)[m
[31m-[m
[31m-        with open(os.path.join(os.getcwd(), "messages/hashing.txt"), "wb") as hashing_message_file:[m
[31m-            hashing_message_file.write(hash_obj.digest())[m
[31m-[m
[32m+[m[32m        hash_obj.update(self.plain_text)[m
[32m+[m[32m        self.hashing_text = hash_obj.digest()[m
[32m+[m[32m        # with open(os.path.join(os.getcwd(), "messages/hashing.txt"), "wb") as hashing_message_file:[m
[32m+[m[32m            # hashing_message_file.write(hash_obj.digest())[m
         print('Hashing generated successful')[m
[31m-[m
[31m-        return hash_obj.digest()[m
[32m+[m[32m        return self.hashing_text[m
 [m
     def integrity_verification(self) -> bool:[m
         """[m
 [m
         :return:[m
         """[m
[31m-[m
         with open(os.path.join(os.getcwd(), "messages/hashing.txt"), "rb") as hashing_file:[m
             hashing_read = hashing_file.read()[m
[31m-[m
         with open(os.path.join(os.getcwd(), "messages/decrypted_message.txt"), "rb") as decrypted_message_file:[m
             decrypted_message_read = decrypted_message_file.read()[m
[31m-[m
         hash_obj = hashlib.sha256()[m
         hash_obj.update(decrypted_message_read)[m
 [m
[1mdiff --git a/firestore_key.json b/firestore_key.json[m
[1mnew file mode 100644[m
[1mindex 0000000..add3871[m
[1m--- /dev/null[m
[1m+++ b/firestore_key.json[m
[36m@@ -0,0 +1,13 @@[m
[32m+[m[32m{[m
[32m+[m[32m  "type": "service_account",[m
[32m+[m[32m  "project_id": "dadoscnj",[m
[32m+[m[32m  "private_key_id": "1b224966154fbc9ba76d83e2a0212d1865e3d1e8",[m
[32m+[m[32m  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCqS5+dyAEY7fZF\nHJd2cnpmRy9ghsOSEqlsW+P20Zzw9TawbZZZA4vKSDpeEz8Rgo2/acrG+wlxHi+n\nB74uHPvWh7VX7zLTKKb9slpFBt2KzUSJDazhCUkegc1MGAlsWpwcR26X7j5rHOWI\n6+cI/OFkNUkJNgEzBReLbtu17Ag6ZpnQhZtUGc8f8jdhfGjULdLgfjjmFvbDqiIW\nGZJlQqtb6x2XoF9A+AEhy/he0/DRpSuDYiq5K8zJRpR3JSfaTUkUxFtsmIpcwafm\nb8V99eq67xWxfVMMqf+4UsY484K9IakPTnXvm7hLF/J+63TFf0W35Y4cet22n9uH\ngncZe6BHAgMBAAECggEACvwo1jE2HOkQt0GSZaIZ0ioqXLQkvnH0utgsmtnHoWV3\n+yZ+icxoQoqpNTNRoKwGv7+vxGkiIUlcso4VzvywpBSJ9pun8CYRq5DLMOOx+8ek\n8aBPtA54yH6AAzYTuYkYw9w5vpQwM5GgHtZ0x0gks+WaCf2RUzyzWZuzkYchur6T\nXejW2/HMAJ1YhhSfnnvix8PL6Qfqp6x1yxqS5e/rgZ/Vmza3Usq2MgtlQcIYN61N\nh/kUnYcRIE8NA56iXtqSe7EAJgYH6ZUiG+0CFjMro0N6TV3+ZEBTJpLgg0a3aoxK\nT/Gbym+0vSAPtf2Nx8j1dTXfZ1p34n/vbJ/z+1JnMQKBgQDwZRrv81gkbzU2iNBu\nbuKygLBC3+kU6Qc6z8DRCShdeODW3DauhyZWInbFffBfqFNwxCLJXCQDHI9DAJnG\nMiy2a8yYIVVSHx7mHxH/WS0P/G/xZ4qDhGVyTO8M4vCCLNDuZNIe3BdN90ceylpL\nK2vdUXb8jXK2vm/s0FaP6zk68QKBgQC1WZnLwhc0hVv0QVVugUzd2C9axPDUpbva\nvGDPIrTv5sYjD87oQU+IvM6BE7wOSKAbQaXdpdZ8abNFjbK2jou8hLniaxLmZIKH\nlLwHSgqJgyzXom7X/sr2TvT2RrUdnVKGJluI8PhmR8b3Xp9JMQby6VVuVO+sWIMk\nD8Wtos5etwKBgBsAMCtdWLwW5ZIvgcG1oK7N9347ahGYLuCzLwQLlEYTaqWXbGjj\n8zFfg5mhEJud62lSDloxiDX1Qj4TVjJFtnHy37MCo3Oq3SyZtsrIeGBASU6DA7LL\n7x0MeRkocD0ezYTJPDSNIez25j0WG1gwE1hzavro5EaUUzv1FpPppq7xAoGATzFY\nivUwAvx1ol1hfEc0lPASBdZYwNO7DBMVR38FennRboA5v4y9uZ2RpCZFCgvG9wAc\n+YSw/FWANtBhCX2IIgPn1Ksjbr7XjXNzBM/deB1zWJsTQnl+kj76lA1ejBcmcXSQ\npmVsY+XWSjHk5yZkvXENoIewvhdM9VN55JBjBFMCgYASwZuhN6DAW4r0HFl+P+AG\npU1ajL1XR4kmB/s9j7BYxnWqUykAsNoziebgysZpQRAbMhkCNL7NRVJNB57eDMN2\naH6YSD2FAAHjeAvrl7FUHhoD/EgGWynERzgjtqF7qBlz5EiQy3Cf/ern6YC4I4hz\n310xM5ur8vYUhDuNn557kA==\n-----END PRIVATE KEY-----\n",[m
[32m+[m[32m  "client_email": "firebase-adminsdk-66reh@dadoscnj.iam.gserviceaccount.com",[m
[32m+[m[32m  "client_id": "103144589835849315195",[m
[32m+[m[32m  "auth_uri": "https://accounts.google.com/o/oauth2/auth",[m
[32m+[m[32m  "token_uri": "https://oauth2.googleapis.com/token",[m
[32m+[m[32m  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",[m
[32m+[m[32m  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-66reh%40dadoscnj.iam.gserviceaccount.com",[m
[32m+[m[32m  "universe_domain": "googleapis.com"[m
[32m+[m[32m}[m
[1mdiff --git a/menu.py b/menu.py[m
[1mindex 1dea210..8114629 100644[m
[1m--- a/menu.py[m
[1m+++ b/menu.py[m
[36m@@ -1,63 +1,116 @@[m
 from basisclasses.secure_file_transfer import SecureFileTransfer[m
[32m+[m[32mfrom google.cloud import firestore[m
 [m
 import streamlit as st[m
 import os[m
 [m
[31m-st.header('Secure File Transfer With RSA and Hashing')[m
[31m-st.markdown('''[m
[31m-    :red[RSA] :gray[and] :orange[Hashing] :green[with] :blue[Python][m
[31m-     ''')[m
[31m-st.markdown(" :tulip::cherry_blossom::rose::hibiscus::sunflower::blossom:")[m
 [m
[31m-uploaded_file = st.file_uploader("Choose a file for encrypt")[m
[32m+[m[32mdef main() -> None:[m
[32m+[m[32m    # Authenticate to Firestore with the JSON account key.[m
[32m+[m[32m    db = firestore.Client.from_service_account_json("firestore_key.json")[m
[32m+[m[32m    # Create a reference to the Google post.[m
[32m+[m[32m    doc_ref = db.collection("secure_file_transfer").document("secure_file")[m
[32m+[m[32m    # Then get the data at that reference.[m
[32m+[m[32m    doc = doc_ref.get()[m
[32m+[m[32m    # Let's see what we got![m
[32m+[m[32m    st.write("The id is: ", doc.id)[m
[32m+[m[32m    st.write("The contents are: ", doc.to_dict())[m
 [m
[31m-if uploaded_file is not None:[m
[31m-    instantiated_file_transfer = SecureFileTransfer(file=uploaded_file.name)[m
[32m+[m
[32m+[m[32m    st.header('Secure File Transfer with RSA and Hashing')[m
     st.markdown('''[m
[31m-        :rainbow[File imported successfully][m
[31m-        ''')[m
[31m-    st.divider()[m
[31m-    st.text_area('',[m
[31m-                 "What would you like to do?")[m
[31m-    with open(os.path.join(instantiated_file_transfer.file), "rb") as file:[m
[31m-        read_message = file.read()[m
[32m+[m[32m        :red[RSA] :gray[and] :orange[Hashing] :green[with] :blue[Python][m
[32m+[m[32m         ''')[m
[32m+[m[32m    st.markdown(" :tulip::cherry_blossom::rose::hibiscus::sunflower::blossom:")[m
[32m+[m
[32m+[m[32m    uploaded_file = st.file_uploader("Choose a file for encrypt")[m
[32m+[m
[32m+[m[32m    if uploaded_file is not None:[m
[32m+[m[32m        st.markdown('''[m
[32m+[m[32m                :rainbow[File imported successfully][m
[32m+[m[32m                ''')[m
[32m+[m[32m        st.text_area(':orange[Message preview]',[m
[32m+[m[32m                     uploaded_file.getvalue(),[m
[32m+[m[32m                     )[m
[32m+[m[32m        plain_text = SecureFileTransfer(plain_text=uploaded_file.getvalue())[m
[32m+[m[32m        st.divider()[m
         col1, col2 = st.columns(2)[m
         with col1:[m
[31m-            button1 = st.button('Encryption')[m
[32m+[m[32m            button1 = st.button('Generated Private Key')[m
             if button1:[m
[31m-                instantiated_file_transfer.encryption(read_message)[m
[31m-                st.write('RSA keys generated successful!')[m
[31m-                st.write('Message encrypted successful!')[m
[31m-[m
[31m-                st.write('Would you like to downloaded')[m
[32m+[m[32m                serialize_rsa_private_key = plain_text.serialize_rsa_private_key()[m
[32m+[m[32m                st.text_area('', serialize_rsa_private_key)[m
[32m+[m[32m                st.write(':orange[Private key generated successful!]')[m
[32m+[m[32m                st.write(':blue[Would you like to download?]')[m
[32m+[m[32m                doc_ref.set({[m
[32m+[m[32m                    "private_key": serialize_rsa_private_key[m
[32m+[m[32m                })[m
                 with open(os.path.join(os.getcwd(), "messages/encrypted_message"), "rb") as encrypted_message_file:[m
                     encrypted_message_read = encrypted_message_file.read()[m
                     st.download_button('Download', encrypted_message_read)[m
         with col2:[m
[31m-            button2 = st.button('Hashing')[m
[32m+[m[32m            button2 = st.button('Generated Public Key')[m
             if button2:[m
[31m-                instantiated_file_transfer.hashing(read_message)[m
[31m-                st.write('Hashing generated successful!')[m
[31m-                st.write('Would you like to downloaded')[m
[32m+[m[32m                serialize_rsa_public_key = plain_text.serialize_rsa_public_key()[m
[32m+[m[32m                st.text_area('', serialize_rsa_public_key)[m
[32m+[m[32m                st.write(':orange[Public key generated successful!]')[m
[32m+[m[32m                st.write(':blue[Would you like to download?]')[m
[32m+[m[32m                doc_ref.update({[m
[32m+[m[32m                    "public_key": serialize_rsa_public_key[m
[32m+[m[32m                })[m
                 with open(os.path.join(os.getcwd(), "messages/hashing.txt"), "rb") as hashing_message_file:[m
                     hashing_message_read = hashing_message_file.read()[m
                     st.download_button('Download', hashing_message_read)[m
[32m+[m
         st.divider()[m
[32m+[m[32m        st.subheader("Would you like to encrypt or generating a hash?")[m
         col3, col4 = st.columns(2)[m
         with col3:[m
[31m-            button3 = st.button('Decryption')[m
[32m+[m[32m            button3 = st.button('Encryption')[m
             if button3:[m
[31m-                instantiated_file_transfer.decryption(os.path.join(os.getcwd(), 'messages/encrypted_message'))[m
[31m-                st.write('Message decrypted successful')[m
[31m-                st.write('Would you like to downloaded')[m
[31m-[m
[32m+[m[32m                encrypted = plain_text.encryption()[m
[32m+[m[32m                st.text_area('', encrypted)[m
[32m+[m[32m                st.write(':orange[Message encrypted successful!]')[m
[32m+[m[32m                st.write(':blue[Would you like to download?]')[m
[32m+[m[32m                doc_ref.update({[m
[32m+[m[32m                    "encrypted": encrypted[m
[32m+[m[32m                })[m
[32m+[m[32m                with open(os.path.join(os.getcwd(), "messages/encrypted_message"), "rb") as encrypted_message_file:[m
[32m+[m[32m                    encrypted_message_read = encrypted_message_file.read()[m
[32m+[m[32m                    st.download_button('Download', encrypted_message_read)[m
[32m+[m[32m        with col4:[m
[32m+[m[32m            button4 = st.button('Hashing')[m
[32m+[m[32m            if button4:[m
[32m+[m[32m                hashing = plain_text.hashing()[m
[32m+[m[32m                st.text_area('', hashing)[m
[32m+[m[32m                st.write(':orange[Hashing generated successful!]')[m
[32m+[m[32m                st.write(':blue[Would you like to download?]')[m
[32m+[m[32m                doc_ref.update({[m
[32m+[m[32m                    "hashing": hashing[m
[32m+[m[32m                })[m
[32m+[m[32m                with open(os.path.join(os.getcwd(), "messages/hashing.txt"), "rb") as hashing_message_file:[m
[32m+[m[32m                    hashing_message_read = hashing_message_file.read()[m
[32m+[m[32m                    st.download_button('Download', hashing_message_read)[m
[32m+[m[32m        st.divider()[m
[32m+[m[32m        col5, col6 = st.columns(2)[m
[32m+[m[32m        with col5:[m
[32m+[m[32m            button5 = st.button('Decryption')[m
[32m+[m[32m            if button5:[m
[32m+[m[32m                decryption = plain_text.decryption()[m
[32m+[m[32m                st.text_area('', decryption)[m
[32m+[m[32m                st.write(':orange[Message decrypted successful]')[m
[32m+[m[32m                st.write(':blue[Would you like to download?]')[m
                 with open(os.path.join(os.getcwd(), "messages/decrypted_message.txt"), "rb") as decrypted_message_file:[m
                     decrypted_message_read = decrypted_message_file.read()[m
                     st.download_button('Download', decrypted_message_read)[m
[31m-        with col4:[m
[31m-            button4 = st.button('Integrity verification')[m
[31m-            if button4:[m
[31m-                if instantiated_file_transfer.integrity_verification() is True:[m
[32m+[m[32m        with col6:[m
[32m+[m[32m            button6 = st.button('Integrity verification')[m
[32m+[m[32m            if button6:[m
[32m+[m[32m                if plain_text.integrity_verification() is True:[m
                     st.write('File received and verified successfully')[m
                 else:[m
                     st.write('File verification failed')[m
[32m+[m
[32m+[m
[32m+[m[32mif __name__ == "__main__":[m
[32m+[m[32m    main()[m
[1mdiff --git a/requirements.txt b/requirements.txt[m
[1mindex fd3c151..f80893c 100644[m
[1m--- a/requirements.txt[m
[1m+++ b/requirements.txt[m
[36m@@ -1,2 +1,3 @@[m
 streamlit[m
[31m-cryptography[m
\ No newline at end of file[m
[32m+[m[32mcryptography[m
[32m+[m[32mgoogle-cloud-firestore[m
\ No newline at end of file[m
