from basisclasses.secure_file_transfer import SecureFileTransfer
from google.cloud import firestore

import streamlit as st
import os

def main() -> None:
    # Authenticate to Firestore with the JSON account key.
    db = firestore.Client.from_service_account_json("firestore_key.json")
    # Create a reference to the Google post.
    doc_ref = db.collection("secure_file_transfer").document("secure_file")
    # Then get the data at that reference.
    doc = doc_ref.get()

    st.header('Secure File Transfer with RSA and Hashing')
    st.markdown('''
                :red[RSA] :gray[and] :orange[Hashing] :green[with] :blue[Python]
                ''')
    st.markdown(" :tulip::cherry_blossom::rose::hibiscus::sunflower::blossom:")
    uploaded_file = st.file_uploader("Choose a file for encrypt")

    if uploaded_file is not None:
        st.markdown('''
                    :rainbow[File imported successfully]
                    ''')
        st.text_area(':orange[Message preview]',
                     uploaded_file.getvalue(),
                     )
        plain_text = SecureFileTransfer(plain_text=uploaded_file.getvalue())
        st.divider()
        col1, col2 = st.columns(2)
        with col1:
            button1 = st.button('Generated Private Key')
            if button1:
                serialize_rsa_private_key = plain_text.serialize_rsa_private_key()
                st.text_area('', serialize_rsa_private_key)
                st.write(':orange[Private key generated successful!]')
                st.write(':blue[Would you like to download?]')
                doc_ref.set({
                    "private_key": serialize_rsa_private_key
                })
                # with open(os.path.join(os.getcwd(), "messages/encrypted_message"), "rb") as encrypted_message_file:
                    # encrypted_message_read = encrypted_message_file.read()
                    # st.download_button('Download', encrypted_message_read)
        with col2:
            button2 = st.button('Generated Public Key')
            if button2:
                serialize_rsa_public_key = plain_text.serialize_rsa_public_key()
                st.text_area('', serialize_rsa_public_key)
                st.write(':orange[Public key generated successful!]')
                st.write(':blue[Would you like to download?]')
                doc_ref.update({
                    "public_key": serialize_rsa_public_key
                })
                # with open(os.path.join(os.getcwd(), "messages/hashing.txt"), "rb") as hashing_message_file:
                     # hashing_message_read = hashing_message_file.read()
                     # st.download_button('Download', hashing_message_read)

        st.divider()
        st.subheader("Would you like to encrypt or generating a hash?")
        col3, col4 = st.columns(2)
        with col3:
            button3 = st.button('Encryption')
            if button3:
                encrypted = plain_text.encryption(serialized_public_key=doc.get('public_key'))
                st.text_area('', encrypted)
                st.write(':orange[Message encrypted successful!]')
                st.write(':blue[Would you like to download?]')
                doc_ref.update({
                    "encrypted": encrypted
                })
                # with open(os.path.join(os.getcwd(), "messages/encrypted_message"), "rb") as encrypted_message_file:
                #    encrypted_message_read = encrypted_message_file.read()
                #    st.download_button('Download', encrypted_message_read)
        with col4:
            button4 = st.button('Hashing')
            if button4:
                hashing = plain_text.hashing()
                st.text_area('', hashing)
                st.write(':orange[Hashing generated successful!]')
                st.write(':blue[Would you like to download?]')
                doc_ref.update({
                    "hashing": hashing
                })
                # with open(os.path.join(os.getcwd(), "messages/hashing.txt"), "rb") as hashing_message_file:
                    # hashing_message_read = hashing_message_file.read()
                    # st.download_button('Download', hashing_message_read)
        st.divider()
        col5, col6 = st.columns(2)
        with col5:
            button5 = st.button('Decryption')
            if button5:
                decryption = plain_text.decryption(encrypted_message=doc.get('encrypted'),
                                                   serialized_private_key=doc.get('private_key')
                                                   )
                st.text_area('', decryption)
                st.write(':orange[Message decrypted successful]')
                st.write(':blue[Would you like to download?]')
                doc_ref.update({
                    "decrypted_message": decryption
                })
                # with open(os.path.join(os.getcwd(), "messages/decrypted_message.txt"), "rb") as decrypted_message_file:
                    # decrypted_message_read = decrypted_message_file.read()
                    # st.download_button('Download', decrypted_message_read)
        with col6:
            button6 = st.button('Integrity verification')
            if button6:
                if plain_text.integrity_verification(decrypted_message=doc.get('decrypted_message'),
                                                     hashing=doc.get('hashing')) is True:
                    st.write('File received and verified successfully')
                else:
                    st.write('File verification failed')



if __name__ == "__main__":
    main()