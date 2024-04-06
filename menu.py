from basisclasses.secure_file_transfer import SecureFileTransfer

import streamlit as st
import os

st.header('Secure File Transfer With RSA and Hashing')
st.markdown('''
    :red[RSA] :gray[and] :orange[Hashing] :green[with] :blue[Python]
     ''')
st.markdown(" :tulip::cherry_blossom::rose::hibiscus::sunflower::blossom:")

uploaded_file = st.file_uploader("Choose a file for encrypt")

if uploaded_file is not None:
    instantiated_file_transfer = SecureFileTransfer(file=uploaded_file.name)
    st.markdown('''
        :rainbow[File imported successfully]
        ''')
    st.divider()
    st.text_area('',
                 "What would you like to do?")
    with open(os.path.join('tempDir', instantiated_file_transfer.file), "rb") as file:
        read_message = file.read()
        col1, col2 = st.columns(2)
        with col1:
            button1 = st.button('Encryption')
            if button1:
                instantiated_file_transfer.encryption(read_message)
                st.write('RSA keys generated successful!')
                st.write('Message encrypted successful!')

                st.write('Would you like to downloaded')
                with open(os.path.join(os.getcwd(), "messages/encrypted_message"), "rb") as encrypted_message_file:
                    encrypted_message_read = encrypted_message_file.read()
                    st.download_button('Download', encrypted_message_read)
        with col2:
            button2 = st.button('Hashing')
            if button2:
                instantiated_file_transfer.hashing(read_message)
                st.write('Hashing generated successful!')
                st.write('Would you like to downloaded')
                with open(os.path.join(os.getcwd(), "messages/hashing.txt"), "rb") as hashing_message_file:
                    hashing_message_read = hashing_message_file.read()
                    st.download_button('Download', hashing_message_read)
        st.divider()
        col3, col4 = st.columns(2)
        with col3:
            button3 = st.button('Decryption')
            if button3:
                instantiated_file_transfer.decryption(os.path.join(os.getcwd(), 'messages/encrypted_message'))
                st.write('Message decrypted successful')
                st.write('Would you like to downloaded')

                with open(os.path.join(os.getcwd(), "messages/decrypted_message.txt"), "rb") as decrypted_message_file:
                    decrypted_message_read = decrypted_message_file.read()
                    st.download_button('Download', decrypted_message_read)
        with col4:
            button4 = st.button('Integrity verification')
            if button4:
                if instantiated_file_transfer.integrity_verification() is True:
                    st.write('File received and verified successfully')
                else:
                    st.write('File verification failed')
