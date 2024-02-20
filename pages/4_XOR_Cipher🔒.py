import streamlit as st

st.header("XOR Cipher🔒🔑")

def xor_encrypt(plaintext, key):
    """Encrypts plaintext using XOR cipher with the given key, printing bits involved."""
    ciphertext = bytearray()
    for i in range(len(plaintext)):
        plaintext_byte = plaintext[i]
        key_byte = key[i % len(key)]
        # st.write(f"key_byte {key_byte}")
        # st.write bits before XOR
        st.write(f"Plaintext byte: {format(plaintext_byte, '08b')} = {chr(plaintext_byte)}")
        st.write(f"Key byte:       {format(key_byte, '08b')} = {chr(key_byte)}")

        # Perform XOR and st.write result
        cipher_byte = plaintext_byte ^ key_byte
        st.write(f"XOR result:     {format(cipher_byte, '08b')} = {chr(cipher_byte)}")
        st.write("-" * 20)  # Separator for clarity

        ciphertext.append(cipher_byte)
    return ciphertext

def xor_decrypt(ciphertext, key):
    """Decrypts ciphertext using XOR cipher with the given key."""
    return xor_encrypt(ciphertext, key)  # XOR decryption is the same as encryption


plaintext = bytes(st.text_area("Plain Text:").encode())
key = bytes(st.text_input("Key:").encode())

if st.button("Submit"):
    if not key:
        st.error("Invalid key")
    else:
        if plaintext != key:
            if len(plaintext.decode()) >= len(key.decode()):
                ciphertext = xor_encrypt(plaintext, key)
                st.write("Ciphertext:", ciphertext.decode())

                decrypted = xor_decrypt(ciphertext, key)
                st.write("Decrypted:", decrypted.decode())
            else:
                st.write(f"Plaintext length should be equal or greater than the length of key")

        else:
            st.write(f"Plaintext should not be equal to the key")
    st.balloons()

