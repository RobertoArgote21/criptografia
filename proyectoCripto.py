import streamlit as st
import pandas as pd
import time
import hashlib
from Crypto.Cipher import ChaCha20
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
import cryptography.exceptions
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from streamlit_option_menu import option_menu


st.markdown(""" <style> .font {
        font-size:18px ; font-family: 'Courier'; color: ##FFFFFF;} 
        </style> """, unsafe_allow_html=True)
st.title(':red[Proyecto Criptografía]')
st.markdown('<p class="font">Argote Dávalos Roberto Carlos</p>', unsafe_allow_html=True)
st.markdown('<p class="font">Pardo Reyna Anelissa Allizon</p>', unsafe_allow_html=True)

with st.sidebar:
    st.subheader('Universidad Nacional Autónoma de México\n Facultad de Ingeniería 2023-1')
    choose = option_menu("Selecciona un Algoritmo", ["Cifrar/Descifrar", "Hashing", "Signing/Verifying"],
                         icons=['key', 'hash', 'vector-pen'],
                         menu_icon="bezier", default_index=0,
                         styles={
        "container": {"padding": "5!important", "background-color": "#000000"},
        "menu-title": {"font-size": "15px", "text-align": "left"},
        "icon": {"color": "#62B6B7", "font-size": "25px"}, 
        "nav-link": {"font-size": "13px", "text-align": "left", "margin":"0px", "--hover-color": "#82AAE3"},
        "nav-link-selected": {"background-color": "#0D4C92"},
    }
    )
    st.sidebar.info("Contacto\n\nRoberto: davalosroberto21@gmail.com\nAnelissa: anelissareyna@gmail.com")



if choose == "Cifrar/Descifrar":

    vector_test_cd = [
        'NcCmyD8VOvpgyVn2ViQy38O35knGdlKA',
        'pWrhOYwc56cPb12lYqRbhrWE7gFQPC8W',
        'O8hWhaoztWqKbfeyAE5Lxd3gcdhsT1Kg',
        'qifmkyta1qPVAUUO8rbw9HqpIX8iFTwR',
        'nGYwpJynvRObAfSy6PtHdXP0qcNZyBr3',
        '0hB5ffRcL85Spw7wMlX3CnhLLL7vnoUE',
        'xbpvDRBhOMlmfrgso5Gej9aDK43S4XQZ',
        'F7VRyClBGrM4shetS0RA2jsJTh3VxxRC',
        'xdSzepZbcOuR5DmneHV2VAe5nJofD22L',
        'k8cn0MVoSiZhaMogcRT7FWHS3cD1Hh8S',
        'KvhabeQtYIsTC9rNzOKmZXHfKYmqe9fW',
        'QZjuR8NmpPbeeM01QmE9JTT3GDeSopyy',
        'sAUpGmcFUD70nkiMrqxlIJMLNYw7fOOo',
        'TsvCOMvtXi9j4m7nanqjE9xcaeDq2qIb',
        'RJDqoKdMXqTAImidmOPSFKGcYx5XP5di',
        'Y9GpRiCb3aNyrvCI8fmfD6LHydOmL3bk',
        'A0jPZPVITGYJlamuGdSot7AeckkfUUkE',
        'JmgKlHu9gkSP4f7cVk6Xxf5pUu97gqVr',
        'hNXxRE0X7xFx2JGs8gObvYpJdkT1VrPe',
        'a0xtA7oEGBc41UIcKOCWUKN15LVY1Jna'
        ]

    options = st.multiselect(
        'Selecciona los algoritmos a comparar',
        ['AES 256 ECB', 'AES 256 CBC','ChaCha20'])

    button = st.button('Aceptar')

    if (button):
        cifDf = {'Vector' : vector_test_cd}
        desDf = {'Vector' : vector_test_cd}
        plaintext = 'Attack at dawn'
        st.write('Plaintext: ' + plaintext)

        for i in options:
            if i == 'AES 256 ECB':
                cifDf['AES 256 ECB'] = []
                desDf['AES 256 ECB'] = []
                for j in vector_test_cd:
                    #cifrar
                    stm=time.time()

                    cipher = AES.new(j.encode('utf8'), AES.MODE_ECB)
                    ciphertex = cipher.encrypt(pad('1234567891234567'.encode("utf8"),32))

                    time.sleep(0.01)
                    ft=time.time()
                    tiempo=ft-stm
                    tiempo = (tiempo-0.01) * 1000
                    cifDf['AES 256 ECB'].append(tiempo) 
                    
                    #descifrar
                    stm=time.time()

                    decipher = AES.new(j.encode('utf8'), AES.MODE_ECB)
                    msg_dec = decipher.decrypt(ciphertex)

                    time.sleep(0.01)
                    ft=time.time()
                    tiempo=ft-stm
                    tiempo = (tiempo-0.01) * 1000
                    desDf['AES 256 ECB'].append(tiempo)            
            if i == 'AES 256 CBC':
                cifDf['AES 256 CBC'] = []
                desDf['AES 256 CBC'] = []
                for j in vector_test_cd:
                    #cifrar
                    stm=time.time()
                    
                    #key = 'Thirty-two byte (256 bits) keyyy'
                    cipher = AES.new(j.encode('utf8'), AES.MODE_CBC,'asdfghjklqwertyu'.encode('utf8'))
                    ciphertex = cipher.encrypt(pad('Attack at dawn'.encode("utf8"),32))

                    time.sleep(0.01)
                    ft=time.time()
                    tiempo=ft-stm
                    tiempo = (tiempo-0.01) * 1000
                    cifDf['AES 256 CBC'].append(tiempo) 
                    
                    #descifrar
                    stm=time.time()

                    decipher = AES.new(j.encode('utf8'), AES.MODE_ECB)
                    msg_dec = decipher.decrypt(ciphertex)

                    time.sleep(0.01)
                    ft=time.time()
                    tiempo=ft-stm
                    tiempo = (tiempo-0.01) * 1000
                    desDf['AES 256 CBC'].append(tiempo)
            if i == 'ChaCha20':
                cifDf['ChaCha20'] = []
                desDf['ChaCha20'] = []
                plaintextcc20 = b'Attack at dawn'
                for j in vector_test_cd:
                    #cifrar
                    stm=time.time()
                    
                    secret = bytes(j, 'utf-8')
                    cipher = ChaCha20.new(key=secret)
                    msg = cipher.encrypt(plaintextcc20)
                    msg = cipher.nonce + cipher.encrypt(plaintextcc20)

                    time.sleep(0.01)
                    ft=time.time()
                    tiempo=ft-stm
                    tiempo = (tiempo-0.01) * 1000
                    cifDf['ChaCha20'].append(tiempo) 
                    
                    #descifrar
                    stm=time.time()
                    
                    msg_nonce = msg[:8]
                    ciphertext = msg[8:]
                    cipher = ChaCha20.new(key=secret, nonce=msg_nonce)
                    plaintext = cipher.decrypt(ciphertext)

                    time.sleep(0.01)
                    ft=time.time()
                    tiempo=ft-stm
                    tiempo = (tiempo-0.01) * 1000
                    desDf['ChaCha20'].append(tiempo)
            
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("Cifrado")
            st.write('Tabla comparativa de tiempos (en milisegundos) de ejecución:')
            cifDf = pd.DataFrame(cifDf)
            cifDf
            st.write('Gráfica comparativa: ')
            st.bar_chart(cifDf, x='Vector')

            meanTimescif = {}

            for i in options:
                meanTimescif[i] = cifDf[i].mean()

            meanTimescif = pd.DataFrame(list(meanTimescif.items()), columns=['Algoritmo','Tiempo promedio'])

            st.write('Tiempo promedio de los algoritmos')
            meanTimescif

            st.bar_chart(meanTimescif, x='Algoritmo')
        with col2:
            st.subheader("Descifrado")
            st.write('Tabla comparativa de tiempos (en milisegundos) de ejecución:')
            desDf = pd.DataFrame(desDf)
            desDf
            st.write('Gráfica comparativa: ')
            st.bar_chart(desDf, x='Vector')

            meanTimesdes = {}

            for i in options:
                meanTimesdes[i] = desDf[i].mean()

            meanTimesdes = pd.DataFrame(list(meanTimesdes.items()), columns=['Algoritmo','Tiempo promedio'])

            st.write('Tiempo promedio de los algoritmos')
            meanTimesdes

            st.bar_chart(meanTimesdes, x='Algoritmo')

elif choose == "Hashing":
    vector_test_hash=[
        "508eef6956f3a1f414d5e1c72c27650c26183206509410afc80e3ca0d77d5e32",
        "c8488ba83963dc4daedeedfe6425dd33dcc653dc5e109160fa2b5cd6133b4fbb",
        "68a86d02628ce05af2e3a27aab992f7c7f43178aebe7bef016102f3e8386f13b",
        "e1455388ddfedd3a1c4abfbdf93748f43e5772150a55ba4806169bb18f5c402c",
        "9ba027249b94b90f3648aed974f6871fd6015eccd55c4dcff12544b985b725a4",
        "d6061cf580b4edb2bfbf13ea6b268da11c64972f69d53d4c15d945a37b4b24c3",
        "e0df1036e4fa3663ade323b3c5e77715eae321bbe6c3abc12a46898d972a127b",
        "5a774e7b34512ff3bb6fee044ee48385272aa84004245acca9b0f41215ec0db2",
        "5b96f3703721e34a9942c0bc3a826124127eac866fad00fa9c461e886147c50c",
        "b67f431a132837a7419af9f6288392de89530ac4ce301b5b85f4e7dff961d78e",
        "b277fe2b9600db4fec2be40de567dc244620627d3c8eec0a6f5d694d241566dd",
        "91327805f10d637323bad42bc78f9cc224de56db6155fcd5c4e59ebe4f8bdf8e",
        "1f6117f6344d72bc9abdf4322ef998126cf4b5002842c35a651fb85f602ddf08",
        "a4b6b68d823b12fa94394f99d7b31542aded9110c656dbedd6536ea5948e60fa",
        "b4aababce005d9393e74a0fbbef7d16ed8d29cc8ba130a98fe9ae134b4329475",
        "73da5a03b3b5d3bc08315a4c75d891eb25386b1fba87f6b5e54d87efb6efb4ef",
        "e4348545586b6eef0eb1774d967c6376f5e5fcae21b53c39eb60d528b8cf965e",
        "45302ac4e2de09ececab941ef6f5af56ce4a1f1586d4f53e9521ec494d8e94f7",
        "8490c0a879b720a9d7f8c915d50e6f829208a327eb676de290e31d1a40f0efd2",
        "b6430bb5bc6f143be4507d43271bb1b7f709a6d00c4e8440e9ab2736541f457f"
        ]
    
    options = st.multiselect(
        'Selecciona los algoritmos a comparar',
        ['SHA2 384', 'SHA2 512', 'SHA3 384', 'SHA3 512'])
    
    button = st.button('Aceptar')

    if (button):
        st.write('Tabla comparativa de tiempos (en milisegundos) de ejecución:')

        hashDf = {'Vector' : vector_test_hash}

        for i in options:
            if i == 'SHA2 384':
                hashDf['SHA2 384'] = []

                for i in vector_test_hash:
                    stm=time.time()
                    sha384 = hashlib.sha384(i.encode()) 
                    sha384.hexdigest()
                    time.sleep(0.01)
                    ft=time.time()
                    tiempo=ft-stm
                    tiempo = (tiempo-0.01) * 1000
                    hashDf['SHA2 384'].append(tiempo)                    
            if i == 'SHA2 512':
                hashDf['SHA2 512'] = []

                for i in vector_test_hash:
                    stm=time.time()
                    sha512 = hashlib.sha512(i.encode()) 
                    sha512.hexdigest()
                    time.sleep(0.01)
                    ft=time.time()
                    tiempo=ft-stm
                    tiempo = (tiempo-0.01) * 1000
                    hashDf['SHA2 512'].append(tiempo)
            if i == 'SHA3 384':
                hashDf['SHA3 384'] = []

                for i in vector_test_hash:
                    stm=time.time()
                    sha3384 = hashlib.sha3_384(i.encode()) 
                    sha3384.hexdigest()
                    time.sleep(0.01)
                    ft=time.time()
                    tiempo=ft-stm
                    tiempo = (tiempo-0.01) * 1000
                    hashDf['SHA3 384'].append(tiempo)
            if i == 'SHA3 512':
                hashDf['SHA3 512'] = []

                for i in vector_test_hash:
                    stm=time.time()
                    sha3512 = hashlib.sha3_512(i.encode()) 
                    sha3512.hexdigest()
                    time.sleep(0.01)
                    ft=time.time()
                    tiempo=ft-stm
                    tiempo = (tiempo-0.01) * 1000
                    hashDf['SHA3 512'].append(tiempo)
        
        hashDf = pd.DataFrame(hashDf)

        hashDf
        
        st.write('Gráfica comparativa: ')
        st.bar_chart(hashDf, x='Vector')

        meanTimes = {}

        for i in options:
            meanTimes[i] = hashDf[i].mean()

        meanTimes = pd.DataFrame(list(meanTimes.items()), columns=['Algoritmo','Tiempo promedio'])

        st.write('Tiempo promedio de los algoritmos')
        meanTimes

        st.bar_chart(meanTimes, x='Algoritmo')


elif choose =="Signing/Verifying":

    vector_test_sv = [
        'UgBJ0JrifqTi60iLyF8tpTEVlfWjIBtm',
        'xF1OMD24QWcIEDsdIM2gsHln87tTiCRc',
        '0AZaHGWonH1Kav6uBRTHRT656iMzYIdu',
        'ZMSd5HUde09gc2Cb8zaRVVxax5X5W01Y',
        'OPwyGDS5i8qlV3nJIrjGZhOcEgdrqxi1',
        'JIvCU9W9XXp2I66kxG4ppa5Nuh9bIRIW',
        'N1pYykF8QYRg5Xn4xir7mnbxZjAmT47v',
        '2GcrSsKRimFoMeRiLt3hfsmXzAGVSfG3',
        'rfNq88EKsaEKKRQ4H60aFEFj0NlrkDvx',
        'Bu4ECB1tGZOHdvJ3BkOt5arx1ea48DW1',
        '9BJa8Fw4jRbA9YRPeNYrYbNHDHpCNGsY',
        '6hKJyxIx0P2qFXXCE2IhVA8toV5IuWhW',
        'lbzK2ZLxtVwGu7nVcW6TUkPdZY7t9WnE',
        '1367D8UAZAoEuJMOVu38jugzmIuL1v65',
        'UBNxYaiJ8jSjoe29nfjmIE0iCkJf3rc2',
        'SHfcTRmjwMjaHv1GERelg5E7Pmx7Sb5U',
        'NDX9Z3t7B2UMLhGpSJAe2BGrrSjrgVXE',
        'wFnfnpCDnJBZX4tGcdvTdCiGUgbaHDU6',
        'C6aPqPuxKAEDdSTIxdifror0zyOu9gOs',
        'LpwaiLjvyMEetdzvUvwgE7iqUdEj54Oj'
    ]

    plaintext = b'Attack at dawn'
    options = st.multiselect(
        'Selecciona los algoritmos a comparar',
        ['RSA-OAEP', 'RSA-PSS','ECDA PF 521','ECDSA BF'])
    
    button = st.button('Aceptar')

    if (button):
        
        sinDf = {'Vector' : vector_test_sv}
        verDf = {'Vector' : vector_test_sv}

        for i in options:
            if i == 'RSA-OAEP':
                sinDf['RSA-OAEP'] = []
                verDf['RSA-OAEP'] = []
                for j in vector_test_sv:
                    #generacion de llave publica
                    keyPair = RSA.generate(1024)
                    pubKey = keyPair.publickey()
                    #generacion de llave privada
                    privKeyPEM = keyPair.exportKey()

                    #Signing
                    stm=time.time()
                    signer = PKCS1_v1_5.new(keyPair)
                    digest = SHA256.new()
                    digest.update(bytes(j, 'utf-8'))
                    signature=signer.sign(digest)
                    time.sleep(0.01)
                    ft=time.time()
                    tiempo=ft-stm
                    tiempo = (tiempo-0.01) * 1000
                    sinDf['RSA-OAEP'].append(tiempo)

                    #Verifying
                    stm=time.time()
                    signer2 = PKCS1_v1_5.new(pubKey)
                    try:
                        signer2.verify(digest, signature)
                        #print ("The signature is authentic.")
                    except cryptography.exceptions.InvalidSignature:
                        # Should not happen
                        #print ("The signature is not authentic.")
                        assert False
                    time.sleep(0.01)
                    ft=time.time()
                    tiempo=ft-stm
                    tiempo = (tiempo-0.01) * 1000
                    verDf['RSA-OAEP'].append(tiempo)



            if i == 'RSA-PSS':
                sinDf['RSA-PSS'] = []
                verDf['RSA-PSS'] = []
                for j in vector_test_sv:
                    # RSA-PSS
                    sha256 = hashes.SHA256()
                    pss_padding = padding.PSS(mgf=padding.MGF1(sha256), salt_length=padding.PSS.MAX_LENGTH)

                    # Public-private key creation
                    private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
                    public_key = private_key.public_key()
                    print(private_key)

                    #Signature
                    stm=time.time()
                    signature = private_key.sign(bytes(j, 'utf-8'), pss_padding, sha256)
                    time.sleep(0.01)
                    ft=time.time()
                    tiempo=ft-stm
                    tiempo = (tiempo-0.01) * 1000
                    sinDf['RSA-PSS'].append(tiempo)

                    #Verifying
                    stm=time.time()
                    try:
                        public_key.verify(signature, bytes(j, 'utf-8'), pss_padding, sha256)
                        print ("The signature is authentic.")
                    except cryptography.exceptions.InvalidSignature:
                        # Should not happen
                        print ("The signature is not authentic.")
                        assert False
                    time.sleep(0.01)
                    ft=time.time()
                    tiempo=ft-stm
                    tiempo = (tiempo-0.01) * 1000
                    verDf['RSA-PSS'].append(tiempo)
            if i == 'ECDA PF 521':
                sinDf['ECDA PF 521'] = []
                verDf['ECDA PF 521'] = []
                for j in vector_test_sv:
                    private_key = ec.generate_private_key(
                        ec.SECP521R1()
                    )

                    #signature
                    stm=time.time()
                    signature = private_key.sign(
                        bytes(j, 'utf-8'),
                        ec.ECDSA(hashes.SHA256())
                    )
                    time.sleep(0.01)
                    ft=time.time()
                    tiempo=ft-stm
                    tiempo = (tiempo-0.01) * 1000
                    sinDf['ECDA PF 521'].append(tiempo)

                    #verifying
                    public_key = private_key.public_key()
                    stm=time.time()
                    try:
                        public_key.verify(signature, bytes(j, 'utf-8'), ec.ECDSA(hashes.SHA256()))
                        #print ("The signature is authentic.")
                    except cryptography.exceptions.InvalidSignature:
                        # Should not happen
                        #print ("The signature is not authentic.")
                        assert False
                    time.sleep(0.01)
                    ft=time.time()
                    tiempo=ft-stm
                    tiempo = (tiempo-0.01) * 1000
                    verDf['ECDA PF 521'].append(tiempo)
            if i == 'ECDSA BF':
                sinDf['ECDSA BF'] = []
                verDf['ECDSA BF'] = []
                for j in vector_test_sv:
                    private_key = ec.generate_private_key(
                        ec.SECT571K1()
                    )
                    #signature
                    stm=time.time()
                    signature = private_key.sign(
                        bytes(j, 'utf-8'),
                        ec.ECDSA(hashes.SHA256())
                    )
                    time.sleep(0.01)
                    ft=time.time()
                    tiempo=ft-stm
                    tiempo = (tiempo-0.01) * 1000
                    sinDf['ECDSA BF'].append(tiempo)

                    #Verifying
                    stm=time.time()
                    public_key = private_key.public_key()
                    try:
                        public_key.verify(signature, bytes(j, 'utf-8'), ec.ECDSA(hashes.SHA256()))
                        #print ("The signature is authentic.")
                    except cryptography.exceptions.InvalidSignature:
                        # Should not happen
                        #print ("The signature is not authentic.")
                        assert False
                    time.sleep(0.01)
                    ft=time.time()
                    tiempo=ft-stm
                    tiempo = (tiempo-0.01) * 1000
                    verDf['ECDSA BF'].append(tiempo)


        
        col1, col2 = st.columns(2)

        with(col1):
            st.subheader("Signing")
            st.write('Tabla comparativa de tiempos (en milisegundos) de ejecución:')
            sinDf = pd.DataFrame(sinDf)
            sinDf
            st.write('Gráfica comparativa: ')
            st.bar_chart(sinDf, x='Vector')

            meanTimessin = {}

            for i in options:
                meanTimessin[i] = sinDf[i].mean()

            meanTimessin = pd.DataFrame(list(meanTimessin.items()), columns=['Algoritmo','Tiempo promedio'])

            st.write('Tiempo promedio de los algoritmos')
            meanTimessin

            st.bar_chart(meanTimessin, x='Algoritmo')

        with(col2):
            st.subheader("Verifyng")
            st.write('Tabla comparativa de tiempos (en milisegundos) de ejecución:')
            verDf = pd.DataFrame(verDf)
            verDf
            st.write('Gráfica comparativa: ')
            st.bar_chart(verDf, x='Vector')

            meanTimesver = {}

            for i in options:
                meanTimesver[i] = verDf[i].mean()

            meanTimesver = pd.DataFrame(list(meanTimesver.items()), columns=['Algoritmo','Tiempo promedio'])

            st.write('Tiempo promedio de los algoritmos')
            meanTimesver

            st.bar_chart(meanTimesver, x='Algoritmo')
