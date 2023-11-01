import base64
import streamlit as st
from Crypto.Cipher import DES
from Crypto.Hash import SHA256
from getpass import getpass
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
import os
import shutil

Key_length = 100005
salt = "$ez*&214097GDAKACNASC;LSOSSBAdjskasnmosuf!@#$^()_adsa"

output_folder = "output"
if not os.path.exists(output_folder):
    os.makedirs(output_folder)

def encrypt_video(video_path, password):
    try:
        with open(video_path, 'rb') as videofile:
            video = videofile.read()
        
        # Hashing original video in SHA256
        hash_of_original = SHA256.new(data=video)
        
        # Inputting Keys
        key_enc = password
        
        # Salting and hashing password
        key_enc = PBKDF2(key_enc, salt, 48, Key_length)
        
        # Pad the input data to meet the block size requirement
        padded_video = pad(video, DES.block_size)
        
        # Encrypting using triple 3 key DES	
        print("Wait it is being encrypting.....\n")
        try:
            cipher1 = DES.new(key_enc[0:8], DES.MODE_CBC, key_enc[24:32])
            ciphertext1 = cipher1.encrypt(padded_video)
            cipher2 = DES.new(key_enc[8:16], DES.MODE_CBC, key_enc[32:40])
            ciphertext2 = cipher2.encrypt(ciphertext1)
            cipher3 = DES.new(key_enc[16:24], DES.MODE_CBC, key_enc[40:48])
            ciphertext3 = cipher3.encrypt(ciphertext2)
            
            print("\n------ENCRYPTION SUCCESSFUL-------")
        except Exception as e:
            print("Encryption failed... Possible causes:", e)
            exit()
        
        # Adding hash at end of encrypted bytes
        ciphertext3 += hash_of_original.digest()
        
        # Saving the encrypted file
        try:
            dpath = os.path.join(output_folder, "encrypted_" + os.path.basename(video_path))
            with open(dpath, 'wb') as video_file:
                video_file.write(ciphertext3)
            print("Encrypted Video Saved successfully as filename " + dpath)
        except:
            print("Failed to save encrypted file!")
            exit()
    except Exception as e:
        print("Error loading the file:", e)
        exit()

def decrypt_video(encrypted_video_path, password):
    try:
        with open(encrypted_video_path, 'rb') as encrypted_file:
            encrypted_data_with_hash = encrypted_file.read()

        # Key Authentication
        key_dec = password

        # Extracting hash and cipher data without hash
        extracted_hash = encrypted_data_with_hash[-32:]
        encrypted_data = encrypted_data_with_hash[:-32]

        # Salting and hashing password
        key_dec = PBKDF2(key_dec, salt, 48, Key_length)

        # Decrypting using triple 3 key DES
        print("Decrypting...")
        try:
            cipher3 = DES.new(key_dec[16:24], DES.MODE_CBC, key_dec[40:48])
            decrypted_data3 = cipher3.decrypt(encrypted_data)
            cipher2 = DES.new(key_dec[8:16], DES.MODE_CBC, key_dec[32:40])
            decrypted_data2 = cipher2.decrypt(decrypted_data3)
            cipher1 = DES.new(key_dec[0:8], DES.MODE_CBC, key_dec[24:32])
            decrypted_data1 = cipher1.decrypt(decrypted_data2)

        except Exception as e:
            print("Decryption failed... Possible causes:", e)
            exit()

        # Unpad the decrypted data
        decrypted_video = unpad(decrypted_data1, DES.block_size)

        # Hashing decrypted plain text
        hash_of_decrypted = SHA256.new(data=decrypted_video)

        # Matching hashes
        if hash_of_decrypted.digest() == extracted_hash:
            print("Password Correct !!!")
            print("------DECRYPTION SUCCESSFUL------")
            st.success("Decryption successful!")
        else:
            print("Incorrect Password!!!!!")
            exit()

        # Saving the decrypted file
        try:
            epath = os.path.join(output_folder, "decrypted_" + os.path.basename(encrypted_video_path))
            #epath = "decrypted_" + epath
            with open(epath, 'wb') as video_file:
                video_file.write(decrypted_video)
            print("Video saved successfully with name " + epath)
        except:
            print("Failed to save decrypted file!")
            exit()
    except Exception as e:
        st.warning("Please provide correct encrypted video file or give correct password for the encrypted video")
        exit()

def encryptor(image_path, password):
    try:
        with open(image_path, 'rb') as imagefile:
            image = imagefile.read()

        # Padding
        while len(image) % 8 != 0:
            image += b" "

        # Hashing original image in SHA256
        hash_of_original = SHA256.new(data=image)

        # Salting and hashing password
        key_enc = PBKDF2(password, salt, 48, Key_length)

        # Encrypting using triple 3 key DES
        print("Wait, it is being encrypted...\n")
        try:
            cipher1 = DES.new(key_enc[0:8], DES.MODE_CBC, key_enc[24:32])
            ciphertext1 = cipher1.encrypt(image)
            cipher2 = DES.new(key_enc[8:16], DES.MODE_CBC, key_enc[32:40])
            ciphertext2 = cipher2.decrypt(ciphertext1)
            cipher3 = DES.new(key_enc[16:24], DES.MODE_CBC, key_enc[40:48])
            ciphertext3 = cipher3.encrypt(ciphertext2)

            print("\n------ENCRYPTION SUCCESSFUL-------")
        except:
            print("Encryption failed... Possible causes: Library not installed properly/low device memory/Incorrect padding or conversions")
            exit()

        # Adding hash at the end of encrypted bytes
        ciphertext3 += hash_of_original.digest()

        # Saving the encrypted file
        try:
            dpath = os.path.join(output_folder, "encrypted_" + os.path.basename(image_path))
            with open(dpath, 'wb') as image_file:
                image_file.write(ciphertext3)
            print("Encrypted Image Saved successfully as filename " + dpath)

        except:
            print("Failed to save encrypted file!")
            exit()
    except:
        print("Error loading the file, make sure file is in the same directory, spelled correctly, and non-corrupted")
        exit()

def decryptor(encrypted_image_path, password):
    try:
        with open(encrypted_image_path, 'rb') as encrypted_file:
            encrypted_data_with_hash = encrypted_file.read()

    except:
        print("Unable to read source cipher data. Make sure the file is in the same directory... Exiting...")
        exit()

    # Key Authentication
    key_dec = PBKDF2(password, salt, 48, Key_length)

    # Extracting hash and cipher data without hash
    extracted_hash = encrypted_data_with_hash[-32:]
    encrypted_data = encrypted_data_with_hash[:-32]

    # Decrypting using triple 3 key DES
    print("Decrypting...")
    try:
        cipher1 = DES.new(key_dec[16:24], DES.MODE_CBC, key_dec[40:48])
        plaintext1 = cipher1.decrypt(encrypted_data)
        cipher2 = DES.new(key_dec[8:16], DES.MODE_CBC, key_dec[32:40])
        plaintext2 = cipher2.encrypt(plaintext1)
        cipher3 = DES.new(key_dec[0:8], DES.MODE_CBC, key_dec[24:32])
        plaintext3 = cipher3.decrypt(plaintext2)

    except:
        print("Decryption failed... Possible causes: Library not installed properly/low device memory/Incorrect padding or conversions")

    # Hashing decrypted plain text
    hash_of_decrypted = SHA256.new(data=plaintext3)

    # Matching hashes
    if hash_of_decrypted.digest() == extracted_hash:
        print("Password Correct !!!")
        print("------DECRYPTION SUCCESSFUL------")
    else:
        print("Incorrect Password!!!!!")
        exit()

    # Saving the decrypted file
    try:
        epath = os.path.join(output_folder, "decrypted_" + os.path.basename(encrypted_image_path))
        with open(epath, 'wb') as image_file:
            image_file.write(plaintext3)
        print("Image saved successfully with name " + epath)
        print("Note: If the decrypted image is appearing to be corrupted then the password may be wrong or it may be a file format error")
    except:
        print("Failed! Exiting...")
        exit()


def main():
    st.title("Triple DES Encryption and Decryption")

    img_video = st.radio("Choose an option:", ("Image", "Video"))

    if img_video == "Image":
        st.subheader("image Encryption and Decryption")
        choice = st.radio("Choose an option:", ("Encrypt", "Decrypt"))

        if choice == "Encrypt":
            image_file = st.file_uploader("Upload an image to encrypt", type=["jpg", "jpeg", "png"])
            password = st.text_input("Enter minimum 8 character long password:", type="password")
            if st.button("Encrypt"):
                if image_file and len(password) >= 8:
                    # Save the uploaded image to the "output" folder
                    image_path = os.path.join(output_folder, image_file.name)
                    with open(image_path, 'wb') as output_file:
                        output_file.write(image_file.read())
                    print(image_path)
                    encryptor(image_path, password)
                    st.success("Encryption successful!")
                    progress_bar = st.progress(0)  # Initialize the progress bar
                    progress_text = st.empty()  # Placeholder for progress text

                    def update_progress_bar(progress):
                        progress_bar.progress(progress)
                        progress_text.text(f"preparing download file... {progress:.2f}%")

                    encrypted_image_name = os.path.basename(image_path)
                    encrypted_image_path = os.path.join(output_folder, "encrypted_" + encrypted_image_name)

                    with open(encrypted_image_path, 'rb') as f:
                        encrypted_image_bytes = f.read()
                    
                    update_progress_bar(100)

                    st.markdown(
                    f'<a href="data:image/png;base64,{base64.b64encode(encrypted_image_bytes).decode()}" download="encrypted_image.png">Download Encrypted Image</a>',
                    unsafe_allow_html=True
                    )

                    # Remove the original uploaded image
                    os.remove(image_path)
                    shutil.rmtree(output_folder)

        elif choice == "Decrypt":
            encrypted_image_file = st.file_uploader("Upload an encrypted image to decrypt", type=["jpg", "jpeg", "png"])
            password = st.text_input("Enter password:", type="password")

            if st.button("Decrypt"):
                if encrypted_image_file and password:
                    # Save the uploaded encrypted image to the "output" folder
                    encrypted_image_path = os.path.join(output_folder, encrypted_image_file.name)
                    with open(encrypted_image_path, 'wb') as output_file:
                        output_file.write(encrypted_image_file.read())
                    print(encrypted_image_path)
                    decryptor(encrypted_image_path, password)
                    st.success("Decryption successful!")

                    # Provide download link for the decrypted image
                    decrypted_image_name = os.path.basename(encrypted_image_path)
                    decrypted_image_path = os.path.join(output_folder, "decrypted_" + decrypted_image_name)
                    with open(decrypted_image_path, 'rb') as f:
                        decrypted_image_bytes = f.read()
                    st.markdown(
                        f'<a href="data:image/png;base64,{base64.b64encode(decrypted_image_bytes).decode()}" download="decrypted_image.png">Download Decrypted Image</a>',
                        unsafe_allow_html=True
                    )

                    # Remove the original uploaded encrypted image
                    os.remove(encrypted_image_path)
                    shutil.rmtree(output_folder)

    elif img_video == "Video":
        st.subheader("Video Encryption and Decryption")
        choice = st.radio("Choose an option:", ("Encrypt", "Decrypt"))

        if choice == "Encrypt":
            video_file = st.file_uploader("Upload a video to encrypt", type=["mp4"])
            password = st.text_input("Enter minimum 8 character long password:", type="password")
            if st.button("Encrypt"):
                print(video_file)
                if video_file and len(password) >= 8:
                    # Save the uploaded video to the "output" folder
                    video_path = os.path.join(output_folder, video_file.name)
                    with open(video_path, 'wb') as output_file:
                        output_file.write(video_file.read())
                    print(video_path)
                    encrypt_video(video_path, password)
                    st.success("Encryption successful!")

                    progress_bar = st.progress(0)  # Initialize the progress bar
                    progress_text = st.empty()  # Placeholder for progress text

                    def update_progress_bar(progress):
                        progress_bar.progress(progress)
                        progress_text.text(f"preparing download file... {progress:.2f}%")

                    encrypted_video_name = os.path.basename(video_path)
                    encrypted_video_path = os.path.join(output_folder, "encrypted_" + encrypted_video_name)
                    with open(encrypted_video_path, 'rb') as f:
                        encrypted_video_bytes = f.read()
                    
                    update_progress_bar(100)

                    st.markdown(
                        f'<a href="data:video/mp4;base64,{base64.b64encode(encrypted_video_bytes).decode()}" download="encrypted_video.mp4">Download Encrypted Video</a>',
                        unsafe_allow_html=True
                    )
                    
                    # Remove the original uploaded video
                    os.remove(video_path)
                    shutil.rmtree(output_folder)
                else:
                    st.warning("Please provide a video file and a password of at least 8 characters.")
        
        elif choice == "Decrypt":
            encrypted_video_file = st.file_uploader("Upload an encrypted video to decrypt", type=["mp4"])
            password = st.text_input("Enter password:", type="password")
            
            if st.button("Decrypt"):
                if encrypted_video_file and password:
                    # Save the uploaded video to the "output" folder
                    encrypted_video_path = os.path.join(output_folder, encrypted_video_file.name)
                    with open(encrypted_video_path, 'wb') as output_file:
                        output_file.write(encrypted_video_file.read())
                    
                    print(encrypted_video_path)
                    decrypted_video_path = os.path.join(output_folder, "decrypted_" + encrypted_video_file.name)
                    decrypt_video(encrypted_video_path, password)

                    with open(decrypted_video_path, 'rb') as f:
                        decrypted_video_bytes = f.read()
                    
                    st.markdown(
                        f'<a href="data:video/mp4;base64,{base64.b64encode(decrypted_video_bytes).decode()}" download="decrypted_video.mp4">Download Decrypted Video</a>',
                        unsafe_allow_html=True
                    )

    
                    
if __name__ == "__main__":
    main()