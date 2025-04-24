## @signing_app_main.py
#  @brief GUI application for digitally signing and verifying PDF documents using RSA keys.
#
#  This app allows :
#  - Sign PDF documents using a private key (can be automatically detected from pendrive)
#  - Verify the integrity and authenticity of signed PDF documents
#  - Select keys and files through a GUI
#
#  The signing process uses secure cryptographic standards to ensure that
#  the signed documents can be verified using a public key.
#  Errors such as invalid signatures or incorrect passphrases are handled by showing appropriate message.
#
#  @date 2025-04-23

import os
import time
import threading
from typing import Optional, Dict, List, Any
from io import BytesIO
import tkinter as tk
from tkinter import ttk, simpledialog, filedialog, messagebox
import psutil
from PyPDF2 import PdfReader, PdfWriter
from Cryptodome.Cipher import AES
from Cryptodome.Signature import pss
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA256
from Cryptodome.Protocol.KDF import PBKDF2

aes_mode = AES.MODE_GCM
PRIVATE_KEY = None
MANUAL_KEY_SELECTION = False

def decrypt_private_key(pk_path, passphrase):
    """
       @brief Decrypts a private key stored in a file.

       This function loads an encrypted private key from the specified file and decrypts it using
       the provided passphrase. The decrypted private key is returned for use in cryptographic
       operations such as signing documents.

       @param pk_path The path to the file containing the encrypted private key.
       @param passphrase The passphrase used to decrypt the private key.

       @return The decrypted private key as a string.
       """
    with open(pk_path, "rb") as f:
        key = f.read()
    salt, nonce, tag, ciphertext = key[:16], key[16:32], key[32:48], key[48:]
    aes_key = PBKDF2(password=passphrase,
                     salt=salt,
                     dkLen=32,
                     count=1000000,
                     hmac_hash_module=SHA256)
    cipher = AES.new(aes_key, aes_mode, nonce=nonce)
    decrypted_key = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted_key


def adjust_metadata(pdf_path: str,
                    remove_fields_metadata: Optional[List[str]] = None,
                    add_fields_metadata: Optional[Dict[str, Any]] = None) -> bytes:
    """
       @brief Adjusts metadata of a PDF file.

       This function modifies the metadata of a PDF file by removing/adding specific fields
       as specified by the parameters. It allows for updating the PDF's metadata without altering
       the content of the document itself.

       @param pdf_path The path to the PDF file whose metadata is to be adjusted.
       @param remove_fields_metadata A list of metadata field names to remove from the PDF.
                                     (Optional, default is None).
       @param add_fields_metadata A dictionary of metadata field names and values to add to the PDF.
                                  (Optional, default is None).

       @return The PDF file as a byte stream with the updated metadata.
       """
    reader = PdfReader(pdf_path)
    writer = PdfWriter()
    writer.append_pages_from_reader(reader)
    metadata = reader.metadata

    if remove_fields_metadata:
        for field in remove_fields_metadata:
            if field in metadata:
                del metadata[field]
    if add_fields_metadata:
        metadata.update(add_fields_metadata)

    writer.add_metadata(metadata)
    pdf_bytes = BytesIO()
    writer.write(pdf_bytes)
    pdf_bytes.seek(0)
    return pdf_bytes.getvalue()


def sign_pdf(private_key_pem, pdf_path):
    """
        @brief Signs a PDF file using a private key.

        This function signs a PDF file with the provided private key, generating a cryptographic
        signature that ensures the authenticity of the document. The private key is used to sign
        the PDF, ensuring that the content has not been changed since the signature was applied.

        @param private_key_pem The private key in PEM format used for signing the PDF.
        @param pdf_path The path to the PDF file that needs to be signed.

        @return The signed PDF as a byte stream.
        """
    private_key = RSA.importKey(private_key_pem)
    pdf_bytes = adjust_metadata(pdf_path, remove_fields_metadata=['/sig'])
    pdf_hash = SHA256.new(pdf_bytes)
    signature = pss.new(private_key).sign(pdf_hash)
    signature_field = {'/sig': signature.hex()}
    signed_pdf_bytes = adjust_metadata(pdf_path, add_fields_metadata=signature_field)
    sign_pdf_path = pdf_path.replace(".pdf", "_signed.pdf")
    with open(sign_pdf_path, "wb") as f:
        f.write(signed_pdf_bytes)
    print('Pdf signed')


def verify_signature(signed_pdf_path, public_key_path):
    """
        @brief Verifies the digital signature of a PDF document.

        @param signed_pdf_path Path to the signed PDF file.
        @param public_key_path Path to the public key used for verification.

        @return None. Displays result of verification.
        """
    reader = PdfReader(signed_pdf_path)
    metadata = reader.metadata
    signature = bytes.fromhex(metadata.get('/sig'))
    signed_pdf_bytes_no_signature = adjust_metadata(signed_pdf_path, remove_fields_metadata=['/sig'])
    pdf_hash = SHA256.new(signed_pdf_bytes_no_signature)
    with open(public_key_path, "rb") as f:
        public_key = RSA.importKey(f.read())
    verifier = pss.new(public_key)
    try:
        verifier.verify(pdf_hash, signature)
        print("Signature is valid!")
    except (ValueError, TypeError) as e:
        print("Invalid signature:", e)
        raise ValueError("Invalid signature")


def detect_pendrive():
    """
       @brief Detects if a USB pendrive is connected to the system.

       @return The path to the detected pendrive or None if not found.
       """
    global PRIVATE_KEY, MANUAL_KEY_SELECTION
    while True:
        time.sleep(1)
        pendrives = {disk.device for disk in psutil.disk_partitions() if 'removable' in disk.opts}
        pem_files = []
        for drive in pendrives:
            for root, dirs, files in os.walk(drive):
                for f in files:
                    if f.endswith('.enc'):
                        pem_files.append(os.path.join(root, f))
        # If only one key is detected, choose key automatically
        if len(pem_files) == 1 and not MANUAL_KEY_SELECTION:
            PRIVATE_KEY = pem_files[0]
            main_window.after(0, lambda: usb_status_label.config(text="One key detected"))
            main_window.after(0, lambda: sign_pdf_button.config(state=tk.NORMAL))
            main_window.after(0, lambda: select_key_button.config(state=tk.DISABLED, text="Using the only available key."))
        # If more than one key is detected, select key manually
        elif len(pem_files) > 1:
            if not MANUAL_KEY_SELECTION:
                PRIVATE_KEY = None
                main_window.after(0, lambda: usb_status_label.config(text="Multiple keys detected. Please select one."))
                main_window.after(0, lambda: sign_pdf_button.config(state=tk.DISABLED))
            main_window.after(0, lambda: select_key_button.config(state=tk.NORMAL))
        else:
            # If no USB is detected, reset everything
            if not pendrives or (PRIVATE_KEY and not os.path.exists(PRIVATE_KEY)):
                PRIVATE_KEY = None
                MANUAL_KEY_SELECTION = False  # Reset manual selection
                main_window.after(0, lambda: usb_status_label.config(text="There are no keys on USB detected"))
                main_window.after(0, lambda: sign_pdf_button.config(state=tk.DISABLED))
                main_window.after(0, lambda: select_key_button.config(state=tk.DISABLED))


def select_pdf_to_sign():
    """
        @brief Opens a file dialog to select a PDF file to sign.

        @return None. Stores the selected PDF path for signing.
        """
    # If no private key is selected, show error message
    if not PRIVATE_KEY or not os.path.exists(PRIVATE_KEY):
        messagebox.showerror("Error", "No private key selected or key file missing!")
        return

    passphrase = simpledialog.askstring("Enter Passphrase", "Enter your passphrase:", show="*")
    # If passphrase is too short, show error message
    if not passphrase or len(passphrase) < 8:
        messagebox.showerror("Invalid passphrase", "Invalid passphrase: minimum length is 8 characters.")
        return

    # Select PDF to sign
    pdf_path = filedialog.askopenfilename(title="Select PDF to sign", filetypes=[("PDF Files", "*.pdf")])
    if not pdf_path:
        return

    # Decrypt private key
    try:
        private_key_pem = decrypt_private_key(PRIVATE_KEY, passphrase)
    # If private key file not found, show error message
    except FileNotFoundError:
        messagebox.showerror("Error", "Private key file not found!")
        return
    # If passphrase incorrect or corrupted file, show error message
    except ValueError:
        messagebox.showerror("Error", "Incorrect PIN or corrupted key file!")
        return
    except Exception as e:
        messagebox.showerror("Error", f"Failed to decrypt private key: {str(e)}")
        return

    # Sign PDF file using private key
    try:
        sign_pdf(private_key_pem, pdf_path)
        messagebox.showinfo("Success", "PDF signed successfully!")
    # If PDF file not found, show error message
    except FileNotFoundError:
        messagebox.showerror("Error", "PDF file not found!")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to sign PDF: {str(e)}")


def check_signature():
    """
       @brief Checks the digital signature of the currently selected PDF.

       @return None. Displays the result of the signature check.
       """
    signed_pdf_path = filedialog.askopenfilename(title="Select signed PDF", filetypes=[("PDF Files", "*.pdf")])
    # If PDF file not found, show error message
    if not signed_pdf_path:
        return
    public_key_path = filedialog.askopenfilename(title="Select Public Key", filetypes=[("PEM Files", "*.pem")])
    if not public_key_path:
        return
    try:
        verify_signature(signed_pdf_path, public_key_path)
        messagebox.showinfo("Signature Verification", "Signature is valid!")
    except Exception as e:
        messagebox.showerror("Signature Verification", "Signature is invalid! Make sure the passphrase and file are correct.")



def select_private_key():
    """
        @brief Opens a file dialog to select a private key file.

        @return None. Stores the selected private key for signing purposes.
        """
    global PRIVATE_KEY, MANUAL_KEY_SELECTION
    pendrives = [disk.device for disk in psutil.disk_partitions() if 'removable' in disk.opts]
    initialdir = pendrives[0] if len(pendrives) == 1 else None
    selected_file = filedialog.askopenfilename(
        title="Select Private Key", initialdir=initialdir, filetypes=[("PEM Files", "*.enc")])
    if selected_file:
        PRIVATE_KEY = selected_file
        MANUAL_KEY_SELECTION = True
        usb_status_label.config(text=f"Key selected: {os.path.basename(selected_file)}")
        sign_pdf_button.config(state=tk.NORMAL)


# Create GUI
main_window = tk.Tk()
main_window.title("Document Signing and Verification App")
main_window.geometry("400x300")
main_window.resizable(False, False)
main_window.columnconfigure(0, weight=1)
main_window.rowconfigure(0, weight=1)
main_window.configure(bg="#f2f2f7")

style = ttk.Style()
style.theme_use("default")
style.configure("TButton", padding=10, font=("Arial", 10), background="#E4EFF0")
style.map("Custom.TButton", background=[("active", "#cde2e4"), ("!active", "#E8F2F1")])
style.configure("TLabel", font=("Arial", 10))
style.configure("TEntry", padding=5)

frame = ttk.Frame(main_window, padding=20)
frame.place(relx=0.5, rely=0.5, anchor="center")
frame.grid(row=0, column=0, sticky="nsew")

sign_pdf_button = ttk.Button(frame, text="Sign PDF", state=tk.DISABLED, command=select_pdf_to_sign, style="Custom.TButton")
sign_pdf_button.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

usb_status_label = ttk.Label(frame, text="There are no keys on USB detected", font=("Arial", 10))
usb_status_label.grid(row=1, column=0, padx=10, pady=5)

check_signature_button = ttk.Button(frame, text="Check Signature", command=check_signature, style="Custom.TButton")
check_signature_button.grid(row=2, column=0, padx=10, pady=10)

select_key_button = ttk.Button(frame, text="Select Private Key", command=select_private_key, style="Custom.TButton")
select_key_button.grid(row=3, column=0, padx=10, pady=10)

frame.columnconfigure(0, weight=1)
frame.rowconfigure(0, weight=1)

usb_thread = threading.Thread(target=detect_pendrive, daemon=True)
usb_thread.start()

main_window.mainloop()
