## @file key_generation_main.py
#  @brief GUI application for secure key generation using RSA and AES encryption.
#
#  This app provides a GUI for users to generate private and public keys.
#  The application allows for:
#  - Generating RSA key pairs (public/private)
#  - Deriving AES keys using a PIN and salt
#  - Saving keys as files
#
#  GUI is built using Tkinter and includes feedback mechanisms to guide
#  the user through the key generation process.
#
#  @date 2025-04-23

from Cryptodome.Protocol.KDF import PBKDF2
import threading
from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA256
from Cryptodome.Random import get_random_bytes
import tkinter as tk
from tkinter import messagebox, ttk, filedialog

rsa_bits = 4096
aes_mode = AES.MODE_GCM


def encrypt_private_key(pk, pin):
    """
        @brief Encrypts a private RSA key using a PIN.

        @param pk The private RSA key to encrypt.
        @param pin The PIN used to encrypt the key.

        @return The encrypted key data.
        """
    salt = get_random_bytes(16)
    aes_k = generate_aes_key(pin, salt)
    cipher = AES.new(aes_k, aes_mode)
    ciphertext, verification_tag = cipher.encrypt_and_digest(pk)
    return salt + cipher.nonce + verification_tag + ciphertext


def generate_rsa_keys():
    """
        @brief Generates a new RSA key pair (private and public keys).

        @return A tuple containing the private key and public key.
        """
    key = RSA.generate(rsa_bits)
    private = key.export_key()
    public = key.public_key().export_key()
    return private, public


def generate_aes_key(pin, salt):
    """
        @brief Generates an AES encryption key based on a PIN and salt.

        @param pin The user's PIN used for key derivation.
        @param salt The salt used in the key derivation process.

        @return The derived AES key.
        """
    return PBKDF2(password=pin,
                  salt=salt,
                  dkLen=32,
                  count=1000000,
                  hmac_hash_module=SHA256)


def update_task_progress(value, text):
    """
       @brief Updates the GUI task progress bar and status message.

       @param value The progress percentage (0–100).
       @param text The status message to display.
       """
    progress_bar["value"] = value
    status_label.config(text=text)
    main_window.update_idletasks()


def generate_keys():
    """
        @brief Initiates the RSA and AES key generation process

        This function coordinates the creation of RSA and AES keys,
        and may update the UI to reflect progress.
        """
    passphrase = passphrase_entry.get()
    if len(passphrase) < 8:
        messagebox.showerror("Weak Passphrase", "Passphrase must be at least 8 characters long.")
        return
    passphrase_entry.config(state=tk.DISABLED)
    gen_button.config(state=tk.DISABLED)
    save_public_button.config(state=tk.DISABLED)
    save_private_button.config(state=tk.DISABLED)

    update_task_progress(10, "Generating AES key...")

    def thread_task():
        """
            @brief Runs the key generation process in a separate thread.

            Allows the GUI to stay responsive while generating keys in the background.
            """
        global generated_public_key, encrypted_private_key
        try:
            update_task_progress(10, "Generating RSA keys...")
            private_key, public_key = generate_rsa_keys()

            update_task_progress(50, "Encrypting private key...")
            encrypted_key = encrypt_private_key(private_key, passphrase)

            update_task_progress(90, "Finalizing...")
            generated_public_key = public_key
            encrypted_private_key = encrypted_key

            update_task_progress(100, "Ready to save keys.")
            save_public_button.config(state=tk.NORMAL)
            save_private_button.config(state=tk.NORMAL)

        except Exception as e:
            messagebox.showerror("Unknown error", f"Unknown error occurred: {str(e)}")
            update_task_progress(0, "Error occurred.")
        finally:
            passphrase_entry.config(state=tk.NORMAL)
            gen_button.config(state=tk.NORMAL)

    threading.Thread(target=thread_task, daemon=True).start()


def save_public():
    """
       @brief Saves the generated public key to a file.

       Asks the user to choose a location and writes the key in PEM format.
       """
    path = filedialog.asksaveasfilename(
        title="Save public key",
        defaultextension=".pem",
        filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
    )
    if path:
        with open(path, "wb") as f:
            f.write(generated_public_key)
        messagebox.showinfo("Success", "Public key saved")


def save_private():
    """
       @brief Saves the encrypted private key to a file.

       Asks the user to choose a location and writes the key securely.
       """
    path = filedialog.asksaveasfilename(
        title="Save private key",
        defaultextension=".enc",
        filetypes=[("ENC files", "*.enc"), ("All files", "*.*")]
    )
    if path:
        with open(path, "wb") as f:
            f.write(encrypted_private_key)
        messagebox.showinfo("Success", "Private key saved")

# Create GUI
main_window = tk.Tk()
main_window.title("Key generation app")
main_window.geometry("300x250")
main_window.resizable(False, False)
main_window.configure(background="#D9D9D9")

style = ttk.Style()
style.theme_use("default")
style.configure("TButton", padding=5, font=("Arial", 10), background="#E4EFF0")
style.map("Custom.TButton", background=[("active", "#cde2e4"), ("!active", "#E8F2F1")])
style.configure("TLabel", font=("Arial", 10), background="#D9D9D9")
style.configure("TEntry", padding=5)
style.configure("TProgressbar", thickness=10, background="#8C8C8C")

main_window.grid_columnconfigure(0, weight=1)
main_window.grid_columnconfigure(1, weight=2)

ttk.Label(main_window, text="Enter a passphrase:").grid(row=0, column=0, padx=10, pady=10, sticky="W")
passphrase_entry = ttk.Entry(main_window, show="*")
passphrase_entry.grid(row=0, column=1, padx=10, pady=10)

gen_button = ttk.Button(main_window, text="Generate Keys", command=generate_keys, style="Custom.TButton")
gen_button.grid(row=1, column=0, columnspan=2, pady=10)

progress_bar = ttk.Progressbar(main_window, length=290)
progress_bar.grid(row=2, column=0, columnspan=2, pady=10)

status_label = ttk.Label(main_window, text="", font=("Arial", 10))
status_label.grid(row=3, column=0, columnspan=2, pady=5)

save_public_button = ttk.Button(main_window, text="Save Public Key", command=save_public, state=tk.DISABLED, style="Custom.TButton")
save_public_button.grid(row=4, column=0, pady=10)

save_private_button = ttk.Button(main_window, text="Save Private Key", command=save_private, state=tk.DISABLED, style="Custom.TButton")
save_private_button.grid(row=4, column=1, pady=10)

main_window.mainloop()
