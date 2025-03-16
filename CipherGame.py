import tkinter as tk
from tkinter import messagebox
import random
import string
import hashlib
from Crypto.Cipher import ARC4

class CipherGame:
    def __init__(self, root):
        self.root = root
        self.root.title("Stream Cipher Game")

        self.message_label = tk.Label(root, text="Введите сообщение:")
        self.message_label.pack()
        self.message_entry = tk.Entry(root, width=50)
        self.message_entry.pack()

        self.key_label = tk.Label(root, text="Введите ключ:")
        self.key_label.pack()
        self.key_entry = tk.Entry(root, width=50)
        self.key_entry.pack()

        self.method_label = tk.Label(root, text="Выберите метод шифрования:")
        self.method_label.pack()
        self.method_var = tk.StringVar(value="XOR")
        self.xor_radio = tk.Radiobutton(root, text="XOR", variable=self.method_var, value="XOR")
        self.rc4_radio = tk.Radiobutton(root, text="RC4", variable=self.method_var, value="RC4")
        self.xor_radio.pack()
        self.rc4_radio.pack()

        self.difficulty_label = tk.Label(root, text="Выберите уровень сложности:")
        self.difficulty_label.pack()
        self.difficulty_var = tk.StringVar(value="Medium")
        self.easy_radio = tk.Radiobutton(root, text="Easy", variable=self.difficulty_var, value="Easy")
        self.medium_radio = tk.Radiobutton(root, text="Medium", variable=self.difficulty_var, value="Medium")
        self.hard_radio = tk.Radiobutton(root, text="Hard", variable=self.difficulty_var, value="Hard")
        self.easy_radio.pack()
        self.medium_radio.pack()
        self.hard_radio.pack()

        self.encrypt_button = tk.Button(root, text="Зашифровать", command=self.encrypt_message)
        self.encrypt_button.pack()

        self.cipher_label = tk.Label(root, text="Зашифрованный текст:")
        self.cipher_label.pack()
        self.cipher_text = tk.Entry(root, width=50)
        self.cipher_text.pack()

        self.decrypt_button = tk.Button(root, text="Расшифровать", command=self.decrypt_message)
        self.decrypt_button.pack()

        self.decrypted_label = tk.Label(root, text="Расшифрованное сообщение:")
        self.decrypted_label.pack()
        self.decrypted_text = tk.Entry(root, width=50)
        self.decrypted_text.pack()

        self.hash_sha256_button = tk.Button(root, text="Хешировать (SHA-256)", command=self.hash_sha256)
        self.hash_sha256_button.pack()
        self.hash_md5_button = tk.Button(root, text="Хешировать (MD5)", command=self.hash_md5)
        self.hash_md5_button.pack()

        self.hash_label = tk.Label(root, text="Хешированный текст:")
        self.hash_label.pack()
        self.hash_text = tk.Entry(root, width=50)
        self.hash_text.pack()

    def generate_random_key(self, length=8):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def xor_cipher(self, text, key):
        key_length = len(key)
        encrypted_bytes = [ord(c) ^ ord(key[i % key_length]) for i, c in enumerate(text)]
        return "".join(f"{b:02x}" for b in encrypted_bytes)

    def xor_decipher(self, hex_text, key):
        key_length = len(key)
        cipher_bytes = bytes.fromhex(hex_text)
        return "".join(chr(b ^ ord(key[i % key_length])) for i, b in enumerate(cipher_bytes))

    def rc4_cipher(self, text, key):
        cipher = ARC4.new(key.encode())
        return cipher.encrypt(text.encode())

    def encrypt_message(self):
        message = self.message_entry.get()
        user_key = self.key_entry.get()
        method = self.method_var.get()
        difficulty = self.difficulty_var.get()

        if not message:
            messagebox.showerror("Ошибка", "Введите сообщение!")
            return

        if difficulty == "Easy":
            key = "easy_key"
        elif difficulty == "Medium":
            if not user_key:
                messagebox.showerror("Ошибка", "Введите ключ!")
                return
            key = user_key
        else:
            key = self.generate_random_key()
            messagebox.showinfo("Сгенерированный ключ", f"Ваш ключ: {key}")

        if method == "XOR":
            cipher_text = self.xor_cipher(message, key)
        else:
            cipher_text = self.rc4_cipher(message, key).hex()

        self.cipher_text.delete(0, tk.END)
        self.cipher_text.insert(0, cipher_text)

        if difficulty == "Hard":
            self.key_entry.delete(0, tk.END)
            self.key_entry.insert(0, key)

    def decrypt_message(self):
        cipher_text = self.cipher_text.get()
        key = self.key_entry.get()
        method = self.method_var.get()
        difficulty = self.difficulty_var.get()

        if difficulty == "Easy":
            key = "easy_key"

        if not cipher_text or not key:
            messagebox.showerror("Ошибка", "Введите зашифрованный текст и ключ!")
            return

        try:
            if method == "XOR":
                decrypted_text = self.xor_decipher(cipher_text, key)
            else:
                cipher_bytes = bytes.fromhex(cipher_text)
                cipher = ARC4.new(key.encode())
                decrypted_text = cipher.decrypt(cipher_bytes).decode()

            self.decrypted_text.delete(0, tk.END)
            self.decrypted_text.insert(0, decrypted_text)
        except Exception:
            messagebox.showerror("Ошибка", "Ошибка при расшифровке!")

    def hash_sha256(self):
        message = self.message_entry.get()
        if not message:
            messagebox.showerror("Ошибка", "Введите сообщение!")
            return
        hash_result = hashlib.sha256(message.encode()).hexdigest()
        self.hash_text.delete(0, tk.END)
        self.hash_text.insert(0, hash_result)

    def hash_md5(self):
        message = self.message_entry.get()
        if not message:
            messagebox.showerror("Ошибка", "Введите сообщение!")
            return
        hash_result = hashlib.md5(message.encode()).hexdigest()
        self.hash_text.delete(0, tk.END)
        self.hash_text.insert(0, hash_result)

root = tk.Tk()
game = CipherGame(root)
root.mainloop()
