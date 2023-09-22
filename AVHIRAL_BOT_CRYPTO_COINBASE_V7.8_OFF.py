import os
import ccxt
import time
import pandas as pd
import tkinter as tk
from tkinter import ttk
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import threading
import logging
import sys

logging.basicConfig(filename='bot.log', level=logging.ERROR)

REFRESH_INTERVAL = 60
RECIPIENT_EMAIL = 'exemple@gmail.com' #Entrez l'email de reception

class XORCipher:
    def __init__(self, key):
        self.key = key

    def encrypt(self, plaintext):
        ciphertext = []
        for i in range(len(plaintext)):
            char = plaintext[i]
            key_char = self.key[i % len(self.key)]
            encrypted_char = chr(ord(char) ^ ord(key_char))
            ciphertext.append(encrypted_char)
        return ''.join(ciphertext)

    def decrypt(self, ciphertext):
        return self.encrypt(ciphertext)  

class TradingBot:
    remember_credentials_var = None

    def __init__(self):
        self.xor_cipher = None
        self.api_key = None
        self.api_secret = None
        self.email = None
        self.password = None
        self.daily_profit_target_euros = None
        self.api_status_label = None
        self.connect_button = None
        self.thread = None
        self.crypto_pairs = []
        self.exchange = None
        self.initialize_ui()
        self.daily_profit = 0
        self.charts = {}
        self.positions = {'BTC/USD': None, 'ETH/USD': None, 'MATIC/USD': None}
        self.entry_prices = {'BTC/USD': None, 'ETH/USD': None, 'MATIC/USD': None}
        self.load_key()  

    def load_key(self):
        # Load the XOR cipher key
        if os.path.isfile("xor_key_coinbase.txt"):
            with open("xor_key_coinbase.txt", "r") as key_file:
                self.xor_cipher = XORCipher(key_file.read())
        else:
            # Create a new XOR cipher key and place it in xor_key_coinbase.txt
            key = "YOUR_GENERATED_KEY_HERE"  # Remplacez par votre propre clé
            with open("xor_key_coinbase.txt", "w") as key_file:
                key_file.write(key)
            self.xor_cipher = XORCipher(key)

    def encrypt_and_save_credentials(self):
        if not self.api_key or not self.api_secret or not self.email or not self.password:
            print("Veuillez fournir toutes les informations sensibles.")
            return

        # Create a string with sensitive information
        credentials = f"{self.api_key}\n{self.api_secret}\n{self.email}\n{self.password}"

        # Use the XOR encryption method
        encrypted_credentials = self.xor_cipher.encrypt(credentials)

        # Save the encrypted information in xor_key_coinbase.txt
        with open("xor_key_coinbase.txt", "w") as key_file:
            key_file.write(encrypted_credentials)

    def load_credentials(self):
        # Load encrypted credentials and decrypt them using XOR
        if os.path.isfile("xor_key_coinbase.txt"):
            with open("xor_key_coinbase.txt", "r") as key_file:
                encrypted_data = key_file.read()
                if self.xor_cipher is not None:
                    decrypted_data = self.xor_cipher.decrypt(encrypted_data)
                    self.api_key, self.api_secret, self.email, self.password = decrypted_data.split("\n")
                    # Clear previous entries if they exist
                    self.api_key_entry.delete(0, tk.END)
                    self.api_secret_entry.delete(0, tk.END)
                    self.email_entry.delete(0, tk.END)
                    self.password_entry.delete(0, tk.END)

    def save_credentials(self):
        # Encrypt and save credentials using XOR
        try:
            if self.xor_cipher is None:
                print("XOR cipher key not initialized.")
                return False

            credentials = f"{self.api_key}\n{self.api_secret}\n{self.email}\n{self.password}"
            encrypted_credentials = self.xor_cipher.encrypt(credentials)
            with open("xor_key_coinbase.txt", "w") as key_file:
                key_file.write(encrypted_credentials)

            return True
        except Exception as e:
            print(f"Error saving credentials: {str(e)}")
            return False

    def initialize_exchange(self):
        # Initialise l'échange en utilisant les clés API
        if not self.api_key or not self.api_secret:
            self.api_status_label.config(text="API Keys non valides", fg="red")
            if self.connect_button:
                self.connect_button.config(text="Reconnecter", command=self.show_credentials_window)
            return None

        try:
            exchange = ccxt.coinbase({
                'apiKey': self.api_key,
                'secret': self.api_secret,
            })

            exchange.load_markets()  
            self.update_api_status_label()
            return exchange
        except ccxt.AuthenticationError as e:
            self.api_status_label.config(text="Coinbase API Not Connected", fg="red")
            if self.connect_button:
                self.connect_button.config(text="Reconnecter", command=self.show_credentials_window)
            logging.error(f"Erreur lors de la connexion à l'API: {str(e)}")
            return None
        except Exception as e:
            self.api_status_label.config(text=f"Erreur: {str(e)}", fg="red")
            if self.connect_button:
                self.connect_button.config(text="Reconnecter", command=self.show_credentials_window)
            logging.error(f"Erreur lors de la connexion à l'API: {str(e)}")

        except ccxt.BaseError as e:
            print(f"Erreur d'initialisation de l'échange: {str(e)}")
            return None

    def initialize_ui(self):
        # Initialise l'interface utilisateur (UI)
        root = tk.Tk()
        root.title("TRADING COINBASE BOT AVHIRAL V7.8")
        root.geometry("800x500")

        self.credentials_window = tk.Toplevel(root)
        self.credentials_window.title("Informations Sensibles")
        self.credentials_window.geometry("400x410")

        api_key_label = tk.Label(self.credentials_window, text="API Key:")
        api_key_label.pack(pady=5)
        self.api_key_entry = tk.Entry(self.credentials_window)
        self.api_key_entry.pack(pady=5)

        api_secret_label = tk.Label(self.credentials_window, text="API Secret:")
        api_secret_label.pack(pady=5)
        self.api_secret_entry = tk.Entry(self.credentials_window)
        self.api_secret_entry.pack(pady=5)

        email_label = tk.Label(self.credentials_window, text="Email:")
        email_label.pack(pady=5)
        self.email_entry = tk.Entry(self.credentials_window)
        self.email_entry.pack(pady=5)

        password_label = tk.Label(self.credentials_window, text="Password:")
        password_label.pack(pady=5)
        self.password_entry = tk.Entry(self.credentials_window, show="*")
        self.password_entry.pack(pady=5)

        # Activer les champs API et Email pour la saisie
        self.api_key_entry.config(state=tk.NORMAL)
        self.api_secret_entry.config(state=tk.NORMAL)
        self.email_entry.config(state=tk.NORMAL)
        self.password_entry.config(state=tk.NORMAL)

        if os.path.isfile("xor_key_coinbase.txt"):
            self.load_credentials()
            self.api_key_entry.config(state=tk.DISABLED)
            self.api_secret_entry.config(state=tk.DISABLED)
            self.email_entry.config(state=tk.DISABLED)
            self.password_entry.config(state=tk.DISABLED)

        self.remember_credentials_var = tk.IntVar()
        remember_credentials_checkbox = tk.Checkbutton(self.credentials_window, text="Sauvegarder les informations",
                                                       variable=self.remember_credentials_var)
        remember_credentials_checkbox.pack(pady=10)

        daily_profit_label = tk.Label(self.credentials_window, text="Somme en euros souhaitée par jour:")
        daily_profit_label.pack(pady=5)
        self.daily_profit_entry = tk.Entry(self.credentials_window)
        self.daily_profit_entry.pack(pady=5)

        go_for_trading_button = tk.Button(self.credentials_window, text="Go for Trading", command=self.go_for_trading)
        go_for_trading_button.pack(pady=10)

        self.api_status_label = tk.Label(root, text="", font=("Helvetica", 14))
        self.api_status_label.pack(pady=10)

        self.connect_button = tk.Button(root, text="Connecter", command=self.show_credentials_window)
        self.connect_button.pack(pady=10)

        self.log_text = tk.Text(root, wrap=tk.WORD, width=80, height=20)
        self.log_text.pack()

        sys.stdout = self.TextRedirector(self.log_text, "stdout")

        frame = ttk.Frame(root)
        frame.pack(side=tk.TOP, padx=10, pady=10)

        chart_container = ttk.Frame(frame)
        chart_container.grid(row=0, column=0, padx=10, pady=10)

        root.protocol("WM_DELETE_WINDOW", self.on_closing)  

        root.mainloop()

    class TextRedirector(object):
        def __init__(self, widget, tag="stdout"):
            self.widget = widget
            self.tag = tag

        def write(self, str):
            self.widget.config(state=tk.NORMAL)
            self.widget.insert(tk.END, str)
            self.widget.config(state=tk.DISABLED)
            self.widget.see(tk.END)
            self.widget.update()

    def go_for_trading(self):
        daily_profit_target_text = self.daily_profit_entry.get()
        if not daily_profit_target_text:
            print("Veuillez entrer une somme en euros souhaitée par jour.")
            return
        daily_profit_target_euros = float(daily_profit_target_text)
        self.daily_profit_target_euros = daily_profit_target_euros

        self.api_key = self.api_key_entry.get()
        self.api_secret = self.api_secret_entry.get()
        self.email = self.email_entry.get()
        self.password = self.password_entry.get()
    
        # Créez la clé ici, après avoir obtenu les informations de l'utilisateur
        self.load_key()
    
        if self.remember_credentials_var.get():
            self.encrypt_and_save_credentials()

        # Activer les champs API et Email pour la saisie
        self.api_key_entry.config(state=tk.NORMAL)
        self.api_secret_entry.config(state=tk.NORMAL)
        self.email_entry.config(state=tk.NORMAL)
        self.password_entry.config(state=tk.NORMAL)

        self.credentials_window.withdraw()

        self.exchange = self.initialize_exchange()
        if not self.exchange:
            self.api_status_label.config(text="API Keys non valides", fg="red")
            if self.connect_button:
                self.connect_button.config(text="Reconnecter", command=self.show_credentials_window)
            return

        self.update_api_status_label()

        if self.exchange:
            self.thread = threading.Thread(target=self.execute_strategy)
            self.thread.start()

    def show_credentials_window(self):
        self.api_key_entry.delete(0, tk.END)
        self.api_secret_entry.delete(0, tk.END)
        self.email_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        if self.api_key and self.api_secret and self.email and self.password:
            self.api_key_entry.insert(0, self.api_key)
            self.api_secret_entry.insert(0, self.api_secret)
            self.email_entry.insert(0, self.email)
            self.password_entry.insert(0, self.password)
        self.credentials_window.deiconify()

    def update_api_status_label(self):
        try:
            if self.exchange:
                self.exchange.load_markets()
                self.api_status_label.config(text="BOT AVHIRAL API Connected Success", fg="green")
                if self.connect_button:
                    self.connect_button.config(text="Tout va bien", state=tk.DISABLED)
            else:
                self.api_status_label.config(text="API Keys non valides", fg="red")
                if self.connect_button:
                    self.connect_button.config(text="Reconnecter", command=self.show_credentials_window)
        except ccxt.AuthenticationError as e:
            self.api_status_label.config(text="BOT AVHIRAL API Not Connected", fg="red")
            if self.connect_button:
                self.connect_button.config(text="Reconnecter", command=self.show_credentials_window)
            logging.error(f"Erreur lors de la connexion à l'API: {str(e)}")
        except Exception as e:
            self.api_status_label.config(text=f"Erreur: {str(e)}", fg="red")
            if self.connect_button:
                self.connect_button.config(text="Reconnecter", command=self.show_credentials_window)
            logging.error(f"Erreur lors de la connexion à l'API: {str(e)}")

    def on_closing(self):
        if self.thread and self.thread.is_alive():
            self.exchange = None  
            self.thread.join()  
        self.save_credentials()  
        self.credentials_window.destroy()  

    def create_chart(self, pair):
        fig, ax = self.charts.get(pair, (None, None))
        if fig is None and ax is None:
            fig = Figure(figsize=(8, 4), dpi=100)
            ax = fig.add_subplot(111)
            ax.set_title(f"Graphique des prix ({pair})")
            canvas = FigureCanvasTkAgg(fig, master=chart_container)
            canvas.get_tk_widget().pack()
            self.charts[pair] = (fig, ax)
        return fig, ax

    def get_crypto_pairs(self):
        try:
            markets = self.exchange.load_markets()
            crypto_pairs = [pair for pair in markets if pair.endswith('/USD')]
            filtered_pairs = []

            for pair in crypto_pairs:
                ticker = self.exchange.fetch_ticker(pair)
                if 'info' in ticker and 'status' in ticker['info'] and ticker['info']['status'] == 'TRADING':
                    volume_threshold = 100000  # Définissez le seuil de volume souhaité
                    if isinstance(ticker['info']['volume'], (int, float)) and ticker['info']['volume'] > volume_threshold:
                        filtered_pairs.append(pair)
                    else:
                        print(f"Le produit {pair} a un volume insuffisant.")
                        logging.info(f"Le produit {pair} a un volume insuffisant.")
                else:
                    print(f"Le produit {pair} n'est pas disponible pour le trading.")
                    logging.info(f"Le produit {pair} n'est pas disponible pour le trading.")

            return filtered_pairs

        except ccxt.DDoSProtection as e:
            print(f"Erreur lors de la récupération des paires de trading (DDoSProtection): {str(e)}")
            logging.error(f"Erreur lors de la récupération des paires de trading (DDoSProtection): {str(e)}")
            return []
        except ccxt.NetworkError as e:
            print(f"Erreur lors de la récupération des paires de trading (NetworkError): {str(e)}")
            logging.error(f"Erreur lors de la récupération des paires de trading (NetworkError): {str(e)}")
            return []
        except Exception as e:
            print(f"Erreur lors de la récupération des paires de trading: {str(e)}")
            logging.error(f"Erreur lors de la récupération des paires de trading: {str(e)}")
            return []

    def execute_strategy(self):
        while self.exchange:
            try:
                print("Chargement des paires de trading...")
                self.crypto_pairs = self.get_crypto_pairs()

                if not self.crypto_pairs:
                    print("Aucune paire de trading disponible pour le moment.")
                    time.sleep(REFRESH_INTERVAL)
                    continue

                for pair in self.crypto_pairs:
                    fig, ax = self.create_chart(pair)

                    # Charger les données historiques du graphique
                    ohlcv = self.exchange.fetch_ohlcv(pair, timeframe='1d', limit=365)
                    df = pd.DataFrame(ohlcv, columns=['timestamp', 'open', 'high', 'low', 'close', 'volume'])
                    df['timestamp'] = pd.to_datetime(df['timestamp'], unit='ms')
                    df.set_index('timestamp', inplace=True)

                    # Exclure les produits délistés ou avec un volume insuffisant
                    if df.empty:
                        continue

                    # Calculer la moyenne mobile sur 30 jours
                    df['30d'] = df['close'].rolling(window=30).mean()

                    # Mettre à jour le graphique
                    ax.clear()
                    ax.plot(df.index, df['close'], label='Prix de clôture', linewidth=1)
                    ax.plot(df.index, df['30d'], label='Moyenne mobile 30 jours', linestyle='--', linewidth=1)
                    ax.set_title(f"Graphique des prix ({pair})")
                    ax.legend()

                time.sleep(REFRESH_INTERVAL)
            except Exception as e:
                print(f"Erreur lors de l'exécution de la stratégie: {str(e)}")
                logging.error(f"Erreur lors de l'exécution de la stratégie: {str(e)}")


if __name__ == "__main__":
    bot = TradingBot()
