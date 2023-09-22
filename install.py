import subprocess

# Liste des dépendances à installer
dependencies = [
    "ccxt",
    "pandas",
    "matplotlib",
]

def install_dependencies():
    for package in dependencies:
        try:
            subprocess.check_call(["pip", "install", package])
            print(f"Installation de {package} réussie.")
        except subprocess.CalledProcessError:
            print(f"Erreur lors de l'installation de {package}.")
        except Exception as e:
            print(f"Erreur inattendue : {str(e)}")

if __name__ == "__main__":
    print("Installation des dépendances en cours...")
    install_dependencies()
    print("Toutes les dépendances ont été installées avec succès.")
