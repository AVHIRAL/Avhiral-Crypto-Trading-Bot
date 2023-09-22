import secrets

# Générer une clé XOR aléatoire de 16 caractères (vous pouvez ajuster la longueur)
xor_key = secrets.token_hex(8)

print("Clé XOR générée :")
print(xor_key)

# Enregistrez cette clé dans un fichier si nécessaire
with open("KEY_XOR_GENERATOR.txt", "w") as key_file:
    key_file.write(xor_key)
