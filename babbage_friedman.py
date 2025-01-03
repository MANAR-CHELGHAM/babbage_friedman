import numpy as np
from collections import Counter
import tkinter as tk
from tkinter import messagebox

# Fonction pour calculer l'indice de coïncidence
def indice_coincidence(text):
    n = len(text)
    if n <= 1:
        return 0
    freq = Counter(text)
    IC = sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))
    return IC

# Fonction pour trouver la longueur probable de la clé
def longueur_cle_probable(text, max_len=20):
    ICs = []
    for k in range(1, max_len + 1):
        segments = [text[i::k] for i in range(k)]
        if any(len(segment) <= 1 for segment in segments):
            ICs.append(0)
        else:
            ICs.append(np.mean([indice_coincidence(segment) for segment in segments]))
    return ICs.index(max(ICs)) + 1 if ICs else 1

# Fonction pour chiffrer le texte
def chiffrer_vigenere(text, key):
    if len(key) == 0:
        raise ValueError("La clé ne peut pas être vide.")
    key = key.upper()
    encrypted = []
    key_len = len(key)
    for i, char in enumerate(text):
        if char.isalpha():
            shift = ord(key[i % key_len]) - ord('A')
            encrypted_char = chr((ord(char) + shift - ord('A')) % 26 + ord('A'))
            encrypted.append(encrypted_char)
        else:
            encrypted.append(char)
    return ''.join(encrypted)

# Fonction pour déchiffrer le texte
def dechiffrer_vigenere(text, key):
    if len(key) == 0:
        raise ValueError("La clé ne peut pas être vide.")
    key = key.upper()
    decrypted = []
    key_len = len(key)
    for i, char in enumerate(text):
        if char.isalpha():
            shift = ord(key[i % key_len]) - ord('A')
            decrypted_char = chr((ord(char) - shift - ord('A')) % 26 + ord('A'))
            decrypted.append(decrypted_char)
        else:
            decrypted.append(char)
    return ''.join(decrypted)

# Estimer la clé avec analyse fréquentielle
def estimer_cle(text, key_len):
    subtexts = [''.join(text[i::key_len]) for i in range(key_len)]
    key = ''
    for subtext in subtexts:
        freq = Counter(subtext)
        most_common = freq.most_common(1)[0][0]
        shift = (ord(most_common) - ord('E')) % 26
        key += chr(shift + ord('A'))
    return key

# Estimer la clé avec indice de coïncidence
def estimer_cle_IC(text, key_len):
    subtexts = [''.join(text[i::key_len]) for i in range(key_len)]
    key = ''
    for subtext in subtexts:
        freq = Counter(subtext)
        most_common = freq.most_common(1)[0][0]
        shift = (ord(most_common) - ord('E')) % 26
        key += chr(shift + ord('A'))
    return key

# Interface graphique
def creer_interface():
    def chiffrer():
        try:
            texte = entree_texte.get("1.0", tk.END).strip().upper()
            cle = entree_cle.get().upper()
            resultat = chiffrer_vigenere(''.join(filter(str.isalpha, texte)), cle)
            champ_resultat.delete("1.0", tk.END)
            champ_resultat.insert(tk.END, resultat)
        except ValueError as e:
            messagebox.showerror("Erreur", str(e))

    def dechiffrer():
        try:
            texte = entree_texte.get("1.0", tk.END).strip().upper()
            cle = entree_cle.get().upper()
            resultat = dechiffrer_vigenere(''.join(filter(str.isalpha, texte)), cle)
            champ_resultat.delete("1.0", tk.END)
            champ_resultat.insert(tk.END, resultat)
        except ValueError as e:
            messagebox.showerror("Erreur", str(e))

    def analyser_frequentiel():
        texte = entree_texte.get("1.0", tk.END).strip().upper()
        texte = ''.join(filter(str.isalpha, texte))
        key_len = longueur_cle_probable(texte)
        cle_estimee = estimer_cle(texte, key_len)
        champ_resultat.delete("1.0", tk.END)
        champ_resultat.insert(tk.END, f"Clé estimée : {cle_estimee}")

    def analyser_IC():
        texte = entree_texte.get("1.0", tk.END).strip().upper()
        texte = ''.join(filter(str.isalpha, texte))
        key_len = longueur_cle_probable(texte)
        cle_estimee = estimer_cle_IC(texte, key_len)
        champ_resultat.delete("1.0", tk.END)
        champ_resultat.insert(tk.END, f"Clé estimée : {cle_estimee}")

    fenetre = tk.Tk()
    fenetre.title("Chiffre de Vigenère")

    tk.Label(fenetre, text="Texte :").pack()
    entree_texte = tk.Text(fenetre, height=5, width=50)
    entree_texte.pack()

    tk.Label(fenetre, text="Clé :").pack()
    entree_cle = tk.Entry(fenetre)
    entree_cle.pack()

    tk.Button(fenetre, text="Chiffrer", command=chiffrer).pack()
    tk.Button(fenetre, text="Déchiffrer", command=dechiffrer).pack()
    tk.Button(fenetre, text="Analyse fréquentielle", command=analyser_frequentiel).pack()
    tk.Button(fenetre, text="Analyse IC", command=analyser_IC).pack()

    tk.Label(fenetre, text="Résultat :").pack()
    champ_resultat = tk.Text(fenetre, height=5, width=50)
    champ_resultat.pack()

    fenetre.mainloop()

if __name__ == "__main__":
    creer_interface()
