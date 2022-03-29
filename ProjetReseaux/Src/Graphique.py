from tkinter import *
import webbrowser

import main as ma
# --------------------------------------------------------------------------- #
def ouvrir_main():
    ma.main()
# --------------------------------------------------------------------------- #
def open_youtube():
    webbrowser.open_new("https://www.youtube.com/channel/UCQ8LwKn9Z6-AFXvfHfR8R9w")
# --------------------------------------------------------------------------- #
def enregistrer_trame():
    print(trameEntree.get())
# --------------------------------------------------------------------------- #
# Creation d'un premiere fenetre
window = Tk()

# Personnalisation de cette fenetre
window.title("WireStudent")             # Titre de la fenetre
window.geometry("1080x720")             # Taille par defaut de la fenetre
window.minsize(1080, 720)                # Taille minimale de la fenetre
window.config(background='#8A81B5')     # Couleur du background

# Ajout du logo a notre fenetre
img = PhotoImage(file = "Images/Logo.gif")
window.tk.call("wm", "iconphoto", window._w, img)

# Creation de la frame
frame = Frame(window, bg='#8A81B5')

# Ajout du 1er texte
label_title = Label(frame, text="WireStudent", font=("Courier", 38), bg='#8A81B5', fg='white')
label_title.pack()


# Ajout du 2nd texte
label_subtitle = Label(frame, text="Bienvenue sur l'analyseur de paquets\n fait par des etudiants pour des etudiants", font=('Courier', 20, 'italic'), bg='#8A81B5', fg='white')
label_subtitle.pack()

# Ajout de la frame
frame.pack(expand=YES)

# Ajout du 1er boutton
startBoutton = Button(frame, text="Appuyer ici", font=("Courier", 20), bg='white', fg='#8A81B5', command=ouvrir_main)
startBoutton.pack(pady=25, fill=X)

# Ajout du champs ou mettre la trace
frameTrace = Frame(frame, bg='#8A81B5')
traceTitre = Label(frameTrace, text="Entrez votre trace a analyser", font=("Courier", 20), bg='#8A81B5', fg='white')
traceTitre.pack()

entreeTrace = Entry(frameTrace, font=("Courier", 20), bg='#8A81B5', fg='white')

# Creation d'une barre de menu
menuBarre = Menu(window)

# Creation du premier menu
fileMenu = Menu(menuBarre, tearoff=0)
fileMenu.add_command(label="Source d'inspiration", command=open_youtube)
fileMenu.add_command(label="Quitter", command=window.quit)
menuBarre.add_cascade(label="Fichier", menu=fileMenu)

# Ajout du menu a notre fenetre
window.config(menu=menuBarre)


# Affichage de la fenetre
window.mainloop()
