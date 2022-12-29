import analyse_traces as AT
import ethernet as Eth
import ip as IP
import udp as UDP
import dhcp as DHCP
import dns as DNS


import tkinter as tk
from tkinter import filedialog

#----------------------------------------------------------------------------#
def chercher_chemin():
    window=tk.Tk()
    window.withdraw()

    chemin = filedialog.askopenfilename()

    return chemin
#----------------------------------------------------------------------------#
def main():
  nomFichierAnalyser = chercher_chemin()
  fichierNettoye = AT.nettoyage_regulier(nomFichierAnalyser, "Trames/Traces_nettoyes.txt");
  # Nettoyage complet du fichier (il ne manque plus qu'à analyser) 
  fichierParfait = AT.nettoyage_traces(fichierNettoye, "Trames/Traces_parfaites.txt")
  # Transformation en une liste de listes, chaque liste representant une trame 
  listeTrames = AT.listes_octets_trames(fichierParfait)

  # Fichier ou on aura les resultats de l'analyse
  analyseTrames = "Analyse_trames.txt"

  # Nettoyage des fichier.txt avant d'ecrire dedans 
  open("Trames/Analyse/Analyse_trames.txt", 'w').close()
  open("Trames/Analyse/Erreur_analyse_trames.txt", 'w').close()

  
  
  for i in range(len(listeTrames)):
    Eth.analyse_ethernet(listeTrames[i], analyseTrames, i+1)
    indiceFinIP, tailleTrame = IP.analyse_ip(listeTrames[i], analyseTrames)
    indiceFinUDP, dhcp = UDP.analyse_udp(listeTrames[i], analyseTrames, indiceFinIP)

    # Si DHCP:
    if (dhcp):
      DHCP.analyse_dhcp(listeTrames[i], analyseTrames, indiceFinUDP, tailleTrame)
    # Si DNS: 
    else:
      DNS.analyse_dns(listeTrames[i], analyseTrames, indiceFinUDP)

        
  return
#----------------------------------------------------------------------------#
