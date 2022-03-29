# On suppose que listeTrace contient une trame nettoyée
# Chaque case de liseTrace contient un octet

# Ethernet en-tête = 14 octets
# listeTrace d'Ethernet va de la position 0 jusqu'au 14 non inclus (pas d'offset)
import sys
# ----------------------------------------------------------------------------- #
def analyse_ethernet(listeTrace, nomFichierEcriture, nbEth):
  # Fichier ou on ecrira les erreur possibles de l'analyse Ethernet
  writer = open("Trames/Analyse/Erreur_analyse_trames.txt", 'a')
  writer.write("------------------------ Trame : "+str(nbEth)+" ----------------------------------\n")
  # Verification si les octets du segment Ethernet existent bien
  try:
    listeTrace[0]   # Verification du premier octet du segment Ethernet
    listeTrace[13]  # Verification du dernier octet du segment Ethernet
  # On annonce une erreur si pb. sur l'indice
  except IndexError:
    print("=== Erreur: En-tête Ethernet incomplete ===")
    writer.write("=== Erreur: En-tête Ethernet incomplete ===\n")
    return 0        # Sortie du programme


  # On prend touts les champs en hexa:
  # listeDest contient les octets 0 à 5 de listeTrace
  listeDest = listeTrace[:6]
  # listeSrc contient les octete 6 à 11 de listeTrace
  listeSrc = listeTrace[6:12]
  #listeType continet les octets 12 à 13 de listeTrace
  listeType = listeTrace[12:14]

  # Construction des adresses MAC 
  macDest = mac_construire(listeDest)
  macSrc = mac_construire(listeSrc)

  # Assemblage des deux octets du champs type
  etherType = listeType[0]+listeType[1]


  # Verification si IPv6
  if (int(etherType, 16) == int("86DD", 16)):
    print("=== Erreur: Il s'agit d'une trame contenant du IPv6, la version actuelle de cet analyseur ne permet pas son etude ===")
    writer.write("=== Erreur: Il s'agit d'une trame contenant du IPv6, la version actuelle de cet analyseur ne permet pas son etude ===\n")
    return 0   # On ne pourra pas etudier la suite de la trame 

  # Verification si ARP
  elif (int(etherType, 16) == int("0806", 16)):
    print("=== Erreur: Il s'agit d'une trame contenant du ARP, la version actuelle de cet analyseur ne permet pas son etude ===")
    writer.write("=== Erreur: Il s'agit d'une trame contenant du ARP, la version actuelle de cet analyseur ne permet pas son etude ===\n")
    return 0   # On ne pourra pas etudier la suite de la trame   

  # Verification si autre chose que IPv4/IPv6 
  elif (etherType != "0800"):
    print("=== Erreur: Il ne s'agit pas d'une trame contenant du IPv4, la version actuelle de cet analyseur ne permet pas son etude ===")
    writer.write("=== Erreur: Il ne s'agit pas d'une trame contenant du IPv4, la version actuelle de cet analyseur ne permet pas son etude ===\n")
    return 0   # On ne pourra pas etudier la suite de la trame 

  # On ferme le fichier car on a plus rien à ecrire
  writer.close()

  # Affichage de la trame dans la console et dans le fichier "nomFichierEcriture"
  affichage_ethernet(nomFichierEcriture, macSrc, macDest, etherType, nbEth)
  
  return 
# ----------------------------------------------------------------------------- #
def mac_construire(listeOctetsMac):
  mac = ''
  # On parcourt tous les octets de l'adresse MAC
  for i in range(6):
    mac += listeOctetsMac[i] + ":"
    
  return mac[:-1]   # En supprimant le dernier caractere ':'
# ----------------------------------------------------------------------------- #
def affichage_ethernet(nomFichierEcriture, macSrc, macDest, etherType, nbEth):
  # Ouverture du fichier pour ecrire les données
  writer = open("Trames/Analyse/"+nomFichierEcriture, 'a')

  # Affichage sur la console et ecriture dans le fichier
  print("------------------------ Trame: "+str(nbEth)+" ----------------------------------")
  writer.write("------------------------ Trame : "+str(nbEth)+" ----------------------------------\n")

  # Affichage trame Ethernet
  print(">>Ethernet II, Src: " + macSrc + ", Dst: " + macDest)
  writer.write(">>Ethernet II, Src: " + macSrc + ", Dst: " + macDest + "\n")

  # Affichage macDest
  print("\t>Destination: " + macDest)
  writer.write("\t>Destination: " + macDest + "\n")

  # Affichage macSrc
  print("\t>Source: " + macSrc)
  writer.write("\t>Source: " + macSrc + "\n")

  # Affichage type
  print("\t>Type: IPv4 0x"+etherType)
  writer.write("\t>Type: IPv4 0x"+etherType+"\n")
  
  # Fermeture du fichier
  writer.close()
  return 
# ----------------------------------------------------------------------------- #