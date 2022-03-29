from ip import hex_to_decimal
# On suppose que listeTrace contient une trame Ethernet nettoyée
# Chaque case de liseTrace contient un octet

# UDP entete = 8 octets
# ----------------------------------------------------------------------------- #
def analyse_udp(listeTrace, nomFichierEcriture, indiceFinIP):
  # Fichier ou on ecrira les erreur possibles de l'analyse UDP
  writer = open("Trames/Analyse/Erreur_analyse_trames.txt", 'a') 
  
  # Verification si les octets du segment IP existent bien
  try:
    indiceFinUDP = indiceFinIP
    listeTrace[indiceFinUDP]      # Verification du premier octet du segment UDP
    listeTrace[indiceFinUDP+7]    # Verification du dernier octet du segment UDP
  # On annonce une erreur si pb. sur l'indice
  except IndexError:  
    print("==== Erreur avec la taille du paquet UDP ====")
    writer.write("=== Erreur avec la taille du paquet UDP ===\n")
    return 0                       # Sortie du programme

  # On prend tous les champs en héxa:
  # Récuperation des ports source et destination
  portSrc = listeTrace[indiceFinUDP] + listeTrace[indiceFinUDP+1]
  indiceFinUDP += 2
  portDest = listeTrace[indiceFinUDP] + listeTrace[indiceFinUDP+1] 
  indiceFinUDP += 2

  # DNS => port 53
  # DHCP => port 67 ou 68
  DHCP = True

  if (int(portDest, 16) == 53 or int(portSrc, 16) == 53):
    DHCP = False
  elif ((int(portDest, 16) or int(portSrc, 16)) in {67, 68}):
    DHCP = True
  else:
    print("===== Erreur le port de destination et/ou source ne correspond pas aux numero de port de DNS(53) ou DHCP (67/68) =====")
    writer.write("===== Erreur le port de destination et/ou source ne   correspond pas aux numero de port de DNS(53) ou DHCP (67/68) =====" + "\n")
    return 0
      
  
  # Récuperation du champs Length
  longueur = listeTrace[indiceFinUDP] + listeTrace[indiceFinUDP+1]
  indiceFinUDP += 2

  # Récuperation du checksum
  checksum = listeTrace[indiceFinUDP] + listeTrace[indiceFinUDP+1] # ######## 0x
  indiceFinUDP += 2

  # Affichage de la couche UDP dans la console et dans le fichier "nomFichierEcriture"
  affichage_udp(nomFichierEcriture, portSrc, portDest, checksum, longueur)

  # Si DHCP=True alors c'est du DHCP sinon c'est du DNS
  return (indiceFinUDP, DHCP)    
# ----------------------------------------------------------------------------- #
def affichage_udp(nomFichierEcriture, portSrc, portDest, checksum, longueur):
  # Ouverture fichier a ecrire les donnees
  writer = open("Trames/Analyse/"+nomFichierEcriture, 'a')

  # Affichage sur la console et ecriture dans le fichier
  print(">>User Datagram Protocol, Src Port: "+str(hex_to_decimal(portSrc))+", Dst Port: "+str(hex_to_decimal(portDest)));
  writer.write(">>User Datagram Protocol, Src Port: "+str(hex_to_decimal(portSrc))+", Dst Port: "+str(hex_to_decimal(portDest))+'\n');

  # Affichage et ecriture du port source
  print("\tSource Port: "+str(hex_to_decimal(portSrc)));
  writer.write("\tSource Port: "+str(hex_to_decimal(portSrc))+"\n")

  # Affichage et ecriture du port destination
  print("\tDestination Port: "+str(hex_to_decimal(portDest)));
  writer.write("\tDestination Port: "+str(hex_to_decimal(portDest))+"\n");

  # Affichage et ecriture de la longueur
  print("\tLength: "+str(hex_to_decimal(longueur)));
  writer.write("\tLength: "+str(hex_to_decimal(longueur))+"\n");

  #affichage checksum
  print("\tChecksum: 0x"+checksum);
  writer.write("\tChecksum: 0x"+checksum+"\n"); 
  
  # Fermeture du fichier
  writer.close()

  return
# ----------------------------------------------------------------------------- #
