# On suppose que listeTrace contient une trame nettoyée
# Chaque case de listeTrace contient un octet

# Sans options = la listeTrace de l'en-tête IP va de la position 14 jusqu'au 34 non inclus
# ### Si options => [14: ?]
# Total length = en-tête IP + données
#              = IHL*4 + données => IHL*4 = IP + options + padding
#                               <=> options+padding = IHL*4 - IP = IHL*4 - 20

# ----------------------------------------------------------------------------- #
def analyse_ip(listeTrace, nomFichierEcriture):
  # Fichier ou on ecrira les erreur possibles de l'analyse IP
  writer = open("Trames/Analyse/Erreur_analyse_trames.txt", 'a')

  # Verification si les octets du segment IP existent bien
  try:
    indiceFinEthernet = 14
    listeTrace[indiceFinEthernet]    # Verification du premier octet du segment IP
    indiceFinIP = int((listeTrace[14])[1], 16)*4 + 14
    listeTrace[indiceFinIP]    # Verification du dernier octet du segment IP
  # On annonce une erreur si pb. sur l'indice
  except IndexError:
    print("==== Erreur avec la taille paquet ip====")
    writer.write("==== Erreur avec la taille paquet ip====\n")
    return 0          # Sortie du programme

  # On prend touts les champs en hexa:
  # Version IP
  versionIP = (listeTrace[indiceFinEthernet])[0]

  # IHL (IHL*4 = IHL mots sur de 32 bits(4 octets) = longueur de l'entete IP)
  ihl = (listeTrace[indiceFinEthernet])[1]
  indiceFinEthernet += 1

  # TOS (Type of serive) ##### pas utilise dans WireShark ?
  tos = listeTrace[indiceFinEthernet]
  indiceFinEthernet += 1

  # Longueur totale du datagramme
  totalLength = listeTrace[indiceFinEthernet] + listeTrace[indiceFinEthernet+1]
  indiceFinEthernet += 2

  # Identification
  identification = listeTrace[indiceFinEthernet]+listeTrace[indiceFinEthernet+1]
  indiceFinEthernet += 2

  # Flags (on prend un octet)
  flags = listeTrace[indiceFinEthernet]

  # Drapeaux sur 3 bits + fragment offset sur 13 bits en binaire = 16 bits
  flagsEtFragmentOffset = listeTrace[indiceFinEthernet]+listeTrace[indiceFinEthernet+1]
  indiceFinEthernet += 2

  # TTL (time to live)
  ttl = listeTrace[indiceFinEthernet]
  indiceFinEthernet += 1

  # Protocol
  protocol = listeTrace[indiceFinEthernet]
  indiceFinEthernet += 1

  # Checksum
  headerChecksum = listeTrace[indiceFinEthernet] + listeTrace[indiceFinEthernet+1]
  indiceFinEthernet += 2

  # Adresse IP source
  IPsrc = listeTrace[indiceFinEthernet:indiceFinEthernet+4]
  indiceFinEthernet += 4

  # Adresse IP destination
  IPdest = listeTrace[indiceFinEthernet:indiceFinEthernet+4]
  indiceFinEthernet += 4


  # Si les deux idnices sont identhiques => pas d'options
  if (indiceFinEthernet == indiceFinIP):
    # Affichage de l'en-tête IP sans options uniquement
    affichage_ip(nomFichierEcriture, IPsrc, IPdest, versionIP, ihl, totalLength, identification, flags, flagsEtFragmentOffset, ttl, protocol, headerChecksum)

  # Si l'indice de la fin des 20 octets d'en-tête est < que l'indice de la d'en-tête IP => on a des  options
  elif (indiceFinEthernet < indiceFinIP):
    # Affichage de l'en-tête IP sans options
    affichage_ip(nomFichierEcriture, IPsrc, IPdest, versionIP, ihl, totalLength, identification, flags, flagsEtFragmentOffset, ttl, protocol, headerChecksum)

    # Affichage des options IP
    affichage_options_ip(listeTrace, nomFichierEcriture, indiceFinEthernet, indiceFinIP)

  # Si le protocol n'est pas UDP alors on ne sait pas l'analyser
  #### SWITCH avec les autres protocoles qu'on connait
  if (int(protocol, 16) != 17):
    print("=== Erreur: Il ne s'agit pas d'une trame contenant un protocol UDP, la version actuelle de cet analyseur ne permet pas son etude ===")
    writer.write("=== Erreur: Il ne s'agit pas d'une trame contenant du protocol UDP, la version actuelle de cet analyseur ne permet pas son etude ===\n")

  # Fermeture du fichier
  writer.close()


  # On renvoie l'indice de la fin du datagramme d'IP et la taille totale de la trame
  return (indiceFinIP, int(totalLength, 16)+14)
# ----------------------------------------------------------------------------- #
def hex_to_decimal(chaine):
  # Convertir une chaine de caracteres exprimée en hexa en un int
  return int(chaine, 16)
# ----------------------------------------------------------------------------- #
def hex_to_bin(chaineHex):
  # Renvoie la valeur chaineHex convertie en binaire de longueur de 16 bits
  # eg: chaineHex="001A" => 0000 0000 0001 1010
  return format(int(chaineHex, 16), 'b').zfill(16)
# ----------------------------------------------------------------------------- #
def decimal_to_bin(entier):
  return format(entier, '04b')
# ----------------------------------------------------------------------------- #
def bin_to_decimal(stringBin):
  return int(stringBin, 2)
# ----------------------------------------------------------------------------- #
def id_construire(identification):
  return "0x" + identification + " ("+str(hex_to_decimal(identification)) + ")"
# ----------------------------------------------------------------------------- #
def ip_decimal(liste_ip_octets):
  return str(hex_to_decimal(liste_ip_octets[0]))+"."+str(hex_to_decimal(liste_ip_octets[1]))+"."+str(hex_to_decimal(liste_ip_octets[2]))+"."+str(hex_to_decimal(liste_ip_octets[3]))
# ----------------------------------------------------------------------------- #
def affichage_ip(nomFichierEcriture, IPsrc, IPdest, versionIP, ihl, totalLength, identification, flags, flagsEtFragmentOffset, ttl, protocol, headerChecksum):
  # Ouverture fichier a ecrire les données
  writer = open("Trames/Analyse/"+nomFichierEcriture, 'a')

  # Fichier ou on ecrira les erreur possibles de l'analyse IP
  writerErreurs = open("Trames/Analyse/Erreur_analyse_trames.txt", 'a')

  # Affichage et ecriture en-tête IP
  print(">>Internet Protocol Version 4, Src: "+ip_decimal(IPsrc)+", Dst: "+ip_decimal(IPdest))
  writer.write(">>Internet Protocol Version 4, Src: "+ip_decimal(IPsrc)+", Dst: "+ip_decimal(IPdest)+"\n")

  # Affichage et ecriture version IP
  print("\t" + str(decimal_to_bin(int(versionIP, 16))) + " .... = Version: " + str(hex_to_decimal(versionIP)))
  writer.write("\t" + str(decimal_to_bin(int(versionIP, 16))) + " .... = Version: " + str(hex_to_decimal(versionIP)) + "\n")

  # Affichage et ecriture longueur en-tête IP
  print("\t.... " + str(decimal_to_bin(int(ihl, 16)) + " = Header Length: " + str(hex_to_decimal(ihl)*4) + " bytes (" + ihl + ")"))
  writer.write("\t.... " + str(decimal_to_bin(int(ihl, 16))) + " = Header Length: " + str(hex_to_decimal(ihl)*4) + " bytes (" + ihl + ")\n")

  # Affichage section differentiated service
  print("\t>Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)")
  print("\t\t0000 00.. = Differentiated Services Codepoint: Default (0)")
  print("\t\t.... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)")

  writer.write("\t>Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)\n")
  writer.write("\t\t0000 00.. = Differentiated Services Codepoint: Default (0)\n")
  writer.write("\t\t.... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)\n")

  # Affichage et ecriture longueur totale
  print("\tTotal Length: " + str(hex_to_decimal(totalLength)))
  writer.write("\tTotal Length: " + str(hex_to_decimal(totalLength)) + "\n")

  # Affichage identification
  print("\tIdentification: " + id_construire(identification))
  writer.write("\tIdentification: " + id_construire(identification) + "\n")

  flagsEtFragmentOffsetBin = hex_to_bin(flagsEtFragmentOffset)

  # La valeur flag en binaire pour distinguer les 3 bits
  flagsBin = flagsEtFragmentOffsetBin[:3]

  # Affichage FLAGS ################## On affiche pas que les 3 bits ?
  print("\t>Flags: 0x" + flags, end ='')
  writer.write("\t>Flags: 0x" + flags)

  # Dictionnaire pour le bit reserve
  reservedBit = {
      0: "\n\t\t0... .... = Reserved bit: Not set",
      1: "\n\t\t1... .... = Reserved bit: Set"
  }
  # Afficher la valeur de cle correspondant a la valeur de bit R
  # se situant a la premiere case du tableau flagsEtFragmentOffset
  # s'il n'existe pas de cle demande, renvoyer Erreur Reserved Bit
  try:
    print(reservedBit.get(int(flagsBin[0])))
    writer.write(reservedBit.get(int(flagsBin[0]))+'\n')
  except IndexError:
    print("=== Erreur Reserved Bit ===")
    writerErreurs.write("=== Erreur Reserved Bit ===\n")
    return 0      # Sortie du programme

  # Dictionnaire pour bit DM
  dontFragment = {
      0: "\t\t.0.. .... = Don't fragment: Not set",
      1: "\t\t.1.. .... = Don't fragment: Set"
  }
  try:
    print(dontFragment.get(int(flagsBin[1])))
    writer.write(dontFragment.get(int(flagsBin[1])) + '\n')
  except IndexError:
    print("==== Erreur Don't fragment ====")
    writerErreurs.write("==== Erreur Don't fragment ====\n")
    return 0      # Sortie du programme

  # Dictionnaire pour bit MF
  moreFragment = {
      0: "\t\t..0. .... = More fragments: Not set",
      1: "\n\t\t..1. .... = More fragments: Set"
  }
  try:
    print(moreFragment.get(int(flagsBin[2])))
    writer.write(moreFragment.get(int(flagsBin[2]))+ '\n')
  except IndexError:
    print("=== Erreur More fragments ====")
    writerErreurs.write("==== Erreur More fragments ====\n")
    return 0      # Sortie du programme


  # Affichage et ecriture du fragment offset
  fragmentOffset =  bin_to_decimal(flagsEtFragmentOffsetBin[3:])
  print("\tFragment offset: " + str(fragmentOffset))
  writer.write("\tFragment offset: " + str(fragmentOffset) + "\n")

  # Affichage et ecriture du TTL
  print("\tTime to Live: " + str(hex_to_decimal(ttl)))
  writer.write("\tTime to Live: " + str(hex_to_decimal(ttl)) + "\n")

  # Affichage et ecriture du protocol (udp)
  print("\tProtocol: UDP (" + str(hex_to_decimal(protocol)) + ")")
  writer.write("\tProtocol: UDP (" +str(hex_to_decimal(protocol)) + ")" + "\n")

  # Affichge et ecriture de l'en-tete checksum
  print("\tHeader Checksum: " + str(hex_to_decimal(headerChecksum)))
  writer.write("\tHeader Checksum: " + str(hex_to_decimal(headerChecksum)) + "\n")

  # Affichage et ecriture de l'adresse IP source #### a nouveau ??
  print("\tSource Address: " + ip_decimal(IPsrc))
  writer.write("\tSource Address: " + ip_decimal(IPsrc) + "\n")

  # Affichage et ecriture de l'adresse IP destination #### a nouveau ?
  print("\tDestination Address: " + ip_decimal(IPdest))
  writer.write("\tDestination Address: " + ip_decimal(IPdest) + "\n")

  # Fermeture des deux fichiers d'ecriture
  writer.close()
  writerErreurs.close()


  return
# ----------------------------------------------------------------------------- #
def affichage_options_ip(listeTrace, nomFichierEcriture, indiceFinEthernet, indiceFinIP):
  # Ouverture fichier a ecrire les donnees
  writer = open("Trames/Analyse/"+nomFichierEcriture, 'a')

  ecritRR = False   # Aide pour ecriture
  ecritLSR = False  # Aide pour ecriture
  ecritTS = False   # Aide pour ecriture
  ecritSSR = False  # Aide pour ecriture

  # Affichage et ecriture des options
  print("\t>Options: ("+str(indiceFinIP-indiceFinEthernet)+" bytes), ", end='')
  writer.write("\t>Options: ("+str(indiceFinIP-indiceFinEthernet)+" bytes), ")
  # Parcourt de tous les octets des options
  i = indiceFinEthernet
  while (i<=indiceFinIP):
    # Affichage et ecriture de l'option End of Options List (EOL)
    if(int(listeTrace[i], 16) == 0):
      print("\t\t>IP Option - End of Options List (EOL)")
      writer.write("\t\t>IP Option - End of Options List (EOL)\n")
      print("\t\t\t>Type: 0")
      writer.write("\t\t\t>Type: 0\n")
      print("\t\t\t\t0... .... = Copy on fragmentation: No")
      writer.write("\t\t\t\t0... .... = Copy on fragmentation: No\n")
      print("\t\t\t\t.00. .... = Class: Control (0)")
      writer.write("\t\t\t\t.00. .... = Class: Control (0)\n")
      print("\t\t\t\t...0 0000 = Number: End of Option List (EOL) (0)")
      writer.write("\t\t\t\t...0 0000 = Number: End of Option List (EOL) (0)\n")

    # Affichage et ecriture de l'option No-Operation (NOP)
    elif (int(listeTrace[i], 16) == 1):
      # Si l'option d'apres c'est Record Route
      if (int(listeTrace[i+1], 16) == 7): ######## autrement ?
        print("Record Route")
        writer.write("Record Route\n")
        ecritRR = True  # Comme ça je le reecrit plus

      # Si l'option d'apres c'est LSR
      elif (int(listeTrace[i+1], 16) == 131):
        print("Loose Source Route")
        writer.write("Loose Source Route\n")
        ecritLSR = True # Comme ça je le reecrit plus

      # Si l'option d'apres c'est TS
      elif (int(listeTrace[i+1], 16) == 68):
        print("Time Stamp")
        writer.write("Time Stamp\n")
        ecritTS = True

      # Si l'option d'apres c'est SSR
      elif (int(listeTrace[i+1], 16) == 137):
        print("Strict Source Route")
        writer.write("Strict Source Route\n")
        ecritSSR = True

      print("\t\t>IP Option - No-Operation (NOP)")
      writer.write("\t\t>IP Option - No-Operation (NOP)\n")
      print("\t\t\t>Type: 1")
      writer.write("\t\t\t>Type: 1\n")
      print("\t\t\t\t0... .... = Copy on fragmentation: No")
      writer.write("\t\t\t\t0... .... = Copy on fragmentation: No\n")
      print("\t\t\t\t.00. .... = Class: Control (0)")
      writer.write("\t\t\t\t.00. .... = Class: Control (0)\n")
      print("\t\t\t\t...0 0001 = Number: No-Operation (NOP) (1)")
      writer.write("\t\t\t\t...0 0001 = Number: No-Operation (NOP) (1)\n")

    # Affichage et ecriture de l'option Record Route
    elif (int(listeTrace[i], 16) == 7):
      # Si on a pas ecrit le nom de l'option, on l'ecrit
      if not(ecritRR):
        print("Record Route")
        writer.write("Record Route\n")
      i += 1 # On passe a l'octet d'apres
      longueur = int(listeTrace[i], 16)
      print("\t\t>IP Option - Record Route ("+str(longueur)+" bytes)")
      writer.write("\t\t>IP Option - Record Route ("+str(longueur)+" bytes)\n")
      print("\t\t\t>Type: 7")
      writer.write("\t\t\t>Type: 7\n")
      print("\t\t\t\t0... .... = Copy on fragmentation: No")
      writer.write("\t\t\t\t0... .... = Copy on fragmentation: No\n")
      print("\t\t\t\t.00. .... = Class: Control (0)")
      writer.write("\t\t\t\t.00. .... = Class: Control (0)\n")
      print("\t\t\t\t...0 0111 = Number: Record route (7)")
      writer.write("\t\t\t\t...0 0111 = Number: Record route (7)\n")
      print("\t\t\tLength: "+str(longueur))
      writer.write("\t\t\tLength: "+str(longueur)+"\n")
      i += 1 # On passe a l'octet d'apres
      pointer = int(listeTrace[i], 16)
      print("\t\t\tPointer: "+str(pointer))
      writer.write("\t\t\tPointer: "+str(pointer)+"\n")
      i += 1 # On passe a l'octet d'apres

      nextRR = True
      # Parcourt de toutes les adresse IP du Record Route

      while (i<indiceFinEthernet+longueur):
        # Recuperation des 4 octets de l'@ IP
        indice0 = int(listeTrace[i], 16)
        indice1 = int(listeTrace[i+1], 16)
        indice2 = int(listeTrace[i+2], 16)
        indice3 = int(listeTrace[i+3], 16)
        i += 4    # On passe a l'adresse IP d'apres
        #print("i = ", i)
        # Si l'@ IP est empty
        if (indice0==indice1==indice2==indice3==0):
          # Si c'est la 1ere
          if (nextRR):
            print("\t\t\tEmpty Route: 0.0.0.0 <- (next)")
            writer.write("\t\t\tEmpty Route: 0.0.0.0 <- (next)\n")
            nextRR = False

          # Si pas la 1ere
          else:
            print("\t\t\tEmpty Route: 0.0.0.0")
            writer.write("\t\t\tEmpty Route: 0.0.0.0\n")

        # Si l'@ IP n'est pas empty
        else:
          print("\t\t\tRecorded Route: "+str(indice0)+"."+str(indice1)+"."+str(indice2)+"."+str(indice3))
      i -= 1 # Pour me mettre sur le bon i

    # Time Stamp (TS)
    elif (int(listeTrace[i], 16) == 68):
      # Si on a pas ecrit le nom de l'option, on l'ecrit
      if not(ecritTS):
        print("Time Stamp")
        writer.write("Time Stamp\n")

      i += 1 # On passe a l'octet d'apres
      longueur = int(listeTrace[i], 16)
      print("\t\t>IP Option - Time Stamp ("+str(longueur)+" bytes)")
      writer.write("\t\t>IP Option - Time Stamp ("+str(longueur)+" bytes)\n")
      print("\t\t\t>Type: 68")
      writer.write("\t\t\t>Type: 68\n")
      print("\t\t\t\t0... .... = Copy on fragmentation: No")
      writer.write("\t\t\t\t0... .... = Copy on fragmentation: No\n")
      print("\t\t\t\t.10. .... = Class: Debugging and measurement (2)")
      writer.write("\t\t\t\t.10. .... = Class: Debugging and measurement (2)\n")
      print("\t\t\t\t...0 0100 = Number: Time Stamp (4)")
      writer.write("\t\t\t\t...0 0111 = Number: Time Stamp (4)\n")
      print("\t\t\tLength: "+str(longueur))
      writer.write("\t\t\tLength: "+str(longueur)+"\n")
      i += 1 # On passe a l'octet d'apres
      pointer = int(listeTrace[i], 16)
      print("\t\t\tPointer: "+str(pointer))
      writer.write("\t\t\tPointer: "+str(pointer)+"\n")
      i += 1 # On passe à l'octet d'apres
      # 4 premiers bits correspondent a l'overflow
      overflow = format(int((listeTrace[i])[0], 16), 'b').zfill(4)
      # 4 derniers bits correspondent au flag
      flag = format(int((listeTrace[i])[1], 16), 'b').zfill(4)
      print("\t\t\t"+str(overflow)+" .... = Overflow: "+str(int((listeTrace[i])[0], 16)))
      writer.write("\t\t\t"+str(overflow)+" .... = Overflow: "+str(int((listeTrace[i])[0], 16))+'\n')
      print("\t\t\t.... "+str(flag)+" = Flag: Time stamp and address (0x"+str((listeTrace[i])[1])+")")
      writer.write("\t\t\t.... "+str(flag)+" = Flag: Time stamp and address (0x"+str((listeTrace[i])[1])+")\n")
      i += 1

      # Parcourt de tous les octets restatns
      while (i<indiceFinEthernet+longueur):
        # Si flag = 0, on affiche que les temps
        if (bin_to_decimal(flag) == 0):
          # Recuperation des 4 octets du time stamp
          timeStamp = listeTrace[i]+listeTrace[i+1]+listeTrace[i+2]+listeTrace[i+3]
          i += 4    # On passe aux octets d'apres

          print("\t\t\tTime stamp: "+str(int(timeStamp,16)))
          writer.write("\t\t\tTime stamp: "+str(int(timeStamp,16))+'\n')

        # Si flag = 1 ou = 3, on affiche les temps et les adresses IP
        elif (bin_to_decimal(flag) == 1 or bin_to_decimal(flag)  == 3):
          # Recuperation des 4 octets de l'@ IP
          indice0 = int(listeTrace[i], 16)
          indice1 = int(listeTrace[i+1], 16)
          indice2 = int(listeTrace[i+2], 16)
          indice3 = int(listeTrace[i+3], 16)
          i += 4    # On passe aux octets d'apres

          # Adresse IP 0.0.0.0 => Time stamp = 0
          if (indice1==indice1==indice2==indice3==0):
            print("\t\t\tAddress: -")
            writer.write("\t\t\tAddress: -\n")
            # Recuperation des 4 octets du time stamp
            timeStamp = listeTrace[i]+listeTrace[i+1]+listeTrace[i+2]+listeTrace[i+3]
            i += 4    # On passe aux octets d'apres
            print("\t\t\tTime stamp: "+str(int(timeStamp,16)))
            writer.write("\t\t\tTime stamp: "+str(int(timeStamp,16))+'\n')

          else:
            print("\t\t\tAddress: "+str(indice0)+'.'+str(indice1)+'.'+str(indice2)+'.'+str(indice3))
            writer.write("\t\t\tAddress: "+str(indice0)+'.'+str(indice1)+'.'+str(indice2)+'.'+str(indice3)+'\n')

            # Recuperation des 4 octets du time stamp
            timeStamp = listeTrace[i]+listeTrace[i+1]+listeTrace[i+2]+listeTrace[i+3]
            i += 4    # On passe aux octets d'apres

            print("\t\t\tTime stamp: "+str(int(timeStamp,16)))
            writer.write("\t\t\tTime stamp: "+str(int(timeStamp,16))+'\n')

    # Loose Source Route (LSR):
    elif (int(listeTrace[i], 16) == 131):
      # Si on a pas ecrit le nom de l'option, on l'ecrit
      if not(ecritLSR):
        print("Loose Source Route")
        writer.write("Loose Source Route\n")

      i += 1 # On passe a l'octet d'apres
      longueur = int(listeTrace[i], 16)
      print("\t\t>IP Option - Loose Source Route ("+str(longueur)+" bytes)")
      writer.write("\t\t>IP Option - Loose Source Route ("+str(longueur)+" bytes)\n")
      print("\t\t\t>Type: 131")
      writer.write("\t\t\t>Type: 131\n")
      print("\t\t\t\t1... .... = Copy on fragmentation: Yes")
      writer.write("\t\t\t\t1... .... = Copy on fragmentation: Yes\n")
      print("\t\t\t\t.00. .... = Class: Control (0)")
      writer.write("\t\t\t\t.00. .... = Class: Control (0)\n")
      print("\t\t\t\t...0 0011 = Number: Loose source route (3)")
      writer.write("\t\t\t\t...0 0011 = Number: Loose source route (3)\n")
      print("\t\t\tLength: "+str(longueur))
      writer.write("\t\t\tLength: "+str(longueur)+"\n")
      i += 1 # On passe a l'octet d'apres
      pointer = int(listeTrace[i], 16)
      print("\t\t\tPointer: "+str(pointer))
      writer.write("\t\t\tPointer: "+str(pointer)+"\n")
      i += 1

      j = i
      # Parcourt de tous les octets restatns
      while (j<indiceFinEthernet+longueur):
        # Recuperation des 4 octets de l'@ IP
        indice0 = int(listeTrace[j], 16)
        indice1 = int(listeTrace[j+1], 16)
        indice2 = int(listeTrace[j+2], 16)
        indice3 = int(listeTrace[j+3], 16)

        # Si le 1er
        if (j == i):
          print("\t\t\tSource route: "+str(indice0)+'.'+str(indice1)+'.'+str(indice2)+'.'+str(indice3)+" <- (next)")
          writer.write("\t\t\tSource route: "+str(indice0)+'.'+str(indice1)+'.'+str(indice2)+'.'+str(indice3)+'<- (next)\n')

        # Si dernier
        elif (j == indiceFinEthernet+longueur-3):
          print("\t\t\tDestination address: "+str(indice0)+'.'+str(indice1)+'.'+str(indice2)+'.'+str(indice3))
          writer.write("\t\t\tDestination address: "+str(indice0)+'.'+str(indice1)+'.'+str(indice2)+'.'+str(indice3)+'\n')

        # Dans les autres cas
        else:
          print("\t\t\tSource route: "+str(indice0)+'.'+str(indice1)+'.'+str(indice2)+'.'+str(indice3))
          writer.write("\t\t\tSource route: "+str(indice0)+'.'+str(indice1)+'.'+str(indice2)+'.'+str(indice3)+'\n')
        j += 4    # On passe aux octets d'apres
      i = j

    # Strict Source Route (SSR):
    elif (int(listeTrace[i], 16) == 137):
      # Si on a pas ecrit le nom de l'option, on l'ecrit
      if not(ecritSSR):
        print("Strict Source Route")
        writer.write("Strict Source Route\n")

      i += 1 # On passe a l'octet d'apres
      longueur = int(listeTrace[i], 16)
      print("\t\t>IP Option - Strict Source Route ("+str(longueur)+" bytes)")
      writer.write("\t\t>IP Option - Strict Source Route ("+str(longueur)+" bytes)\n")
      print("\t\t\t>Type: 131")
      writer.write("\t\t\t>Type: 131\n")
      print("\t\t\t\t1... .... = Copy on fragmentation: Yes")
      writer.write("\t\t\t\t1... .... = Copy on fragmentation: Yes\n")
      print("\t\t\t\t.00. .... = Class: Control (0)")
      writer.write("\t\t\t\t.00. .... = Class: Control (0)\n")
      print("\t\t\t\t...0 1001 = Number: Strict source route (9)")
      writer.write("\t\t\t\t...0 1001 = Number: Strict source route (9)\n")
      print("\t\t\tLength: "+str(longueur))
      writer.write("\t\t\tLength: "+str(longueur)+"\n")
      i += 1 # On passe a l'octet d'apres
      pointer = int(listeTrace[i], 16)
      print("\t\t\tPointer: "+str(pointer))
      writer.write("\t\t\tPointer: "+str(pointer)+"\n")
      i += 1

      j = i
      # Parcourt de tous les octets restatns
      while (j<indiceFinEthernet+longueur):
        # Recuperation des 4 octets de l'@ IP
        indice0 = int(listeTrace[j], 16)
        indice1 = int(listeTrace[j+1], 16)
        indice2 = int(listeTrace[j+2], 16)
        indice3 = int(listeTrace[j+3], 16)

        # Si le 1er
        if (j == i):
          print("\t\t\tSource route: "+str(indice0)+'.'+str(indice1)+'.'+str(indice2)+'.'+str(indice3)+" <- (next)")
          writer.write("\t\t\tSource route: "+str(indice0)+'.'+str(indice1)+'.'+str(indice2)+'.'+str(indice3)+'<- (next)\n')

        # Si dernier
        elif (j == indiceFinEthernet+longueur-3):
          print("\t\t\tDestination address: "+str(indice0)+'.'+str(indice1)+'.'+str(indice2)+'.'+str(indice3))
          writer.write("\t\t\tDestination address: "+str(indice0)+'.'+str(indice1)+'.'+str(indice2)+'.'+str(indice3)+'\n')

        # Dans les autres cas
        else:
          print("\t\t\tSource route: "+str(indice0)+'.'+str(indice1)+'.'+str(indice2)+'.'+str(indice3))
          writer.write("\t\t\tSource route: "+str(indice0)+'.'+str(indice1)+'.'+str(indice2)+'.'+str(indice3)+'\n')
        j += 4
      i = j
    i += 1


  # Fermeture du fichier
  writer.close()

  return
# ----------------------------------------------------------------------------- #
