from ip import hex_to_decimal, hex_to_bin, bin_to_decimal, ip_decimal


# Dans le cas de DNS, votre analyseur décodera les six (6) champs d’entête ainsi que les sections Questions, Réponses, Autorités et Additionnelles. 
# Vous décoderez toutes les informations y compris les noms compressés.

# ----------------------------------------------------------------------------- #
#DNS entete = 12 octets
# + Questions, Réponses, Autorités et Additionnelles
#liste_trace de packet DNS va de la position 42 jusqu'au 54 non inclus
def analyse_dns(liste_trace, nom_fichier_ecriture, indiceFinUDP):
  #42
  indiceDNS = indiceFinUDP
  try:
    liste_trace[indiceDNS]
  except IndexError:
    print("==== Erreur avec la taille packet dns ====")
    return 0

  #transaction sur 2 octets : str
  transaction_id = "0x" + str(hex_to_decimal(liste_trace[indiceDNS] + liste_trace[indiceDNS + 1]))
  indiceDNS += 2

  #DNS has two types of messages: query and response. Both types have the same format. The query message consists of a header and question records; the response message consists of a header, question records, answer records, authoritative records, and additional records
  #flags en binaire 16 bits : str
  flags = liste_trace[indiceDNS] + liste_trace[indiceDNS + 1]
  indiceDNS += 2

  #nombre de questions sur 2 octets : int
  questions = hex_to_decimal(liste_trace[indiceDNS] + liste_trace[indiceDNS + 1])
  indiceDNS += 2

  #nombre de reponses sur 2 octets : int
  answers_rrs = hex_to_decimal(liste_trace[indiceDNS] + liste_trace[indiceDNS + 1])
  indiceDNS += 2

  #nombre de authority rr sur 2 octets : int
  authorities_rrs = hex_to_decimal(liste_trace[indiceDNS] + liste_trace[indiceDNS + 1])
  indiceDNS += 2

  #nombre d'additionnelles rr sur 2 octets : int
  additionals_rrs = hex_to_decimal(liste_trace[indiceDNS] + liste_trace[indiceDNS + 1])
  indiceDNS += 2
  
  affichage_dns(nom_fichier_ecriture, transaction_id, flags, questions, answers_rrs, authorities_rrs, additionals_rrs, liste_trace, indiceDNS)

  return

# ----------------------------------------------------------------------------- #
def affichage_dns(nomFichierEcriture, transaction_id, flags, questions, answers_rrs, authorities_rrs, additionals_rrs,liste_trace, indiceDNS):
  # Ouverture fichier a ecrire les donnees
  writer = open("Trames/Analyse/"+nomFichierEcriture, 'a') 

  #affichage type de message DNS
  flagsBin = hex_to_bin(flags)

  flagQR = int(flagsBin[0])

  #valeur qui indique si c'est query ou response
  msgType = ""
  msgTypeInt = 0
  if flagQR == 1:
    msgType = "response"
    msgTypeInt = 0

  affichage_type(nomFichierEcriture, msgType, flagQR)

  #affichage transaction id
  print("\tTransaction ID: " + transaction_id)
  writer.write("\tTransaction ID: " + transaction_id + "\n")

  #affichage flags
  print("\t>Flags: " + "0x" + flags, end ='')
  writer.write("\t>Flags: " + "0x" + flags)
  affichage_flags(nomFichierEcriture, msgType, msgTypeInt, flags, flagsBin)

  #affichage questions
  print("\tQuestions: " + str(questions))
  writer.write("\tQuestions: " + str(questions) + "\n")

  #affichage answer RRs
  print("\tAnswer RRs: " + str(answers_rrs))
  writer.write("\tAnswer RRs: " + str(answers_rrs) + "\n")

  #affichage authority RRs
  print("\tAuthority RRs: " + str(authorities_rrs))
  writer.write("\tAuthority RRs: " + str(authorities_rrs) + "\n")

  #affichage additionnal RRs
  print("\tAdditional RRs: " + str(additionals_rrs))
  writer.write("\tAdditional RRs: " + str(additionals_rrs) + "\n")

  #Donnees
  #affichage data
  affichage_data(nomFichierEcriture, liste_trace, questions, answers_rrs, authorities_rrs, additionals_rrs, indiceDNS)
 

  # Fermeture des deux fichiers d'ecriture 
  writer.close()
  
  return

# ----------------------------------------------------------------------------- #
def affichage_type(nomFichierEcriture, msgType, flagsBin):
  # Ouverture fichier a ecrire les donnees
  writer = open("Trames/Analyse/"+nomFichierEcriture, 'a') 
  # Fichier ou on ecrira les erreur possibles de l'analyse IP
  writerErreurs = open("Trames/Analyse/Erreur_analyse_trames_dns.txt", 'w')

  message = "response"
  if msgType == "":
    message = "query"
  # Dictionnaire pour query/response
  QR = {
      0: ">>Domain Name System (" + message + ")",
      1: ">>Domain Name System (" + message + ")"
  }
  try:
    typeQR = QR.get(flagsBin)
    print(str(typeQR))
    writer.write(str(typeQR) + "\n")
  except IndexError:
    print("==== Erreur avec le type de message dns ====")
    writerErreurs.write("==== Erreur avec le type de message dns ====\n")
    return 0

  # Fermeture des deux fichiers d'ecriture 
  writer.close()
  writerErreurs.close()

  return

# ----------------------------------------------------------------------------- #
def affichage_flags(nomFichierEcriture, msgType, msgTypeInt, flags, flagsBin):
  # Ouverture fichier a ecrire les donnees
  writer = open("Trames/Analyse/"+nomFichierEcriture, 'a') 
  # Fichier ou on ecrira les erreur possibles de l'analyse IP
  writerErreurs = open("Trames/Analyse/Erreur_analyse_trames_dns.txt", 'w')

  # OpCode: This is a 4-bit subfield that defines the type of query or response 
  #(0 if standard, 1 if inverse, and 2 if a server status request)

  # Dictionnaire pour query/response
  code = bin_to_decimal(flagsBin[1:5])

  OpCode = {
      0: " (Standard query " + msgType + ")",
      1: " (Inverse query " + msgType + ")",
      2: " (Server status request)"
  }
  typeOpCode = ""

  try:
    typeOpCode = OpCode.get(code)
    print(typeOpCode)
    writer.write(typeOpCode + '\n')
  except IndexError:
    print("==== Erreur avec le type de message dns ====")
    writerErreurs.write("==== Erreur avec le type de message dns ====\n")
    return 0

  #QR 1 bits
  print("\t\t" + str(msgTypeInt) + "... .... .... ....", end = '')
  writer.write("\t\t" + str(msgTypeInt) + "... .... .... ....")
  print(" = Message is a " + msgType)
  writer.write(" = Message is a " + msgType + "\n")

  #OpCode 4 bits
  print("\t\t." + flagsBin[1:4] + " " + flagsBin[4] + "... .... ....", end = '')
  writer.write("\t\t." + flagsBin[1:4] + " " + flagsBin[4] + "... .... ....")
  print(" = Opcode: " + typeOpCode + "(" + str(code) + ")")
  writer.write(" = Opcode: " + typeOpCode + "(" + str(code) + ")" + "\n")

  #AA (authoritative answer)
  # This is a 1-bit subfield. When it is set (value of 1)it means that the name server is an authoritative server. It is used only in a response message.
  if msgType == "response":
    print("\t\t...." + " ." + flagsBin[5] + ".. " + ".... ....", end = '')
    writer.write("\t\t...." + " ." + flagsBin[5] + ".. " + ".... ....")
    isauthor = ""
    if(flagsBin[5] == 0):
      isauthor = "not"
    print(" = Authoritative: Server is " + isauthor + " an authority for domain")
    writer.write(" = Authoritative: Server is " + isauthor + " an authority for domain")


  #TC (truncated): This is a 1-bit subfield. When it is set (value of 1), it means that the response was more than 512 bytes and truncated to 512. It is used when DNS uses the services of UDP (see Section 19.8 on Encapsulation).
  print("\t\t...." + " .." + flagsBin[6] + ". " + ".... ....", end = '')
  writer.write("\t\t...." + " .." + flagsBin[6] + ". " + ".... ....")
  trunc = ""
  if(flagsBin[6] == 0):
    trunc = "not"
  print(" = Truncated: Message is " + trunc + " truncated")
  writer.write(" = Truncated: Message is " + trunc + " truncated" + "\n")

  #RD (recursion desired): This is a 1-bit subfield. When it is set (value of 1) it means the client desires a recursive answer. It is set in the query message and repeated in the response message.
  print("\t\t...." + " ..." + flagsBin[7] + " " + ".... ....", end = '')
  writer.write("\t\t...." + " .." + flagsBin[7] + ". " + ".... ....")
  recurs = ""
  if(flagsBin[7] == 0):
    recurs = "not do "
  print(" = Recursion desired: Do " + recurs + "query recursively")
  writer.write(" = Recursion desired: Do " + recurs + "query recursively" + "\n")

  #RA (recursion available): This is a 1-bit subfield. When it is set in the response, it means that a recursive response is available. It is set only in the response message.
  if msgType == "response":
    print("\t\t...." + " .... " + flagsBin[8] + "... ....", end = '')
    writer.write("\t\t...." + " .... " + flagsBin[8] + "... ....")
    avail = ""
    if(flagsBin[8] == 0):
      avail = "not"
    print(" = Recursion available: Server can" + avail + " do recursive queries")
    writer.write(" = Recursion available: Server can" + avail + " do recursive queries" + "\n")

  #Reserved: This is a 3-bit subfield set to 000
  print("\t\t.... .... .0.. ....", end = '')
  writer.write("\t\t.... .... .0.. ....")
  print(" = Z reserved (0)")
  writer.write(" = Z reserved (0)" + "\n")

  #rCode: This is a 4-bit field that shows the status of the error in the response.
  print("\t\t.... .... .... " + flagsBin[12:], end = '')
  writer.write("\t\t.... .... .... " + flagsBin[12:])
  error = bin_to_decimal(flagsBin[12:])
  NoErr = "No"
  if  error != 0:
    NoErr = ""
  print(" = Reply code: "+ NoErr + "Error (" + str(error) + ")")
  writer.write(" = Reply code: "+ NoErr + "Error (" + str(error) + ")\n")


  # Fermeture des deux fichiers d'ecriture 
  writer.close()
  writerErreurs.close()

  return

# ----------------------------------------------------------------------------- #
def affichage_data(nomFichierEcriture, liste_trace, questions, answers_rrs, authorities_rrs, additionals_rrs, indiceDNS):
  # Ouverture fichier a ecrire les donnees
  writer = open("Trames/Analyse/"+nomFichierEcriture, 'a')
  # Fichier ou on ecrira les erreur possibles de l'analyse IP
  writerErreurs = open("Trames/Analyse/Erreur_analyse_trames_dns.txt", 'w')

  #S'il n'y a pas de queries
  if questions == 0:
    writerErreurs.write("==== Il doit avoir la section queries ====\n")
    return 0

  classes = {
    1:  "IN (0x0001)",
    2:  "CS (0x0002)",
    3:  "CH (0x0003)",
    4:  "HS (0x0004)"
  }

  types = {
    1:  "A", #data is an IPv4 address.
    2:  "NS",  #data is the name of the authoritative server.
    3:  "MD",
    4:  "MF",
    5:  "CNAME", #data is the canonical name.
    6:  "SOA",
    7:  "MB",
    8:  "MG",
    9:  "MR",
    10: "NULL",
    11: "WKS",
    12: "PTR",
    13: "HINFO",
    14: "MINFO",
    15: "MX", #data is the name of a mail server
    16: "TXT"
  }

  #indice a partir de laquelle on a DNS
  indiceCourant = indiceDNS
  nomCourant = 12

  #dictionnaire qui pour les cles - la position de nom et pour les valeurs - les domain names
  names = {}

  #Affichage Queries
  #Question section contains incomplete RR {DNSname, TYPE, CLASS} 
  print("\t>Queries")
  writer.write("\t>Queries" + "\n")

  (name, indiceCourant, nomCourant) = recherche_name(liste_trace, indiceCourant, indiceDNS, nomCourant, names, float('inf'))

  (typeAfficher, classAfficher, indiceCourant, nomCourant) = trouve_type_class(liste_trace, indiceCourant, nomCourant, types, classes)


  affichage_name_type_class(nomFichierEcriture, name, typeAfficher, classAfficher)

  #Affichage Ans, Auth, Add
  # Ans, Auth, Add Sections : {DNSname, TYPE(2), CLASS, TTL, (RDATA_LENGTH), RDATA}
  
  #S'il y a la section answers
  if answers_rrs != 0:
    print("\t>Answers")
    writer.write("\t>Answers" + "\n")
    #for i in range(answers_rrs):
    #recherche domain name

    (name, indiceCourant, nomCourant) = recherche_name(liste_trace, indiceCourant, indiceDNS, nomCourant, names, float('inf'))

    #determiner type, class
    (typeAfficher, classAfficher, indiceCourant, nomCourant) = trouve_type_class(liste_trace, indiceCourant, nomCourant, types, classes)
    #afficher nom, type, class
    affichage_name_type_class(nomFichierEcriture, name, typeAfficher, classAfficher)

    #determiner ttl, longueur, data
    (ttl, dataLength, rdata, indiceCourant, nomCourant, dataLength) = trouve_ttl_dataLength_rdata(liste_trace, indiceCourant, nomCourant, indiceDNS, typeAfficher, names)
    #afficher ttl, longueur, data
    affichage_ttl_length_data(nomFichierEcriture, ttl, dataLength, rdata, typeAfficher)


  """
  #S'il y a la section authorities
  if authorities_rrs != 0:
    print("\t>Authorities")
    writer.write("\t>Authorities" + "\n")
    for i in range(answers_rrs):
      #recherche domain name
      (name, indiceCourant, nomCourant) = recherche_name(liste_trace, indiceCourant, indiceDNS, nomCourant, names, float('inf'))

      #determiner type, class
      (typeAfficher, classAfficher, indiceCourant, nomCourant) = trouve_type_class(liste_trace, indiceCourant, nomCourant, types, classes)
      #afficher nom, type, class
      affichage_name_type_class(nomFichierEcriture, name, typeAfficher, classAfficher)

      #determiner ttl, longueur, data
      (ttl, dataLength, rdata, indiceCourant, nomCourant, dataLength) = trouve_ttl_dataLength_rdata(liste_trace, indiceCourant, nomCourant, indiceDNS, typeAfficher, names)
      #afficher ttl, longueur, data
      affichage_ttl_length_data(nomFichierEcriture, ttl, dataLength, rdata, typeAfficher)
  """
  """
  #S'il y a la section additionnelles
  if additionals_rrs  != 0:
    print("\t>Additionals")
    writer.write("\t>Additionals" + "\n")
    for i in range(answers_rrs):
      #recherche domain name
      (name, indiceCourant, nomCourant) = recherche_name(liste_trace, indiceCourant, indiceDNS, nomCourant, names, float('inf'))

      #determiner type, class
      (typeAfficher, classAfficher, indiceCourant, nomCourant) = trouve_type_class(liste_trace, indiceCourant, nomCourant, types, classes)
      #afficher nom, type, class
      affichage_name_type_class(nomFichierEcriture, name, typeAfficher, classAfficher)

      #determiner ttl, longueur, data
      (ttl, dataLength, rdata, indiceCourant, nomCourant, dataLength) = trouve_ttl_dataLength_rdata(liste_trace, indiceCourant, nomCourant, indiceDNS, typeAfficher, names)
      #afficher ttl, longueur, data
      affichage_ttl_length_data(nomFichierEcriture, ttl, dataLength, rdata, typeAfficher)
  """

  writer.close()
  return

# ----------------------------------------------------------------------------- #
def recherche_name(liste_trace, indiceCourant, indiceDNS, nomCourant, names, positionFin):
  # Fichier ou on ecrira les erreur possibles de l'analyse IP
  writerErreurs = open("Trames/Analyse/Erreur_analyse_trames_dns.txt", 'w')

  #Le nom
  name = ""
  cpt = 0

  while(cpt < positionFin and liste_trace[indiceCourant] != "00" and liste_trace[indiceCourant][0] not in {"C","c","D","d","E","e","F","f"}):
    #Longueur de sous-nom
    TextLength = hex_to_decimal(liste_trace[indiceCourant])
    #Indice d'octet courant
    indiceCourant += 1
    name = name + hex_to_ascii(''.join(liste_trace[indiceCourant:indiceCourant + TextLength])) + "."

    #On passe au sous text suivant
    indiceCourant += TextLength
    nomCourant += TextLength

  #Pour enlever le dernier point
  if name:
    name = name[:len(name)-1]

  if liste_trace[indiceCourant][0] in {"C","c","D","d","E","e","F","f"}:
    offset = hex_to_bin(liste_trace[indiceCourant] + liste_trace[indiceCourant+1])
    indiceCourant += 2
    #on prends 14 bits de poids faible pour trouver la valeur de l'offset
    
    offset = offset[2:]
    #conversion en decimal de l'offset
    offset = bin_to_decimal(offset)

    try:
      if name:
        name += "." + names.get(offset)
      else:
        name = names.get(offset)
    except IndexError:
      print("==== Le programme trouve pas le domain name demande ====")
      writerErreurs.write("==== Le programme trouve pas le domain name demande ====\n")
      return 0
  else:
    indiceCourant += 1

  #Ajout des sous-noms dans dictionnaire
  if name:
    ajout_dans_dico(name, indiceCourant  - indiceDNS - 12, names)
  
  return (name, indiceCourant, nomCourant)
# ----------------------------------------------------------------------------- #
def ajout_dans_dico(name, offsetNameCourant, names):
  #on ajoute le nom complet
  names[offsetNameCourant] = name
  for i in range(len(name)-1, 0, -1):
    #Si on est arrive au point dans le name
    if name[i] == ".":
      #On verifie s'il existe pas de ce sous-nom dans dico
      if name[i+1:]: #not in names.values():
        #Cle - position dans la trame, valeur - sous-nom
        names[i + offsetNameCourant] = name[i+1:]
  return

# ----------------------------------------------------------------------------- #
def trouve_type_class(liste_trace, indiceCourant, nomCourant, types, classes):
  # Fichier ou on ecrira les erreur possibles de l'analyse IP
  writerErreurs = open("Trames/Analyse/Erreur_analyse_trames_dns.txt", 'w')

  try:
    #type sur 2 octets
    typeDNS = hex_to_decimal(liste_trace[indiceCourant] + liste_trace[indiceCourant+1])
    typeAfficher =  types.get(typeDNS)

    indiceCourant += 2
    nomCourant += 2

    #class sur 2 octets
    classDNS = hex_to_decimal(liste_trace[indiceCourant] + liste_trace[indiceCourant+1])
    classAfficher = classes.get(classDNS)

    indiceCourant += 2
    nomCourant += 2

  except IndexError:
    print("==== Il n'existe pas de ce type ou classe dans dns ====")
    writerErreurs.write("==== Il n'existe pas de ce type ou classe dans dns====\n")
    return 0

  
  writerErreurs.close()

  return (typeAfficher, classAfficher, indiceCourant, nomCourant)

# ----------------------------------------------------------------------------- #
def trouve_ttl_dataLength_rdata(liste_trace, indiceCourant, nomCourant, indiceDNS, typeAfficher, names):
  ttl = hex_to_decimal(''.join(liste_trace[indiceCourant:indiceCourant+4]))

  indiceCourant += 4
  nomCourant += 4
  dataLength = hex_to_decimal(''.join(liste_trace[indiceCourant:indiceCourant+2]))
  indiceCourant += 2
  nomCourant += 2
  
  if typeAfficher == "A":
    rdata = ip_decimal(liste_trace[indiceCourant:indiceCourant+4])
    indiceCourant += dataLength
    nomCourant += dataLength
  else:
    (rdata, indiceCourant, nomCourant) = recherche_name(liste_trace, indiceCourant, indiceDNS, nomCourant, names, dataLength)

  

  return (ttl, dataLength, rdata, indiceCourant, nomCourant, dataLength)

# ----------------------------------------------------------------------------- #
def affichage_name_type_class(nomFichierEcriture, name, typeAfficher, classAfficher):
  # Ouverture fichier a ecrire les donnees
  writer = open("Trames/Analyse/"+nomFichierEcriture, 'a')


  print("\t\t>" + name + ": " + typeAfficher + ", " + classAfficher)
  writer.write("\t\t>" + name + ": " + typeAfficher + ", " + classAfficher + "\n")
  print("\t\t[Name length: " + str(len(name)) + "]")
  writer.write("\t\t[Name length: " + str(len(name)) + "]" + "\n")


  print("\t\tName: " + name)
  writer.write("\tName: " + name + "\n")

  print("\t\tType: " + typeAfficher)
  writer.write("\t\tType: " + typeAfficher + "\n")

  print("\t\tClass: " + classAfficher)
  writer.write("\t\tClass: " + classAfficher + "\n")

  writer.close()
  return

# ----------------------------------------------------------------------------- #
def affichage_ttl_length_data(nomFichierEcriture, ttl, dataLength, rdata, typeDNS):
  # Ouverture fichier a ecrire les donnees
  writer = open("Trames/Analyse/"+nomFichierEcriture, 'a')

  print("\t\tTime to live: " + str(ttl))
  writer.write("\t\tTime to live: " + str(ttl) + "\n")

  print("\t\tData length: " + str(dataLength))
  writer.write("\t\tData length: " + str(dataLength) + "\n")

  print("\t\t" + typeDNS + ": " + rdata)
  writer.write("\t\t" + typeDNS + ": " + rdata + "\n")

  writer.close()
  return

# ----------------------------------------------------------------------------- #
def hex_to_ascii(string):
  #creer un tableau des octets
  byte_array = bytearray.fromhex(string)
  return byte_array.decode()