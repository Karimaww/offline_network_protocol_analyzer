from ip import hex_to_decimal, hex_to_bin, bin_to_decimal, ip_decimal
from ethernet import mac_construire

# ----------------------------------------------------------------------------- #
def analyse_dhcp(listeTrace, nomFichierEcriture, indiceFinUDP, tailleTrame):
  # Fichier ou on ecrira les erreur possibles de l'analyse DHCP
  writer = open("Trames/Analyse/Erreur_analyse_trames.txt", 'a') 
  
  # Verification si les octets du segment IP existent bien
  try:
    indiceFinDHCP = indiceFinUDP
    listeTrace[indiceFinDHCP]    # Verification du premier octet du segment DHCP
    listeTrace[tailleTrame-1]      # Verification du dernier octet du segment DHCP
  # On annonce une erreur si pb. sur l'indice
  except IndexError:
    print("==== Erreur avec la taille de DHCP ====")
    writer.write("=== Erreur avec la taille de DHCP ===\n")
    return 0                       # Sortie du programme
    
  # Message type/Opcode
  messageType = hex_to_decimal(listeTrace[indiceFinDHCP])
  indiceFinDHCP += 1

  # Hardware type
  hwtype = "0x" + listeTrace[indiceFinDHCP]
  indiceFinDHCP += 1
  
  # Hardware address length
  hwlen = hex_to_decimal(listeTrace[indiceFinDHCP])
  indiceFinDHCP += 1

  # Hoops
  hops = hex_to_decimal(listeTrace[indiceFinDHCP])
  indiceFinDHCP += 1

  # Transaction id
  transactionId = "0x" + listeTrace[indiceFinDHCP] + listeTrace[indiceFinDHCP+1] + listeTrace[indiceFinDHCP+2] + listeTrace[indiceFinDHCP+3]
  indiceFinDHCP += 4

  # Seconds elapsed
  secElapsed = hex_to_decimal(listeTrace[indiceFinDHCP]) + hex_to_decimal(listeTrace[indiceFinDHCP+1])
  indiceFinDHCP += 2

  # Bootp flags
  flags = listeTrace[indiceFinDHCP] + listeTrace[indiceFinDHCP+1]
  indiceFinDHCP += 2

  # Client IP address
  clientIpAdr = ip_decimal(listeTrace[indiceFinDHCP:indiceFinDHCP+4])
  indiceFinDHCP += 4

  # Your IP adress
  yourIpAdr = ip_decimal(listeTrace[indiceFinDHCP:indiceFinDHCP+4])
  indiceFinDHCP += 4

  # Next server IP adrdess
  serveIpAdr = ip_decimal(listeTrace[indiceFinDHCP:indiceFinDHCP+4])
  indiceFinDHCP += 4

  # Relay agent ip address/Gateway IP address
  routIpAdr = ip_decimal(listeTrace[indiceFinDHCP:indiceFinDHCP+4])
  indiceFinDHCP += 4
  
  # Client mac address sur 16 octets
  clientMacAdr = listeTrace[indiceFinDHCP:indiceFinDHCP+16]
  indiceFinDHCP += 16

  # Server host name sur 64 octets
  servHostName = ""
  for octet in listeTrace[indiceFinDHCP:indiceFinDHCP+64]:
    servHostName = servHostName + octet
  indiceFinDHCP += 64
    
  # Boot filename sur 128 octets
  bootFilename = ""
  for octet in listeTrace[indiceFinDHCP:indiceFinDHCP+128]:
    bootFilename = bootFilename + octet
  indiceFinDHCP += 128

  affichage_dhcp(nomFichierEcriture, listeTrace, messageType, hwtype, hwlen, hops, transactionId, secElapsed, flags, clientIpAdr, yourIpAdr, serveIpAdr, routIpAdr, clientMacAdr, servHostName, bootFilename, tailleTrame)
  
  writer.close()
  return 
# ----------------------------------------------------------------------------- #
def affichage_dhcp(nomFichierEcriture, listeTrace, messageType, hwtype, hwlen, hops, transactionId, secElapsed, flags, clientIpAdr, yourIpAdr, serveIpAdr, routIpAdr, clientMacAdr, servHostName, bootFilename, tailleTrame):
  # Ouverture fichier a ecrire les donnees
  writer = open("Trames/Analyse/"+nomFichierEcriture, 'a')
  
  # Affichage et ecriture du type de message (on part du principe que l'option 53 est toujours la)
  typeDHCP = dhcp_message_type(hex_to_decimal(listeTrace[284]))
  print(">>Dynamic Host Configuration Protocol ("+typeDHCP+")")
  writer.write(">>Dynamic Host Configuration Protocol ("+typeDHCP+")\n")
  
  # Affichage et ecriture du message type
  print("\tMessage type: ", end='')
  writer.write("\tMessage type: ")
  
  # Dictionnaire pour message type
  msgType = {
        1: "Boot Request (1)",
        2: "Boot Reply (2)"
    }
  try:
    print(msgType.get(messageType))
    writer.write(msgType.get(messageType)+'\n')
  except IndexError:
    print("==== Erreur Message Type (DHCP) ====")
    writer.write("==== Erreur Message Type ====\n")
    return 0

  # Affichage et ecriture du hardware type
  print("\tHardware type: Ethernet (" + hwtype + ")")
  writer.write("\tHardware type: Ethernet (" + hwtype + ")\n")

  # Affichage et ecriture du hardware adress length
  print("\tHardware adress length: " + str(hwlen))
  writer.write("\tHardware adress length: " + str(hwlen)+ "\n")

  # Affichage et ecriture du hops
  print("\tHops: " + str(hops))
  writer.write("\tHops: " + str(hops) + "\n")

  # Affichage et ecriture du transaction id
  print("\tTransaction ID: " + transactionId)
  writer.write("\tTransaction ID: " + transactionId + "\n")

  #Affichage et ecriture du seconds elapsed
  print("\tSeconds elapsed: " + str(secElapsed))
  writer.write("\tSeconds elapsed: " + str(secElapsed) + "\n")

  # Affichage et ecriture du bootp flags
  print("\t>Bootp flags: 0x" + flags, end='')
  writer.write("\t>Bootp flags: 0x" + flags)
  msb = hex_to_bin(flags)[0] 
  if int(msb) == 1:
    message = "Broadcast"
  else:
    message = "Unicast"
  print(" ("+message+")\n\t\t" + str(msb) + "... .... .... .... = Broadcast flag: " + message)
  writer.write(" ("+message+")\n\t\t" + str(msb) + "... .... .... .... = Broadcast flag: " + message + "\n")
  print("\t\t" + ".000 0000 0000 0000 = Reserved flags: 0x0000")
  writer.write("\t\t" + ".000 0000 0000 0000 = Reserved flags: 0x0000" + "\n")

  # Affichage et ecriture client ip address
  print("\tClient IP address: " + clientIpAdr)
  writer.write("\tClient IP address: " + clientIpAdr + "\n") 

  # Affichage et ecriture du your (client) ip address
  print("\tYour (client) IP address: " + yourIpAdr)
  writer.write("\tYour (client) IP address: " + yourIpAdr + "\n") 

  # Affichage et ecriture next server ip address
  print("\tNext server IP address: " + serveIpAdr)
  writer.write("\tNext server IP address: " + serveIpAdr + "\n")

  # Affichage et ecriture relay agent ip address
  print("\tRelay agent IP address: " + routIpAdr)
  writer.write("\tRelay agent IP address: " + routIpAdr + "\n") 

  # Affichage et ecriture client mac address
  print("\tClient MAC address: " + mac_construire(clientMacAdr)) ####### Apple
  writer.write("\tClient MAC address: " + mac_construire(clientMacAdr) + "\n")

  # Affichage et ecriture client hardware address padding
  print("\tClient hardware address padding: "+ajouter_octets(clientMacAdr[6:]) ) #########""
  writer.write("\tClient hardware address padding: "+ajouter_octets(clientMacAdr[6:])+"\n") 

  # Affichage et ecriture server host name
  serv_host_name_dec = hex_to_decimal(servHostName)
  serverName = "not given"
  if serv_host_name_dec != 0 :
    # Convertir en ASCII le nom
    serverName = hex_to_ascii(servHostName)

  print("\tServer host name " + serverName)
  writer.write("\tServer host name " + serverName + "\n")

  # Affichage et ecriture bootfile_name
  bootfile_name = hex_to_decimal(bootFilename)
  bootName = "not given"
  if bootfile_name != 0 :
    # Convertir en ASCII le nom
    bootName = hex_to_ascii(bootfile_name)

  print("\tBootfile name " + bootName)
  writer.write("\tBootfile name " + bootName + "\n")

  # Affichage et ecriture magic cookie
  print("\tMagic cookie: DHCP")
  writer.write("\tMagic cookie: DHCP" + "\n") 

  # Affichage et ecriture option 53 : type de message
  print("\t>Option: (53) DHCP Message Type ("+typeDHCP+")")
  writer.write("\t>Option: (53) DHCP Message Type ("+typeDHCP+")\n")  

  # Ecriture de la longueur de l'option 53
  longueur = hex_to_decimal(listeTrace[283])
  print("\t\tLength: " + str(longueur))
  writer.write("\t\tLength: " + str(longueur) + "\n") 

  print("\t\tDHCP: " + typeDHCP+" ("+str(int(listeTrace[284], 16))+")")
  writer.write("\t\tDHCP: "+typeDHCP+" ("+str(int(listeTrace[284], 16))+")\n") 

  # Fermeture du fichier
  writer.close()
  
  # Affichage et ecriture des options
  affichage_options(nomFichierEcriture, listeTrace, tailleTrame)

  return
# ----------------------------------------------------------------------------- #
def hex_to_ascii(string):
  #creer un tableau des octets
  byte_array = bytearray.fromhex(string)
  return byte_array.decode()
# ----------------------------------------------------------------------------- #
def ajouter_octets(octets):
  string = ""
  for i in range(len(octets)):
    string += octets[i]
  
  return string
# ----------------------------------------------------------------------------- #
def dhcp_message_type(messageType):
  # Fichier ou on ecrira les erreur possibles de l'analyse DHCP
  writer = open("Trames/Analyse/Erreur_analyse_trames.txt", 'a') 

  
  # Dictionnaire pour message reponse
  msgType = {
        1: "Discover",
        2: "Offer",
        3: "Request",
        4: "Decline",
        5: "ACK",
        6: "NAK",
        7: "Release",
        8: "Inform"
    }
  try:
    return msgType.get(messageType)
  except IndexError:
    print("==== Il n'exite pas de tel DHCP Message Type ====")
    writer.write("==== Il n'exite pas de tel DHCP Message Type ====\n")
    writer.close()
    return 0
# ----------------------------------------------------------------------------- #
def ip_decimal_domaine(listeIPDomaine):
  string = ""
  for i in range(0, len(listeIPDomaine), 4):
    string += "\t\tDomaine Name Server: "+ip_decimal(listeIPDomaine[i:i+4])+'\n'
  
  return string
# ----------------------------------------------------------------------------- #
def affichage_options(nomFichierEcriture, listeTrace, tailleTrame):
  # Ouverture fichier a ecrire les donnees
  writerOK = open("Trames/Analyse/"+nomFichierEcriture, 'a')

  # Fichier ou on ecrira les erreur possibles de l'analyse IP
  writerErreurs = open("Trames/Analyse/Erreur_analyse_trames.txt", 'a')
  
  optionIndice = 285 ### + options IP
  indiceFinDHCP = tailleTrame
  # Parcours des options jusqu'à ce qu'on tombe a la derniere option 
  while ((optionIndice < indiceFinDHCP) & (hex_to_decimal(listeTrace[optionIndice]) != 255)):
    numOption = hex_to_decimal(listeTrace[optionIndice])
    longueurOption = hex_to_decimal(listeTrace[optionIndice + 1])

    # Option (1) - Subnet Mask   
    if (numOption == 1):
      string = "\t>Option: (1) Subnet Mask ("+ip_decimal(listeTrace[optionIndice+2: optionIndice+2+longueurOption]) + ")\n"+"\t\tLength: "+str(longueurOption)+ "\n"+"\t\tSubnet Mask: "+ip_decimal(listeTrace[optionIndice+2:optionIndice+2+ longueurOption])
      print(string)
      writerOK.write(string+'\n')
      optionIndice += longueurOption+2
    
    # Option (3) - Router
    elif (numOption == 3):
      string = "\t>Option: (3) Router\n"+"\t\tLength: "+str(longueurOption)+"\n"+"\t\tRouter: "+ip_decimal(listeTrace[optionIndice+2:optionIndice+2+ longueurOption])
      print(string)
      writerOK.write(string+'\n')
      optionIndice += longueurOption+2
    
    # Option (6) - Domaine Name Server
    elif(numOption == 6):
      string = "\t>Option: (6) Domaine Name Server\n"+"\t\tLength: " + str(longueurOption) + "\n"+ip_decimal_domaine(listeTrace[optionIndice+2:optionIndice+2+longueurOption])
      print(string, end='')
      writerOK.write(string+'\n')
      optionIndice += longueurOption+2
   
    # Option (12) - Host Name
    elif (numOption == 12):
      string = "\t>Option: (12) Host Name\n"+"\t\tLength: " + str(longueurOption) + "\n"+"\t\tHost Name: "+hex_to_ascii(''.join(listeTrace[optionIndice+2: optionIndice+2+longueurOption])) #split la liste en un string
      print(string)
      writerOK.write(string+'\n')
      optionIndice += longueurOption+2
     
    # Option (28) - Broadcast Address
    elif (numOption == 28):
      string = "\t>Option: (28) Broadcast Address ("+ip_decimal(listeTrace[optionIndice+2:optionIndice+2+longueurOption])+")\n"+"\t\tLength: "+str(longueurOption)+"\n"+"\t\tBroadcast Address: "+ip_decimal(listeTrace[optionIndice+2:optionIndice+2+longueurOption])
      print(string)
      writerOK.write(string+'\n')
      optionIndice += longueurOption+2
   
    # Option (43) - Vendor-Specific Information
    elif (numOption == 43):
      string = "\t>Option: (43) Vendor-Specific Information\n"+"\t\tLength: "+str(longueurOption)+"\n"+"\t\tValue: "+''.join(listeTrace[optionIndice+2: optionIndice+2+longueurOption])
      print(string)
      writerOK.write(string+'\n')
      optionIndice += longueurOption+2
  
    # Option (50) - Requested IP Address
    elif (numOption == 50):
      string = "\t>Option: (50) Requested IP Address ("+ip_decimal(listeTrace[optionIndice+2:optionIndice+2+longueurOption])+")\n"+"\t\tLength: "+str(longueurOption)+"\n"+"\t\tRequested IP Address: "+ip_decimal(listeTrace[optionIndice+2:optionIndice+2+longueurOption])
      print(string)
      writerOK.write(string+'\n')
      optionIndice += longueurOption+2
    
    # Option (51) - IP Address Lease Time
    elif (numOption == 51):
      string = "\t>Option: (51) IP Address Lease Time \n"+"\t\tLength: "+str(longueurOption) + "\n"+"\t\tIP Address Lease Time: ("+str(hex_to_decimal(ajouter_octets(listeTrace[optionIndice+2:optionIndice+2+longueurOption])))+"sec)"
      print(string)
      writerOK.write(string+'\n')
      optionIndice += longueurOption+2
    
    # Option (54) - DHCP Server Identifier
    elif (numOption == 54):
      string = "\t>Option: (54) DHCP Server Identifier ("+ip_decimal(listeTrace[optionIndice+2:optionIndice+2+longueurOption])+")\n"+"\t\tLength: "+str(longueurOption)+"\n"+"\t\tDHCP Server Identifier: "+ip_decimal(listeTrace[optionIndice+2:optionIndice+2+longueurOption])
      print(string)
      writerOK.write(string+'\n')
      optionIndice += longueurOption+2

    # Option (55) - Parameter Request List 
    elif (numOption == 55):
      donnees = affichage_option55(longueurOption, listeTrace[optionIndice+2:optionIndice+2+longueurOption])
      # Si pas un item present, le signaler et sortir pour analyser la trame suivante
      if (donnees == 0):
        return 0
  
      else:
        string = "\t>Option: (55) Parameter Request List\n"+"\t\tLength: "+str(longueurOption)+"\n"+donnees
      print(string, end='')
      writerOK.write(string)
      optionIndice += longueurOption+2
     
    # Option (57) - Maximum DHCP Message Size
    elif (numOption == 57):
      string = "\t>Option: (57) Maximum DHCP Message Size\n"+"\t\tLength: "+str(longueurOption)+"\n"+"\t\tMaximum DHCP Message Size: "+str(hex_to_decimal(ajouter_octets(listeTrace[optionIndice+2:optionIndice+2+longueurOption])))
      print(string)
      writerOK.write(string+'\n')
      optionIndice += longueurOption+2
    
    # Option (58) - Renewal Time Value
    elif (numOption == 58):
      string = "\t>Option: (58) Renewal Time Value\n"+"\t\tLength: "+str(longueurOption)+"\n"+"\t\tRenewal Time Value: ("+str(hex_to_decimal(ajouter_octets(listeTrace[optionIndice +2:optionIndice+2+longueurOption])))+"sec) "
      print(string)
      writerOK.write(string+'\n')
      optionIndice += longueurOption+2
    
    # Option (59) - Rebinding Time Value
    elif (numOption == 59):
      string = "\t>Option: (59) Rebinding Time Value \n"+"\t\tLength: "+str(longueurOption)+"\n"+"\t\tRebinding Time Value: ("+str(hex_to_decimal(ajouter_octets(listeTrace[optionIndice+2:optionIndice+2+longueurOption])))+"sec)"
      print(string)
      writerOK.write(string+'\n')
      optionIndice += longueurOption+2
      
    # Option (61) - Client identifier  
    elif (numOption == 61):
      string = "\t>Option: (61) Client identifier\n"+"\t\tLength: "+str(longueurOption) +"\n"+"\t\tHardware type: Ethernet (0x"+str(listeTrace[optionIndice+2])+")\n"+"\t\tClient MAC address: "+mac_construire(listeTrace[optionIndice+3:optionIndice+2+longueurOption])
      print(string)
      writerOK.write(string+'\n')
      optionIndice += longueurOption+2

    # Option (224) - Private
    elif(numOption == 244):
      string = "\t>Option: (224) Private\n"+"\t\tLength: "+str(longueurOption)+"\n"+"\tValue: "+''.join(listeTrace[optionIndice+2:optionIndice+2+ longueurOption])
      print(string)
      writerOK.write(string+'\n')
      optionIndice += longueurOption+2
    
    # Pas une de ces options
    else:
      print("=== La version acutelle ne connais pas cette option ("+str(numOption)+") ===")
      writerErreurs.write("=== La version acutelle ne connais pas cette option ("+str(numOption)+") ====\n")
      return 0    # Sortie si on connais pas une option


  # Option (255) - End
  print("\t>Option: (255) End\n" + "\t\tOption End: 255")
  writerOK.write("\t>Option: (255) End\n" + "\t\tOption End: 255\n")
  optionIndice += 1

  # Affichage et ecriture padding
  if (hex_to_decimal(listeTrace[optionIndice]) == 0):
    nombreOctetsZeros = tailleTrame - optionIndice
    print("\tPadding: " + "00"*nombreOctetsZeros)
    writerOK.write("\tPadding: " + "00"*nombreOctetsZeros + "\n") 

  # Fermeture des deux fichiers d'ecriture 
  writerOK.close()
  writerErreurs.close()

  return
# ----------------------------------------------------------------------------- #
def affichage_option55(longueurOption, listeItems):
  # Fichier ou on ecrira les erreur possibles de l'analyse IP
  writerErreurs = open("Trames/Analyse/Erreur_analyse_trames.txt", 'a')
  items_string = ""

  items = {
    1: "\t\tParameter Request List Item: (1) Subnet Mask\n",
    121: "\t\tParameter Request List Item: (121) Classless Static Route\n",
    3: "\t\tParameter Request List Item: (3) Router\n",
    6: "\t\tParameter Request List Item: (6) Domaine Name Server\n",
    15: "\t\tParameter Request List Item: (15) Domain Name\n",
    114: "\t\tParameter Request List Item: (114) DHCP Captive-Portal\n",
    119: "\t\tParameter Request List Item: (119) Domain Search\n",
    252: "\t\tParameter Request List Item: (252) Private/Proxy autodiscovery\n",
    95: "\t\tParameter Request List Item: (95) LDAP [TODO:RFC3679]\n",
    44: "\t\tParameter Request List Item: (44) NetBIOS over TCP/IP Name Server\n",
    46: "\t\tParameter Request List Item: (46) NetBIOS over TCP/IP Node Type\n",
    42: "\t\tParameter Request List Item: (42) Network Time Protocol Servers\n"
    
  }
  for i in range(longueurOption):
    item = items.get(int(listeItems[i], 16))
    # Si pas un item present, le signaler et sortir pour analyser la trame suivante
    if (item == None):
      print("==== Il n'existe pas d'item ("+str(int(listeItems[i], 16))+")  dans notre analyseur ====")
      writerErreurs.write("==== Il n'existe pas d'item ("+str(int(listeItems[i], 16))+")  dans notre analyseur ====\n")
      return 0      # Sortie du programme
      
    else:
      items_string += item
      

  # Fermeture des deux fichiers d'ecriture 
  writerErreurs.close()

  return items_string
# ----------------------------------------------------------------------------- #
  