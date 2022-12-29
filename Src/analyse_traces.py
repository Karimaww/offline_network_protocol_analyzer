import re # Bibliotheque pour les expressions regulieres (RegEx)

# ----------------------------------------------------------------------------- #
def nettoyage_regulier(nomFichier, fichierEcriture):
  # Ouverture du ficher texte en lecture contenant les octets 'bruts'
  reader = open(nomFichier, 'r')
  # Fichier ou on ecrira les trames apres le nettoyage regulier
  writer = open(fichierEcriture, 'w') 
  # On lit toutes les lignes
  lines = reader.readlines()
  # Fermeture du fichier de lecture 
  reader.close()    

  # Expression qui va selectionner que les trames 
  pattern = "^(\d|[a-f]|[A-F]){3,}\s+(((\d|[a-f]|[A-F]){2})\s)+" 
  nbLignes = 0  # Numero de la ligne dans le fichier nettoyé 

  # Pour chaque ligne du fichier texte
  for line in lines:
    # On cherche s'il y a une ligne de trame sur cette ligne
    result = re.search(pattern, line)   
    # S'il y a bien une ligne de trame 
    if (result):
      # Recuperation de l'offset et des octets pour bien ecrire dans le fichier nettoyé (saut de ligne entre les trames)
      ligne = result.group().split()
      # On fait le saut de ligne a chaque nouvelle trame 
      if (int(ligne[0], 16)==0) & (nbLignes != 0):
        writer.write('\n') 
      # On ecrit la ligne de trame nettoyé
      writer.write(result.group()+'\n')
      # A chaque ecriture on augmente le nombre de lignes ecrites
      nbLignes += 1
 
  # Fermeture du fichier d'ecriture 
  writer.close()

  return fichierEcriture
# ----------------------------------------------------------------------------- #
def nettoyage_traces(nomFichier, fichierEcriture):
  # Ouverture du ficher texte nettoyé en regulier
  reader = open(nomFichier, 'r')
  # Fichier ou on ecrira les trames à analyser
  writer = open(fichierEcriture, 'w')  
  # On lit toutes les lignes
  lines = reader.readlines() 
  # Fermeture du fichier de lecture 
  reader.close()  

  # Variables permettant de nous reperer dans les lignes 
  nbLignes = 1            # Numero de la ligne dans le fichier à analyser
  offsetsExistants = []   # Liste contenant les offsets de la trame courante
  nbChiffresHexa = 0      # Variable qui stockera le nb de chiffres héxa de l'offset
  ligneAEcrire = ''       # Ligne à ecrire une fois le nb de octets d'une ligne connus
  tailleTrame = 0         # Valeur qui stockera la taille totale de la trame
  indiceTaille = 0        # Indice d'ecriture des octets de la trame
  versionIP = ''

  # On parcourt ligne par ligne
  for line in lines:
    # Recuperation de la liste d'octets de la ligne
    listeOctets = line.split()
    # Recuperation du nombre d'octets sur la ligne + l'offset
    taille_ligne = len(listeOctets)    

    # Si la ligne est vide on analyse la ligne suivante
    # Ceci peut arriver car on a fait expres de sauter une ligne entre les trames
    if(taille_ligne < 1): 
      continue
      
    offset_hexa = listeOctets[0]        # Recuperation de l'offset 
    int_offset = int(offset_hexa, 16)   # Conversion hexa en decimal

    # Si c'est bien le premier offset de la trame
    if (int_offset == 0): 
      # Si dans la trame precedente (dans le cas ou elle existe) on a pas terminé de ecrire la derniere ligne, on le fait avant de passer a une nouvelle trame
      if (indiceTaille < tailleTrame) & (ligneAEcrire != ''):
        # Si l'en-tête qu'on ecrit utilise IPv4:
        if (len(ligneAEcrire) >= tailleTrame-indiceTaille) & (versionIP == '4') :
          # Recuperation du nb d'octets a ecrire    
          nbOctetsAEcrire = tailleTrame-indiceTaille      
          # Ecriture de ces octets dans le fichier nettoyé
          for i in range(nbOctetsAEcrire+1):
            writer.write(ligneAEcrire[i]+' ')  
          writer.write('\n\n')  # Double saut car on passe a une autre trame apres
          nbLignes += 2   # Car double saut
          # Remise par defaut des valeurs car on s'apprete a nettoyer une nouvelle trame
          offsetsExistants = []
          tailleTrame = 0 
          indiceTaille = 0
          nbChiffresHexa = 0
          ligneAEcrire = ''
        # Si l'en-tête qu'on ecrit utilise IPv6
        else:
          # Ecriture des octets de la derniere ligne 
          for i in range(len(ligneAEcrire)):
            writer.write(ligneAEcrire[i]+' ')  
          writer.write('\n\n')  # Double saut car on passe a une autre trame apres
          nbLignes += 2   # Car double saut
          # Remise par defaut des valeurs car on s'apprete a nettoyer une nouvelle trame
          offsetsExistants = []
          tailleTrame = 0 
          indiceTaille = 0
          nbChiffresHexa = 0
          ligneAEcrire = ''

      
      # Si pas d'offsets deja dans le tableau, int_offset doit etre le tout premier
      if (len(offsetsExistants) == 0): 
        # Recuperation du nb de chiffres hexa de l'offset
        nbChiffresHexa = len(offset_hexa)        
        # On ajoute l'offset actuel dans le tableau
        offsetsExistants += [int_offset]
        # On stocke la ligne à ecrire pour l'offest 0          
        ligneAEcrire = listeOctets                
      
      # Si pas le tout premier, on passe a la ligne suivante
      else:
        continue

    # S'il existe deja un offset precedent
    else:
      # Si les offsets sont sur le meme nb de chiffres héxa
      if (len(offset_hexa) == nbChiffresHexa):
        # Si l'offset precedent est bien son precedent
        if (int_offset > offsetsExistants[-1]):
          # Recuperation du nb d'octets a ecrire pour l'offset precedent (avec l'offset)
          nbOctetsAEcrire = int_offset - offsetsExistants[-1] + 1    # +1 pour l'offset
          
          # Si le nombre d'octets presents sur la ligne est inferieur au nb d'octets
          # indiqués par l'offset on a une ERREUR
          if (len(ligneAEcrire) < nbOctetsAEcrire):
            # On augmente le nombre de lignes car on ecrira l'erreur sur celle-ci
            nbLignes += 1 
            # Ecriture de l'erreur 
            writer.write("==== ERREUR - l."+str(nbLignes)+" === Le nombre d'octets ("+str(len(ligneAEcrire)-1)+") sur la ligne est inferieur au nombre d'octets indiqué par l'offset 0x"+offset_hexa+" ("+str(nbOctetsAEcrire)+")\n\n")
            # Remise par defaut des valeurs car on s'apprete a nettoyer une nouvelle trame
            offsetsExistants = []
            tailleTrame = 0 
            indiceTaille = 0
            nbChiffresHexa = 0
            ligneAEcrire = ''
            continue 

          # On ajoute l'offset actuel dans le tableau
          offsetsExistants += [int_offset]                    
          # On ecrit le nombre d'octets pour l'offset precedent
          # Si plus d'octets sur la ligne on prends que ceux indiqués par l'offset
          for i in range(nbOctetsAEcrire): 
            # On compte pas l'offset dans l'indice
            if (i != 0):                                      
              indiceTaille += 1 
            # Si on est à l'indeice 15 de la trame, on pourra trouver la version IP 
            if (indiceTaille == 15):  #### faire avec type
              versionIP = (ligneAEcrire[i])[0]
            # Si on est a l'indice 17 de la trame c'est qu'on a une partie de la taille de l'en-tête IP
            if (indiceTaille == 17):
              tailleTrame =  ligneAEcrire[i]     # Recuperation de cette partie
            # Si on est a l'indice 18 de la trame c'est qu'on a l'autre partie de la taille de l'en-tête IP
            if (indiceTaille == 18):
              tailleTrame += ligneAEcrire[i]     # Recuperation de la derniere partie
              # Conversion de la taille + 14 pour la taille de l'en-tête Ethernet 
              tailleTrame = int(tailleTrame, 16) + 14
            # Ecriture de l'octet d'indice i
            writer.write(ligneAEcrire[i]+' ')
          writer.write('\n')
          nbLignes += 1
          # On stocke la ligne à ecrire pour l'offset actuel
          ligneAEcrire = listeOctets 

        # Si ce n'est pas son offset precedent, on ignore
        else:  
          continue    
      
      # Si l'offset n'est pas sur le même nb de chiffres héxa que l'offset nul, on ignore
      else:
        continue   
  
  # Si dans la trame precedente (dans le cas ou elle existe) on a pas terminé de ecrire la derniere ligne, on le fait avant de terminer l'ecriture
  if (indiceTaille < tailleTrame) & (ligneAEcrire != ''):
    # Si l'en-tête qu'on ecrit utilise IPv4:
    if (len(ligneAEcrire) >= tailleTrame-indiceTaille) & (versionIP == '4') :
      # Recuperation du nb d'octets a ecrire    
      nbOctetsAEcrire = tailleTrame-indiceTaille      
      # Ecriture de ces octets dans le fichier nettoyé
      for i in range(nbOctetsAEcrire+1):
        writer.write(ligneAEcrire[i]+' ')  
      writer.write('\n\n')  # Double saut car on passe a une autre trame apres
      nbLignes += 2   # Car double saut
    # Si l'en-tête qu'on ecrit utilise IPv6
    else:
      # Ecriture des octets de la derniere ligne 
      for i in range(len(ligneAEcrire)):
        writer.write(ligneAEcrire[i]+' ')  
      writer.write('\n\n')  # Double saut car on passe a une autre trame apres
      nbLignes += 2   # Car double saut

  # Fermeture du fichier d'ecriture       
  writer.close()
  return fichierEcriture
# ----------------------------------------------------------------------------- #
def listes_octets_trames(nomFichier):
  # Ouverture du ficher texte en lecture contenant les trames 'parfaites'
  reader = open(nomFichier, 'r')
  # On lit toutes les lignes
  lines = reader.readlines()
  # Fermeture du fichier de lecture 
  reader.close() 

  
  ListeTrames = []      # Liste de listes de Trames
  LR = []               # Liste qui va être incluse dans la liste de listes

  # On parcourt toutes les lignes des trames 
  for line in lines:
    # Il y a un saut de ligne entre chaque nouvelle trame dans les trames 'parfaites'
    # A chaque nouvelle trame on charge la trame liste de la trame precedente dans la liste de listes de Trames
    if (line == '\n'):
      ListeTrames += [LR]
      LR = []               # Remise par defaut pour la liste d'une trame

    # Si la ligne n'est pas vide, donc on est en train d'analyser la ligne d'une trame
    else:  
      LTmp = line.split()   # Recuperation de la liste d'octets + offset
      del LTmp[0]           # Suppresion de l'offset
      LR += LTmp            # Ajout de tous les octets d'une ligne dans une liste contenant tous les octets de la TRAME
  
  # Ecriture de la derniere trame dans la liste de listes de trames
  ListeTrames += [LR] 
  del ListeTrames[-1]   # Suppression de la trame vide 
  
  return ListeTrames
# ----------------------------------------------------------------------------- #





