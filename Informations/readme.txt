########################################################
##      Description de la structure de code           ##
##            et des fonctions réalisées              ##
########################################################

Le projet est partagé en deux parties:
I. Nettoyage des traces
  Fichier "analyse_traces.py":
  Ce fichier comporte 3 fonctions, la premiere, "nettoyage_regulier()" permet de nettoyer/ignorer les lignes de texte situées entre les traces ou entrelacées entre les lignes d’octets. Permet egalement de verifier que chaque octet est codé sur deux chiffres héxadecimaux, qu'il existe un espace entre chaque octet, que l'offset est codé sur au moins 3 octets et que les lignes d'octets debutent bien par un offset valide. On utilise dans cette fonction des expressions regulieres (biliotheque RegEx). Les traces nettoyés sont stockées dans une fichier.txt qui sera pris en charge par la fonction suivante.
     
  La seconde fonction, "nettoyage_traces()", permet de verifier que chaque ligne commence par l’offset du premier octet situé à la suite sur la même ligne, d'eliminer les eventuelles valeurs textuelles en fin de ligne y compris si ces valeurs sont des chiffres hexadécimaux. De plus, elle permet de signaler une erreur sur les lignes d'octets incompletes (i.e les lignes ayant un nombre inferieur d'octets qu'annoncé par l'offset). Les traces pretes à etre analyées sont stockées dans une second fichier.txt qui va etre pris a son tour par la derniere fonction.
     
  La troisieme fonction, "listes_octets_trames()", prepare notre future analyse en créeant une liste de listes d'octets. Chaque liste d'octet correspond a une trame nettoyé. Ceci nous permettra de nous referer par rapport aux indices pour prelever chaque champs. 

  => Ces fonctions seront utilisé dans le main.py final.

  
  
II. Analyse et affichage des traces
  1. Fichier "ethernet.py":
    Ce fichier comporte egalement 3 fonctions qui permetteront d'extraire les champs de l'en-tête Ethernet. 
    La premiere fonction, appelé "analyse_ethernet()", permet d'extraire les champs: Adresse MAC destination, Adresse MAC source et Type de la couche Ethernet en utilisant les indices de la liste fournie en argument (listeTrace). Ces informations serot ecrites dans le fichier final ou seront montrées toutes les trames analyées comme sur le fichier WireShark. Pour diferencier les differentes trames on utilise une numerotation qui permet de les identifier (nbEth). S'il y a des erreurs, comme un protocole que notre analyseur ne sait pas encore analyser, elles seront ecrites dans "Trames/Analyse/Erreur_analyse_trames.txt". 
    
    Cette fonction appelle la fonction "affichage_ethernet()", qui permet d'ecrire les champs de la couche Ethernet dans une fichier.txt formaté ainsi que dans le terminal. 

    La fonction "mac_construire()" est egalement utilsée pour representer correctement les adresses MAC. 

    => La fonction "analyse_ethernet()" sera utilisé dans le main.py final pour       
       analyser la couche Ethernet de toutes les trames capturées. 
  

  2. Fichier "ip.py":
    Ce fichier comporte beaucoup plus de fonctions que le fichier precedent, nottament grâce a l'en-tête et aux options qu'elle peut contenir.
    La premiere fonction, "analyse_ip()" est la fonction qui va permetre de recuperer chaque champs de l'en-tête et les stocker dans des variables qu'elle donnera a la fonction "affichage_ip()" pour permettre l'affichage. 
    D'autres fonctions comme "hex_to_decimal()", "hex_to_bin()", "decimal_to_bin()", "bin_to_decimal()", decimal_to_bin(), id_construire() et "ip_decimal()" aident a la mise en place du fichier texte formaté et l'affichage sur le terminal. La fonction "analyse_ip()" ecrit egalement les eventuelles erreurs comme l'utilisation d'un protocole que notre analyseur ne sait pas encore analyser. Ces erreurs sont ecrites dans le même fichier que celui de la couche Ethernet. 

    La fonction "affichage_flags()" a été crée car la l'en-tête IP possede un champs particulier (Flags) qui possede comme son nom l'indique des flags, chacun sur 1 bit, donc certaines manipulations en binaire sont necessaires. Cette fonction assure donc l'affichage sur le terminal et l'ecriture dans le fichier formaté.

    L'en-tête IP peut posseder des options et la fonction "affichage_options_ip()" s'assurera qu'elles seront bien affichés si elles existent.

    => La fonction "analyse_ip()" sera la fonction représentatrice de cette couche dans le main.py final et permettra d'analyser l'en-tête IP des differentes trames. 
  

  3. Fichier "udp.py"
    Ce fichier concerne la couche de transport UDP, cette derniere n'etant representé que par 8 octets, elle ne possede donc que 2 fonctions. 
    La premiere est la fonction d'analyse, "analyse_udp()" permetant de recuperer les champs de la couche de transport et le mettre dans des variables afin de les afficher grâce a la fonction d'affichage "affichage_udp()". 
    Si des erreurs surviennent, comme des mauvais ports, elles seront ecrites dans notre fichier d'erreurs.

    => La focntion "analyse_udp()" est la fonction qui analysera les couches transport des differents trames dans main.py.

  4. Fichier "dhcp.py":
    Ce fichier traite la couche réseau et possede un grand nombre d'octets a analyser, donc par consequant un nombre elevé de fonctions pour permettre son fonctionnement. 
    Une premiere fonction d'analyse, "analyse_dhcp()" assurant la récuperation des champs immuables et leur préparation pour l'affichage.

    La fonction affichage_dhcp() est la fonction qui affiche les resultats obtenus, par elle-même ou en appelant d'autres fonction d'affichage comme dhcp_message_type() qui affiche les 8 types de messages d'DHCP: Discover, Offer, Request, Decline, ACK, NAK, Release et Inform.       
    
    Elle appelle egalement la fonction qui affiche les options, contrairement aux champs qu'affiche affichage_dhcp(), les options ne sont pas immuables et ont des champs qui ne sont a leur tour pas immubales. 
    La fonction affichage_options() permet l'affichage des options :
      - Option (1) - Subnet Mask
      - Option (3) - Router
      - Option (6) - Domaine Name Server
      - Option (12) - Host Name
      - Option (28) - Broadcast Address
      - Option (43) - Vendor-Specific Information
      - Option (50) - Requested IP Address
      - Option (51) - IP Address Lease Time
      - Option (54) - DHCP Server Identifier
      - Option (55) - Parameter Request List
      - Option (57) - Maximum DHCP Message Size
      - Option (58) - Renewal Time Value
      - Option (59) - Rebinding Time Value
      - Option (61) - Client identifier
      - Option (224) - Private
      - Option (255) - End
      
    Cette derniere fonction fait egalement appel a la fonction affichage_option55(), car cette derniere possede differents Parameter Request. La version actuelle de notre analyseur est capable de comprendre cette liste de Parameter Request:
      - Parameter Request List Item: (1) Subnet Mask
      - Parameter Request List Item: (121) Classless Static Rout
      - Parameter Request List Item: (3) Router
      - Parameter Request List Item: (6) Domaine Name Server
      - Parameter Request List Item: (15) Domain Name
      - Parameter Request List Item: (114) DHCP Captive-Portal
      - Parameter Request List Item: (119) Domain Search
      - Parameter Request List Item: (252) Private/Proxy autodiscovery
      - Parameter Request List Item: (95) LDAP [TODO:RFC3679]
      - Parameter Request List Item: (44) NetBIOS over TCP/IP Name Server
      - Parameter Request List Item: (46) NetBIOS over TCP/IP Node Type
      - Parameter Request List Item: (42) Network Time Protocol Servers

    D'autres fonctions comme hex_to_ascii(), ajouter_octets(), ip_decimal_domaine() sont utilisées afin de mieux aider le formatage. 

    => La fonction analyse_dhcp() sera presente dans le main.py final et analysera les eventueles trames contenant du DHCP.
       