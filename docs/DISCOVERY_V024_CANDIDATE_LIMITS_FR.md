# SENTINEL X — NIGHTFALL : limites du candidat Discovery v0.2.4

Ce document décrit les sources et leurs limites, pas l'existence d'un tag ou
d'une Release. Vérifier leur disponibilité dans les Releases GitHub et consulter
`VERSION` pour identifier la version des sources de la copie choisie.

## Portée et confidentialité

L'exploration est un GET HTTPS borné, sur le seul périmètre autorisé. Les références à des scripts et feuilles de style sont comptées par page, sans téléchargement automatique. Leur somme est un nombre de références, non d'URL distinctes. Les exclusions sont comptées par référence effectivement examinée ; les motifs `unknown` restent indéterminés. Un filtre de noms ne peut pas reconnaître toutes les routes susceptibles d'avoir des effets : un GET n'est pas intrinsèquement sans effet.

Le rapport partageable n'inclut pas la correspondance privée. La vue technique est désactivée par défaut et nécessite une option distincte du consentement à l'exploration. Elle ne montre qu'un vocabulaire de segments génériques autorisés ; les autres sont masqués. Deux chemins distincts peuvent avoir la même projection mais restent distingués par leur alias. Un mot générique autorisé pourrait lui-même être sensible : la revue humaine avant capture ou partage reste nécessaire. La mémoire, les outils de diagnostic du navigateur et les captures d'écran ne garantissent pas l'effacement physique des données.

Si les chemins exacts ne figurent pas dans une réponse conservée, ne pas les reconstituer ni les inventer. La structure des rapports anonymisés reste une information à examiner avant partage.

## Observations et interprétation

Les informations TLS optionnelles proviennent du chemin d'exécution qui a validé certificat et nom. Absence d'attestation signifie inconnu, pas invalide ni conforme. Les constats HSTS/CSP/cookies concernent les seules réponses effectivement analysées ; ils ne constituent pas une vulnérabilité démontrée ni une certification du site. La politique Report-Only reste distincte de la politique active. Les valeurs de cookies ne sont pas exposées dans le rapport.

Le compteur `requests` représente des tentatives. Les envois et réponses sont distincts ; un envoi potentiellement partiel reste indéterminé. Une page incomplète peut conserver le statut et les noms d'en-têtes validés sans dévoiler leurs valeurs. Une limite de pages atteinte après collecte est une collecte bornée à couverture partielle, pas une panne ni une exploration complète.

Le statut `304` est représenté comme réponse non analysée et non comme redirection suivie. L'analyse de contenu complet reste limitée aux formes prises en charge par le transport. Les réponses `Content-Length`, `chunked` et sans corps correctement cadrées se terminent sans attendre systématiquement la fermeture TLS. Les octets déjà lus au-delà du cadrage sont rejetés ; ceux qui arriveraient plus tard ne sont pas inspectés et la connexion n'est pas réutilisée. Les réponses délimitées par fermeture exigent une fin TLS propre, sous limites de taille et de temps. Les trailers restent refusés.

## Limites de recette

Le laboratoire local et les simulations ne constituent pas une nouvelle observation publique ni une attestation d'isolation réseau au niveau du système. Les tests de la vue privée via jsdom utilisent des données synthétiques ; ils ne prouvent pas tous les effets possibles des outils navigateur ou des journaux tiers. Les délais et la supervision Windows conservent leurs limites précédemment documentées ; l'annulation de l'interface n'atteste pas l'arrêt du worker et les ports libérés ne prouvent pas seuls l'absence de tous les descendants après panne.

La candidate est identifiée comme **v0.2.4** dans ses métadonnées applicatives. Cela ne transforme pas une version absente des preuves historiques en version attestée : la version du moteur non fournie reste affichée comme inconnue. Une relecture des preuves sauvegardées ne constitue pas une nouvelle campagne.

## Avant une PR officielle

Effectuer une revue ciblée du diff et de la confidentialité, résoudre explicitement la cohérence de version et vérifier que les fichiers et tests nécessaires sont bien inclus. L'autorisation de préparer une PR n'est pas une autorisation de pousser ou de publier. Une nouvelle observation d'un site public nécessite un GO distinct et un périmètre explicite.
