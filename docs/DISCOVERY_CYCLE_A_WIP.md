# Cycle A discovery — état expérimental, NO GO

Un prototype de parcours multipage expérimental est présent dans
`fortress_discovery_lab` : aucun hôte, socket, certificat ou contenu ne peut être
fourni à son point d'entrée. Il ouvre sa propre boucle locale, sans DNS, et utilise
le moteur GET/TLS v0.2.3. Les liens et redirections proviennent des réponses
reçues ; `_ROUTES` définit les réponses de la fixture, pas la frontière du crawl.
Ne pas raccorder ces modules à une API, au cockpit ou à un worker.
Le module `fortress_discovery_a` reste une projection HTML hors ligne, non qualifiée comme
politique de requête. Ses compteurs ne sont ni des URLs ni des preuves réseau :
`internal_links`, `excluded_links`, `scripts`, `stylesheets`, `forms`,
`api_references` (heuristique limitée aux attributs contenant `/api`). Ils ne
constituent pas le contrat final de la phase B ; leur somme ne décrit pas la
couverture d'un site et les références peuvent être extérieures ou dupliquées.
Le résultat ne contient ni URL ni corps ; entrée invalide ou trop volumineuse :
`None`. Aucun mécanisme d'authentification ou de requête n'est présent.

Le résultat de `run_lab` contient les compteurs `pages`, `requests`, `bytes`,
`complete`, `reason` et un `graph` : `pages[]` (`route`, `depth`, `status`),
`relations[]` (`from`, `to`, `kind` link/redirect) et `resources[]` (`page`,
`kind` script/stylesheet/form/api). Une relation peut cibler une page non visitée
ou une redirection. Les ressources ne sont ni téléchargées ni dédupliquées ; la
détection API est une heuristique d'attributs, pas une analyse JavaScript.

Les identifiants de route sont des SHA-256 déterministes des chemins synthétiques.
Un hash non salé est devinable par dictionnaire : il ne protège pas les secrets
et ce schéma n'est pas qualifié pour des données réelles. Aucun corps, paramètre,
en-tête ou valeur de formulaire n'est exporté. Les exclusions ne sont pas toutes
inventoriées individuellement. Le plafond de 20 pages, la profondeur 2, les 30
requêtes (redirections comprises), 700 ms, 10 Mio et 120 s sont appliqués ; la
durée est coopérative et une lecture ou le nettoyage peut retarder le retour.
Le transport existant limite la réponse complète à 64 Kio et n'accepte que
Content-Length, sans décompression : pas de plafond de 512 Kio décodés démontré.
La suppression des fragments et la résolution relative précèdent la déduplication ;
paramètres, `%`, backslash, autres origines, API et routes dangereuses sont refusés.
La liste de mots dangereux n'est pas exhaustive et un GET peut avoir des effets.

`reason` vaut `none`, `depth_limit`, `page_limit`, `request_limit`,
`duration_limit`, `byte_limit`, `redirect_blocked`, `redirect_loop`,
`http_refused` ou `incomplete`. Une seule raison ne décrit pas toutes les omissions ;
`complete` concerne seulement la frontière admise du laboratoire.

Les tests ciblés utilisent une fixture TLS locale réelle, incluent un changement
métamorphique de contenu, des URL adversariales et les limites 20/30. Seul le
premier test métamorphique a été observé en échec avant implémentation ; les autres
sont des vérifications après implémentation.

Bloquants avant activation : qualifier les budgets et leur gestion des états
partiels en conditions adversariales, y compris 512 Kio décodés, et établir une borne d'exécution et
d'exclusion couvrant réellement DNS, transport, annulation, concurrence et
nettoyage. Démontrer la validation même origine HTTPS à chaque redirection,
DNS/IP et pair épinglé à chaque connexion, TLS et SNI vérifiés, cadrage HTTP,
traitement des réponses partielles, décodage borné et exclusion des routes
sensibles. La liste locale de mots clés n'est pas une garantie exhaustive.
Démontrer ensuite le secret scrub et le contrat de sortie sur erreurs et
tracebacks, et tester l'ensemble sur fixture HTTPS loopback isolée uniquement.
Aucune de ces garanties réseau n'est démontrée par les tests de projection.
