# P2 — démonstration standard synthétique

Cette démonstration locale isolée est distincte de l’application normale et de
`START_SENTINEL.cmd`. Elle ne lance aucun audit de site externe : les résultats
proviennent uniquement d’une réponse synthétique locale. La connexion HTTPS/TLS
sur loopback valide le certificat uniquement contre la CA du laboratoire, avec SAN
et SNI ; le DNS et le pair public sont simulés. Ce n’est pas une preuve TLS publique,
ni une validation de production ou une certification de sécurité. Aucun site
utilisateur réel n’est audité.

## Lancer sous Windows

Prérequis : un checkout P2 avec son environnement `.venv` et les dépendances Python
du projet déjà installées. Node et les dépendances frontend ne sont pas nécessaires
pour ce laboratoire autonome ; ils peuvent l’être pour l’application normale.
Dans PowerShell, remplacez le chemin par celui du checkout courant :

```powershell
Set-Location '<path-to-checkout>'
.\START_FORTRESS_STANDARD_LAB.cmd
```

Gardez la fenêtre ouverte et ouvrez manuellement dans un navigateur l’URL locale
affichée : aucun navigateur n’est ouvert automatiquement. L’interface locale utilise
HTTP sur 127.0.0.1 ; la route synthétique observée est `GET https://standard-lab.invalid/`
et sa connexion TLS est redirigée vers la fixture loopback, sans DNS public. Choisissez
un scénario, cochez la case autorisant uniquement ce GET synthétique, puis cliquez
sur « Exécuter le test ». Le laboratoire expire après environ 60 secondes.
Ctrl+Break a été vérifié pour l’arrêter avant ; Ctrl+C n’a pas été vérifié.

## Lire les résultats

- **Positive** : les attributs du cookie synthétique examiné sont conformes ; cela
  ne signifie pas que tous les contrôles sont conformes ni que le site est sûr.
- **Negative** : un attribut recommandé manque sur le cookie synthétique ; attention.
- **Indeterminate** : réponse synthétique bloquée, résultat incomplet et indéterminé.

Les contrôles non effectués restent indéterminés. Les codes de preuve décrivent
seulement les observations synthétiques ; la présence d’un en-tête ne prouve pas
son efficacité. Le rapport masque les chemins ; les résultats structurés utilisent
des indices de routes plutôt que leurs chemins. Dans les rapports concernés,
l’inclusion de l’origine exige un choix explicite ; elle reste masquée par défaut.
Les valeurs de cookies ne sont jamais intentionnellement stockées.

## Frontière avec l’API

L’API d’audit opérationnelle reste désactivée et renvoie HTTP 503, même pour des
entrées sûres ; le mode avancé n’est pas actif. Le laboratoire utilise son propre
fixture loopback : il ne crée aucune exception implicite pour les IP privées en
production. Sa capacité contribue à protéger les requêtes web entre origines, mais
ne constitue pas une protection contre les processus locaux qui peuvent accéder à
la page.
