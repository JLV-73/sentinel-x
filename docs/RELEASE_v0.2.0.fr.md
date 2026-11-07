# v0.2.0 — notes des sources

`VERSION` et les métadonnées du paquet frontend indiquent 0.2.0. Ce document n'établit pas le statut de la Release ni sa disponibilité distante ; consulter les [Releases GitHub](https://github.com/JLV-73/sentinel-x/releases). Lors du préflight du 07-11-2026, ces notes décrivaient un candidat local et aucun tag ou Release v0.2.0 n'avait été trouvé.

## Périmètre et maturité

| Domaine | État observé dans les sources | Limites |
|---|---|---|
| NIGHTFALL CISA KEV, NVD/CVSS, EPSS et triage | Fonctions locales existantes | Collectes explicites ; données et signaux distincts, pas de score de risque inventé ni diagnostic d’appareil. |
| GHSA | Pilote existant et borné | Recherche explicite d’une CVE locale, une page et 100 avis au maximum ; couverture non exhaustive. |
| DIGITAL FORTRESS fixture | Expérimental | HTTPS de boucle locale ; DNS et pair public simulés ; trois scénarios prédéfinis, pas de site Internet. |
| Import JSON et rapport HTML | Expérimental | Import manuel local, validation fermée, aperçu et export ; observations déclarées, non authentifiées. |
| Analyse Internet d’un site | Désactivée, protections non qualifiées | Aucun lancement même avec URL et autorisation ; pas d’audit de cible réelle. |

Détails et utilisation : [guide local](DIGITAL_FORTRESS_LOCAL.md), [contrat d’import](diagnostic-import-schema.md), [contrat GHSA](GHSA_PILOT_CONTRACT.md). La démo et l’import ne sollicitent pas Internet ; installation et collectes officielles sont distinctes et peuvent en avoir besoin. Ni certification, ni aptitude à la production ou à une exposition publique ne sont promises. Les contrôles existants restent nécessaires ; aucune cible utilisateur n’a été contactée pour préparer ces notes.

## Vérification et parcours historique de préparation

Ces notes reposent sur une lecture statique des sources et documents ; elles n’affirment aucune nouvelle exécution de tests, recette navigateur ou collecte. Les preuves historiques ne sont pas une recette de ce candidat.

Schéma proposé pendant la préparation du candidat ; chaque action exige une autorisation distincte :
1. Revue documentaire et technique du périmètre exact, des licences et des données exclues ; validation indépendante et recette appropriée dans un environnement isolé, sans activer l’analyse Internet.
2. Vérifier les métadonnées de version et décider séparément du commit/arbre exact et du statut pré-release ou stable ; résoudre les écarts avant toute décision. Ne pas déplacer les tags existants ni toucher aux copies et données opérationnelles.
3. Après GO explicite seulement, préparer un tag immuable et une Release source seule ; décider explicitement de son statut et de l’éventuelle diffusion. Aucun binaire, base, sauvegarde, secret ou preuve privée ne doit être inclus. Conserver LICENSE, NOTICE et les droits tiers.
4. Vérifier ensuite le tag, l’arbre, les archives et la visibilité effectivement publiés. Sans GO, conserver uniquement ce candidat local ; même un brouillon distant est une action distincte.
