# DIGITAL FORTRESS — démonstration et import locaux / local demo and import

## Français

**Expérimental : l’analyse Internet est désactivée.** La saisie d’une URL et la case d’autorisation ne l’activent pas ; ne pas contourner cette désactivation. Le moteur interne de diagnostic n’est pas qualifié pour une cible non fiable. Aucune certification, aucun audit complet ni garantie de sécurité ne découlent d’un rapport. Ne pas exposer l’application publiquement.

### Démo locale

Dans un environnement déjà installé et lancé localement, ouvrir DIGITAL FORTRESS, choisir **HTTPS 200**, **HTTP 403** ou **Erreur TLS**, autoriser la fixture sélectionnée puis lancer la fixture. Une connexion HTTPS de boucle locale utilise une fixture détenue, avec DNS et pair public simulés et une route fixe `GET /` pour `standard-lab.invalid` ; aucun site Internet n’est contacté. Les scénarios et résultats sont des démonstrations, pas des observations de votre site. En cas d’erreur, le résultat est indéterminé, pas une preuve de sécurité. Les certificats et la clé livrés sont des fixtures publiques : ne jamais les utiliser en production ni installer leur CA dans le magasin de confiance système.

### Import et rapport

Choisir manuellement un JSON local conforme au [contrat v1](diagnostic-import-schema.md) : maximum 65 536 octets ; MIME `application/json`, ou extension `.json` si aucun MIME n’est fourni. Le fichier est lu en mémoire ; aucune URL qu’il contient n’est résolue ou contactée. Les objets ont un schéma fermé ; champs manquants, doublons ou valeurs incompatibles entraînent le rejet, avec l’exception documentée pour `csp_report_only`. Ne pas fournir de secrets, corps, en-têtes bruts ni valeurs de cookies. Provenance et observations sont déclaratives, non authentifiées ; l’import n’atteste pas leur exactitude.

Après une fixture ou un import valide, consulter l’aperçu isolé puis, si souhaité, télécharger le rapport HTML : même moteur de rendu, export séparé et explicite. Le rapport peut contenir des informations sensibles déclarées : le conserver et le partager avec précaution. Importer ne crée pas un diagnostic réseau et ne sauvegarde pas automatiquement le fichier d’entrée.

L’usage de ces deux parcours ne nécessite pas de connexion Internet ; l’installation initiale des dépendances et du schéma et les collectes CISA/NVD/EPSS/GHSA décrites dans les README sont des opérations distinctes qui peuvent nécessiter Internet. Ne pas déclencher ces collectes pour la démo locale.

## English

**Experimental: Internet analysis is disabled.** Entering a URL and checking authorization does not enable it; do not bypass this restriction. The internal diagnostic engine is not qualified for an untrusted target. Reports are not certification, a complete audit or a security guarantee. Do not expose the application publicly.

### Local demo

With the application already installed and running locally, open DIGITAL FORTRESS, select **HTTPS 200**, **HTTP 403** or **TLS error**, consent to the selected fixture and run it. Loopback HTTPS uses an owned fixture with simulated DNS and public peer, fixed `GET /` route and `standard-lab.invalid`; no Internet site is contacted. Scenarios and results are demonstrations, not observations of your site. A failure is indeterminate, not proof of security. The bundled certificates and key are public fixtures: never use them in production or install their CA in the system trust store.

### Import and report

Manually select a local JSON file conforming to the [v1 contract](diagnostic-import-schema.md): at most 65,536 bytes; MIME `application/json`, or `.json` extension when no MIME is supplied. It is read in memory; no URL in it is resolved or contacted. Objects have a closed schema; missing fields, duplicate keys or incompatible values are rejected, with the documented `csp_report_only` exception. Do not include secrets, bodies, raw headers or cookie values. Provenance and observations are declarations, not authenticated or independently verified.

After a valid fixture or import, inspect the sandboxed preview and optionally download the HTML report: the same renderer is used, and export is a separate explicit action. A report may contain sensitive declared information; store and share it carefully. Import does not perform a network diagnosis or automatically save the input file.

These two workflows need no Internet connection; initial dependency/schema installation and the CISA/NVD/EPSS/GHSA collections in the READMEs are separate operations that may require Internet. Do not trigger those collections for the local demo.
