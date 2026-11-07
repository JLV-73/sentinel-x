# Import local des diagnostics HTTPS — version 1

Le fichier est choisi manuellement, lu localement en mémoire, au plus 65 536 octets. MIME `application/json`, ou extension `.json` si le navigateur ne fournit pas de MIME. Aucune URL du fichier n'est une destination réseau. L'import ne contacte ni la cible ni un service et n'enregistre pas le fichier ; l'export HTML est une action distincte. Pas d'import automatique. Le rendu et son export partagent `renderFortressReport` et une iframe sandboxée. Les données déclarées ne sont pas authentifiées ; la provenance n'est pas une attestation cryptographique.

## Contrat fermé

Tous les objets ont exactement les clés indiquées : aucune propriété additionnelle ou clé répétée (même échappée), aucune valeur texte libre, aucun corps, secret, en-tête brut ou valeur de cookie. Tous les champs sont obligatoires sauf `headers.csp_report_only`, optionnel pour compatibilité v1 ; son omission signifie indéterminé, pas absent. Énumérations et null sont littéraux JSON ; entiers sans décimale. La validité du JSON, les types et les contraintes croisées sont vérifiés avant rendu.

- `mode`: `"import"`; `version`: `1`.
- `provenance`: `"original_sanitized_observations"` ou `"report_transcription"` (déclaration uniquement).
- `target`: URL HTTPS canonique ASCII en minuscules, nom DNS à deux labels minimum, chemin `/` uniquement, sans identifiants, port, requête ou fragment ; jamais suivie.
- `observed_at`: date-heure exacte `YYYY-MM-DDTHH:mm:ssZ` ou avec décalage `±HH:mm`, date réelle, offset jusqu'à 14:00 ; le texte est conservé.
- `method`: `"GET"`; `scope`: `"root_only"` (une seule requête racine, sans exploration, scan actif ni test authentifié).
- `http_status`: entier 200–599, réponse complète déclarée.
- `tls`: objet fermé `protocol` (`"TLSv1.2"`, `"TLSv1.3"`, `"unknown"`), `certificate` et `hostname` (`"verified"` ou `"unknown"`), `not_before` et `not_after` (dates comme ci-dessus, toutes deux null ou toutes deux renseignées, début ≤ observation ≤ fin et début < fin), `revocation` (`"not_checked"` ou `"unknown"`). Une vérification déclarée exige protocole connu et les deux vérifications `verified`.
- `headers`: objet fermé contenant :
  - `hsts`: `{state,max_age_seconds,include_subdomains}` ; state `"present"|"absent"|"unknown"`, durée entière 0–999999999999 et booléen ou null si présent ; si absent/inconnu les deux valeurs sont null.
  - `csp`: `{state,unsafe_inline,wildcard,location}` ; même state, indicateurs booléen ou null si présent, null sinon ; `location` toujours `"unknown"`. Les indicateurs agrégés n'identifient aucune directive précise.
  - `csp_report_only` (optionnel) : même objet fermé et mêmes contraintes que `csp`, séparé de la politique active. Report-Only ne l'applique pas ; les indicateurs sont agrégés et leur directive reste inconnue.
  - `referrer_policy`: `"strict-origin-when-cross-origin"|"absent"|"unknown"`.
  - `x_content_type_options`: `"nosniff"|"absent"|"unknown"`.
  - `permissions_policy`: `"present"|"absent"|"unknown"`.
- `cookies`: objet fermé `{count,secure,httponly,samesite_absent}` ; entiers 0–1000, chaque compteur d'attribut au plus égal à count. Aucun nom ni valeur de cookie. Les nombres décrivent la réponse unique.

Hormis l'omission compatible de `csp_report_only`, une valeur manquante n'est jamais complétée : utiliser explicitement les états indéterminés permis ou refuser l'import. Ce contrat volontairement étroit ne représente ni transport incomplet, ni redirection suivie, ni CSP par directive ; ne pas convertir ces cas en résultats positifs.

Les diagnostics réels et leurs preuves peuvent contenir des informations privées et ne sont pas inclus dans ce dépôt. Pour un import, conserver la date et son décalage d'origine ; ne pas attribuer des indicateurs CSP agrégés à une directive précise sans preuve.
