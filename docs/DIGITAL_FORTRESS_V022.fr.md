# DIGITAL FORTRESS — candidat v0.2.2

[English](DIGITAL_FORTRESS_V022.md) · [README français](../README.fr.md)

Ce candidat source local Windows est expérimental : ce n'est ni une release publiée, ni un audit complet, ni une certification de sécurité, ni une garantie d'aptitude à la production. Le [guide local](DIGITAL_FORTRESS_LOCAL.md) décrit séparément la fixture et l'import.

## Périmètre

Le candidat propose une **tentative explicite d'observation HTTPS HEAD** d'une URL saisie : au plus une requête HTTP par tentative, sans nouvelle tentative automatique ni suivi des redirections 3xx. Un refus ou un échec préalable peut empêcher l'envoi du HEAD. Ce n'est ni un scanner de vulnérabilités ni une tentative d'exploitation. Une réponse HTTP, une négociation réussie ou la simple présence d'un en-tête de sécurité ne démontrent ni la sécurité ni la conformité de l'en-tête. Une observation incomplète, bloquée ou en échec ne signifie pas que tout est conforme.

Ne tenter une observation qu'avec une autorisation explicite couvrant précisément la cible, le chemin, la méthode et le moment. La case de consentement est une déclaration, pas une preuve indépendante d'autorisation. Le chemin et les paramètres sont transmis au service local et à la cible ; le résultat affiché les masque. Éviter les secrets dans les URL. Ne pas exposer l'application locale publiquement.

## Protections et limites

- Le transport valide les destinations HTTPS et les réponses DNS, refuse les adresses privées et d'autres adresses spéciales, se connecte à une adresse contrôlée et compare le pair connecté. Cette atténuation SSRF exclut volontairement certaines adresses publiques de transition ou de relais ; elle ne prouve pas la protection dans tous les contextes réseau ou de déploiement.
- TLS utilise les autorités de confiance du système et vérifie le certificat et le nom d'hôte. Une négociation vérifiée ne certifie ni le site, ni son contenu, ni la sécurité de sa configuration. Une erreur TLS/transport peut avoir plusieurs causes ; ne pas conclure à un certificat invalide sans preuve.
- L'annulation dans l'interface ou le changement de vue ne propage **pas** l'annulation au worker. Un délai supervisé vise à borner l'exécution, sans garantie absolue de temps réel.
- Le nettoyage après crash du parent n'est que partiellement qualifié ; l'exclusion entre sessions n'a pas été démontrée. Un mutex nommé ne prouve ni ses permissions ni l'isolation entre sessions et identités. Ne présumer ni ces garanties ni l'aptitude à la production.
- La fixture locale et les rapports importés sont distincts des observations réelles : la fixture est synthétique ; les observations importées sont déclarées par l'utilisateur, sans authentification indépendante. Une fixture ou un mock local ne prouve pas le comportement du transport Internet.

La lecture de ce document n'effectue aucune observation réseau. Les métadonnées du candidat ne prouvent pas la disponibilité distante d'un tag ou d'une release v0.2.2.
