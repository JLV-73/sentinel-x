# SENTINEL X — NIGHTFALL

**Renseignement cyber défensif : des faits traçables, pas de menaces simulées.**  
JLV LABS · Prototype open source expérimental et défensif · Apache-2.0 · [English](README.md)

**Référence stable P0.1 — INTERNATIONAL EDITION.** Cette branche main utilise uniquement CISA KEV. Les enrichissements NVD/CVSS et FIRST EPSS appartiennent à la branche distincte `p1/intelligence-core`.

![Capture réelle du cockpit NIGHTFALL — CISA](docs/images/overview-en.png)

*Capture applicative d'une validation réelle CISA : contenu daté, pas un flux
d'attaques en direct. Aucune base locale, donnée brute ou preuve privée du poste n'est livrée.*

## Fonctions disponibles

- Cockpit NIGHTFALL français/anglais, tableaux de bord et catalogue CISA.
- Recherche, filtres, pagination et fiches CVE détaillées.
- Synchronisation CISA manuelle : validation, transaction SQLite atomique,
  absence de doublons, empreintes SHA-256 et provenance.
- États sans données/erreur/péremption explicites ; conservation des données
  validées après échec de collecte.
- Backend FastAPI/SQLite et frontend React/TypeScript/Vite/Tailwind/ECharts.


## Installer et démarrer — Windows 11

Prérequis : Git, Python **3.11** et Node.js **24**
avec npm. Le projet ne les installe pas globalement. Dépendances Python/npm dans
le dossier du projet uniquement. Utiliser un système de fichiers local normal
acceptant les liens physiques pour l'installation atomique du schéma.

Ouvrir **PowerShell**, pas une invite Python, dans un dossier dédié :

```powershell
git clone https://github.com/JLV-73/sentinel-x.git
cd sentinel-x
py -3.11 -m venv .venv
New-Item -ItemType Directory -Force -Path .cache/pip,.cache/tmp | Out-Null
$env:TEMP = Join-Path (Get-Location) ".cache/tmp"
$env:TMP = $env:TEMP
.\.venv\Scripts\python.exe -I -m pip --isolated install --cache-dir .cache/pip -r backend/requirements-lock.txt
.\.venv\Scripts\python.exe -I tools/bootstrap_schema.py
npm --prefix frontend ci
.\START_SENTINEL.cmd
```

`TEMP`/`TMP` sont limités à cette session PowerShell, sans modification globale de
Windows. Le bootstrap télécharge **localement** le schéma officiel épinglé, vérifie
son SHA-256 et n'écrase jamais un fichier différent. Cette ressource externe n'est
pas redistribuée dans Git : [procédure](docs/SCHEMA_SETUP.md).

Ouvrir soi-même http://127.0.0.1:5177 ; santé API :
http://127.0.0.1:8007/api/health . Le lanceur n'ouvre pas de navigateur personnel,
ne crée pas de service et refuse les ports occupés sans arrêter un autre processus.

Un clone neuf affiche **NO DATA**. Dans **DATA CONTROL**, déclencher une première
synchronisation CISA manuelle. Un accès réseau est nécessaire ; aucune protection
d'accès officielle n'est contournée. Aucun jeu fictif n'alimente les indicateurs
réels et aucune collecte ne démarre automatiquement avec l'application.

**Arrêter :** Ctrl+C dans la console du lanceur, puis confirmer si Windows le
demande. Ne pas exposer ces serveurs de développement hors de `127.0.0.1`.

## Vérifier

```powershell
.\.venv\Scripts\python.exe -I -m pytest backend/tests -q
.\.venv\Scripts\python.exe -I -m unittest discover -s scripts -p "test*.py" -v
.\.venv\Scripts\python.exe -I -m unittest discover -s tools -p "test*.py" -v
npm --prefix frontend test
npm --prefix frontend run build
```

Ces tests utilisent des jeux isolés, pas la base d'exploitation. Ils ne lancent ni
recette navigateur ni actualisation officielle. Suites historiques réussies pour
ce snapshot : [vérifications](docs/VERIFICATION.md).

**Sauvegarde à la demande :** `.\.venv\Scripts\python.exe -I scripts/backup.py`
crée sous `data/backups/` une sauvegarde SQLite cohérente avec sources et manifeste
SHA-256. Restaurer et vérifier dans un dossier séparé avant tout remplacement.
Ne jamais committer bases, caches bruts, sauvegardes, environnements ou dépendances.

## Documentation

[Architecture](docs/ARCHITECTURE.md) · [Sources](docs/SOURCES.md) ·
[Roadmap](docs/ROADMAP.md) · [Correspondance historique](docs/HISTORY_MAP.md) ·
[Contributions](CONTRIBUTING.md) · [Sécurité](SECURITY.md) ·
[Changelog](CHANGELOG.md) · [Notices tierces](THIRD_PARTY_NOTICES.md)

## Limites et licence

Prototype local défensif mono-utilisateur : aucun scanner, exploit, inventaire
automatique, alerte planifiée, IA autonome, connecteur de télémétrie, hébergement
public ou authentification multi-utilisateur. Une entrée KEV ne prouve pas qu'un
appareil est vulnérable. Les échéances CISA ne sont pas des obligations françaises générales.

Réserves actuelles : bundle frontend volumineux et dépréciation d'une dépendance.
P1-A ajoute quotas fournisseurs, délais réseau coopératifs et non absolus,
couverture NVD partielle, fraîcheur des caches et paramètre NVD déprécié mais testé.
Revoir les conditions des sources avant toute redistribution à grande échelle.

**Sous [Apache License 2.0](LICENSE)** pour le code original dont JLV LABS détient les droits.
Conserver [NOTICE](NOTICE) ; droits des tiers séparés. Voir le
[périmètre de licence](COPYRIGHT.md) et les [contributions](CONTRIBUTING.md).
Aucune base locale, réponse brute ou arborescence de dépendances n'est incluse.
Code public, mais aucun service hébergé, release, package ou binaire proposé.
Fusions structurantes, releases et changements futurs de visibilité exigent le GO JLV.
Les versions des manifests ne sont pas des annonces de release.
