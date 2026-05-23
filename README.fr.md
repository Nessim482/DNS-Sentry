# DNS-Sentry

[English version](README.md)

DNS-Sentry est un outil défensif de cybersécurité qui détecte de possibles tentatives de DNS tunneling en analysant l'entropie de Shannon des sous-domaines DNS.

Il détecte et alerte uniquement. Il ne bloque pas le trafic.

## Fonctionnalités

- Calcul de l'entropie de Shannon pour les sous-domaines DNS.
- Analyseur de domaines avec seuil d'entropie configurable.
- Parser simple de requêtes ou lignes DNS.
- Monitoring DNS en temps réel avec Scapy.
- Alertes Discord via webhook avec embeds structurés.
- Configuration par `.env` avec `python-dotenv`.
- Interface en ligne de commande avec `argparse`.
- Interface graphique Tkinter avec l'icône DNS-Sentry lorsque disponible.
- Mode démo sans capture réseau réelle.
- Logging sécurisé qui évite d'exposer les valeurs sensibles du webhook.
- Suite de tests Pytest.
- Workflow GitHub Actions pour les vérifications automatiques.
- Dépendances déclarées dans `pyproject.toml`.

## Fonctionnement

DNS-Sentry observe les requêtes DNS et extrait le nom de domaine demandé. L'analyseur se concentre sur la partie sous-domaine, calcule son entropie de Shannon, puis compare le résultat avec un seuil configuré.

Des sous-domaines à forte entropie peuvent indiquer des données encodées ou aléatoires, souvent associées à du DNS tunneling. C'est un signal heuristique, pas une preuve d'activité malveillante.

Lorsqu'une requête est considérée comme suspecte, DNS-Sentry journalise l'événement et peut envoyer une alerte Discord si un webhook est configuré.

## Installation

Installer le projet en mode éditable avec les dépendances de développement :

```bash
python -m pip install -e ".[dev]"
```

Après installation, le paquet peut être lancé avec :

```bash
python -m dns_sentry
```

ou avec la commande console :

```bash
dns-sentry
```

## Prérequis système

- Python 3.10 ou plus récent.
- `pip` pour l'installation.
- Scapy pour le monitoring DNS réel.
- Permissions de capture réseau pour le monitoring réel.
- Tkinter pour l'interface graphique. Il est inclus avec beaucoup d'installations Python, mais certains systèmes le fournissent séparément.

Les tests et le mode démo ne nécessitent pas Npcap ni de capture réseau réelle.

## Prérequis Npcap sur Windows

Sur Windows, le monitoring DNS réel nécessite Npcap.

Npcap n'est pas installé par `pip` et doit être installé séparément avec l'installateur officiel de Npcap. Le vrai monitoring peut aussi nécessiter un terminal lancé en administrateur.

Les commandes suivantes ne nécessitent pas Npcap :

```bash
python -m pytest
python -m dns_sentry --demo
python -m dns_sentry --check-env
```

## Note de permissions Linux/macOS

Le monitoring DNS réel nécessite Scapy et les permissions nécessaires pour capturer le trafic réseau. Sur Linux ou macOS, il peut être nécessaire d'utiliser des privilèges élevés ou de configurer les permissions de capture selon l'environnement.

Le mode démo et les tests ne nécessitent pas de permissions de capture réseau.

## Configuration avec `.env`

Créer un fichier `.env` local à partir de `.env.example` si nécessaire :

```env
DISCORD_WEBHOOK_URL=
DNS_ENTROPY_THRESHOLD=4.0
DNS_INTERFACE=Wi-Fi
DNS_DEBUG=false
```

Variables de configuration :

- `DISCORD_WEBHOOK_URL` : webhook Discord optionnel pour les alertes.
- `DNS_ENTROPY_THRESHOLD` : seuil d'entropie utilisé pour signaler les domaines suspects.
- `DNS_INTERFACE` : nom optionnel de l'interface réseau pour le monitoring réel.
- `DNS_DEBUG` : mettre à `true` pour activer les logs de debug.

Règles de sécurité :

- `.env` ne doit jamais être commit.
- `.env.example` est safe à commit car il ne contient aucun vrai secret.
- Un webhook Discord est un secret et doit rester privé.
- Ne pas commit de tokens, webhooks, vrais fichiers `.env`, captures réseau ou logs contenant des données privées.

## Utilisation CLI

Vérifier les dépendances et le chargement de la configuration sans capturer de trafic :

```bash
python -m dns_sentry --check-env
```

Lancer le mode démo sans capture réseau réelle :

```bash
python -m dns_sentry --demo
dns-sentry --demo
```

Lancer le monitoring DNS réel avec une interface et un seuil explicites :

```bash
python -m dns_sentry --interface Wi-Fi --threshold 4.0
```

Le monitoring réel nécessite Scapy et les permissions de capture réseau.

## Utilisation GUI

Lancer l'interface graphique Tkinter :

```bash
python -m dns_sentry --gui
dns-sentry --gui
```

La GUI permet de définir l'interface réseau, le seuil d'entropie, un webhook Discord optionnel et le niveau de debug. Elle peut lancer le monitoring réel, l'arrêter et exécuter le mode démo.

Le monitoring réel depuis la GUI a les mêmes prérequis Scapy, Npcap et permissions que la CLI.

## Mode démo

Le mode démo analyse des domaines d'exemple intégrés et ne capture aucun trafic réseau réel.

```bash
python -m dns_sentry --demo
dns-sentry --demo
```

Le mode démo est utile pour vérifier l'analyseur, les logs et le chemin d'alerte Discord optionnel sans nécessiter Npcap ni permissions de capture.

## Alertes Discord

Si `DISCORD_WEBHOOK_URL` est configuré, DNS-Sentry peut envoyer une alerte Discord lorsqu'une requête DNS suspecte est détectée.

Les alertes incluent le domaine, le sous-domaine, le score d'entropie, le seuil, le niveau de sévérité et l'horodatage UTC.

Le webhook doit rester secret. Ne jamais coller un vrai webhook dans la documentation, des tickets, des logs, des commits ou des captures d'écran.

## Lancer les tests

Installer les dépendances de développement et lancer la suite de tests :

```bash
python -m pip install -e ".[dev]"
python -m pytest
```

Les tests ne nécessitent pas Npcap ni de capture réseau réelle.

## GitHub Actions

Le dépôt contient un workflow GitHub Actions lancé sur les pushes et les pull requests. Il installe le projet, lance pytest, vérifie le chargement de l'environnement et exécute le mode démo sur Python 3.11 et 3.12.

Aucun vrai webhook Discord n'est nécessaire en CI.

## Notes de sécurité

- DNS-Sentry est uniquement un outil de détection et d'alerte.
- Il ne bloque pas le trafic DNS et n'arrête pas les attaques.
- Garder les fichiers `.env`, webhooks Discord, captures réseau et logs privés hors des commits.
- Le dépôt ignore `.env`, `.env.*` sauf `.env.example`, les captures réseau, les logs, les caches Python et les métadonnées de build.
- Utiliser l'outil uniquement sur des systèmes et réseaux pour lesquels vous avez une autorisation.

## Limitations connues

- La détection repose sur l'entropie de Shannon et peut générer des faux positifs.
- Du tunneling à faible entropie ou d'autres techniques d'évasion peuvent ne pas être détectés.
- Le sniffer temps réel se concentre sur les requêtes DNS visibles par Scapy, pas sur le DNS chiffré comme DoH ou DoT.
- Les noms d'interfaces varient selon le système d'exploitation et la configuration réseau.
- DNS-Sentry ne remplace pas un IDS, SIEM, EDR ou outil professionnel de supervision réseau.

## Clause défensive et légale

DNS-Sentry est destiné au monitoring défensif, à l'apprentissage et aux tests de sécurité autorisés. Utilisez-le uniquement sur des réseaux et systèmes que vous possédez ou que vous êtes explicitement autorisé à surveiller.

Vous êtes responsable du respect des lois, politiques internes et exigences de confidentialité applicables.
