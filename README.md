# DNS-Sentry

DNS-Sentry est un outil defensif de cybersecurite pour detecter des signaux
suspects de DNS tunneling a partir de l'analyse statistique des noms de
domaine, notamment via l'entropie de Shannon.

## Objectif actuel

Cette branche contient uniquement le coeur logique minimal du projet :

- calcul d'entropie de Shannon ;
- extraction simple du sous-domaine ;
- analyse d'un domaine avec un seuil configurable.

## Exemple d'utilisation

```python
from dns_sentry.analyzer import analyze_domain

result = analyze_domain("dGhpcy1sb29rcy1saWtlLWJhc2U2NC1kYXRh.example.com")

print(result)
```

## Tests

```bash
python -m pip install -e ".[dev]"
python -m pytest
```

## Configuration

Copier `.env.example` vers `.env` localement si necessaire. Ne jamais committer
de vrai fichier `.env`.

- `DISCORD_WEBHOOK_URL` : webhook Discord optionnel.
- `DNS_ENTROPY_THRESHOLD` : seuil d'entropie, defaut `3.5`.
- `DNS_INTERFACE` : interface reseau optionnelle.
- `DNS_DEBUG` : mode debug, defaut `false`.

## Future work

- TODO: capture reseau, hors scope de cette branche.
- TODO: notifications Discord, hors scope de cette branche.
- TODO: interface graphique, hors scope de cette branche.
