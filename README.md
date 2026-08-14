# AuditFlow V3 PHP

Application locale d'audit interne avec **un fichier principal `index.php`** et SQLite.

## Lancement avec PHP

Prérequis : PHP 8.1+ avec `PDO_SQLite`.

Dans le dossier :

```bash
php -S localhost:8000
```

Puis ouvrir : `http://localhost:8000`

## Avec XAMPP

1. Copier le dossier dans `C:\xampp\htdocs\`.
2. Démarrer Apache.
3. Ouvrir `http://localhost/auditflow_v3_php/`.

## Comptes de démonstration

- `admin` / `admin123`
- `auditeur` / `audit123`
- `manager` / `manager123`

## Modules

Tableau de bord, cartographie des risques, missions, constats, recommandations, suivi, rapports/impression PDF et journal de traçabilité.

La base `data/auditflow.sqlite` est créée automatiquement.
