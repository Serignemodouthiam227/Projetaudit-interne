<?php
declare(strict_types=1);

session_start();

$db = new PDO('sqlite:' . __DIR__ . '/data/auditflow.sqlite');
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
$db->exec('PRAGMA foreign_keys = ON');

$db->exec("
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    password TEXT,
    name TEXT,
    role TEXT
);

CREATE TABLE IF NOT EXISTS risks(
    id INTEGER PRIMARY KEY,
    code TEXT UNIQUE,
    title TEXT,
    process TEXT,
    probability INTEGER,
    impact INTEGER,
    owner TEXT,
    status TEXT
);

CREATE TABLE IF NOT EXISTS missions(
    id INTEGER PRIMARY KEY,
    code TEXT UNIQUE,
    title TEXT,
    process TEXT,
    auditor TEXT,
    start_date TEXT,
    end_date TEXT,
    status TEXT,
    risk_id INTEGER,
    FOREIGN KEY(risk_id) REFERENCES risks(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS findings(
    id INTEGER PRIMARY KEY,
    code TEXT UNIQUE,
    mission_id INTEGER,
    title TEXT,
    severity TEXT,
    risk_id INTEGER,
    description TEXT,
    FOREIGN KEY(mission_id) REFERENCES missions(id) ON DELETE CASCADE,
    FOREIGN KEY(risk_id) REFERENCES risks(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS recommendations(
    id INTEGER PRIMARY KEY,
    code TEXT UNIQUE,
    finding_id INTEGER,
    title TEXT,
    owner TEXT,
    due_date TEXT,
    priority TEXT,
    status TEXT,
    FOREIGN KEY(finding_id) REFERENCES findings(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_log(
    id INTEGER PRIMARY KEY,
    username TEXT,
    action TEXT,
    created_at TEXT
);
");

function e(mixed $value): string
{
    return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
}

function lvl(int $probability, int $impact): string
{
    $score = $probability * $impact;

    return $score >= 16
        ? 'Critique'
        : ($score >= 10 ? 'Élevé' : ($score >= 5 ? 'Moyen' : 'Faible'));
}

function bc(string $value): string
{
    if (in_array($value, ['Critique', 'Élevée', 'En retard'], true)) {
        return 'red';
    }

    if (in_array($value, ['Élevé', 'Haute'], true)) {
        return 'orange';
    }

    if (in_array($value, ['Moyenne', 'En cours'], true)) {
        return 'blue';
    }

    if (in_array($value, ['Faible', 'Basse', 'Réalisée'], true)) {
        return 'green';
    }

    return 'gray';
}

function logx(string $action): void
{
    global $db;

    $statement = $db->prepare(
        'INSERT INTO audit_log(username, action, created_at)
         VALUES(?, ?, datetime("now"))'
    );

    $statement->execute([
        $_SESSION['user']['username'] ?? 'visiteur',
        $action
    ]);
}

function csrf_token(): string
{
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }

    return $_SESSION['csrf'];
}

function verify_csrf(): void
{
    $token = $_POST['csrf'] ?? '';

    if (
        !isset($_SESSION['csrf']) ||
        !hash_equals($_SESSION['csrf'], $token)
    ) {
        throw new RuntimeException(
            'Session expirée. Rechargez la page puis réessayez.'
        );
    }
}

function next_code(string $table, string $prefix): string
{
    global $db;

    $allowed = [
        'risks',
        'missions',
        'findings',
        'recommendations'
    ];

    if (!in_array($table, $allowed, true)) {
        throw new InvalidArgumentException('Table non autorisée.');
    }

    $count = (int)$db->query(
        "SELECT COUNT(*) FROM {$table}"
    )->fetchColumn();

    return sprintf($prefix . '%03d', $count + 1);
}


/* =========================================================
   DONNÉES DE DÉMONSTRATION
   ========================================================= */

if (!(int)$db->query('SELECT COUNT(*) FROM users')->fetchColumn()) {

    $statement = $db->prepare(
        'INSERT INTO users(username, password, name, role)
         VALUES(?, ?, ?, ?)'
    );

    $users = [
        ['admin', 'admin123', 'Administrateur', 'Administrateur'],
        ['auditeur', 'audit123', 'Amadou Diop', 'Auditeur'],
        ['manager', 'manager123', 'Responsable métier', 'Responsable métier']
    ];

    foreach ($users as $user) {
        $statement->execute([
            $user[0],
            password_hash($user[1], PASSWORD_DEFAULT),
            $user[2],
            $user[3]
        ]);
    }
}

if (!(int)$db->query('SELECT COUNT(*) FROM risks')->fetchColumn()) {

    $statement = $db->prepare(
        'INSERT INTO risks
        (code, title, process, probability, impact, owner, status)
        VALUES(?, ?, ?, ?, ?, ?, ?)'
    );

    $risks = [
        [
            'R-001',
            'Fraude et détournement de fonds',
            'Finance',
            4,
            5,
            'Direction financière',
            'Ouvert'
        ],
        [
            'R-002',
            'Perte ou fuite de données',
            'SI',
            3,
            5,
            'DSI',
            'Ouvert'
        ],
        [
            'R-003',
            'Erreurs de facturation',
            'Ventes',
            3,
            3,
            'Direction commerciale',
            'Sous contrôle'
        ],
        [
            'R-004',
            'Non-respect des procédures achats',
            'Achats',
            4,
            4,
            'Responsable achats',
            'Ouvert'
        ]
    ];

    foreach ($risks as $risk) {
        $statement->execute($risk);
    }
}

if (!(int)$db->query('SELECT COUNT(*) FROM missions')->fetchColumn()) {

    $risks = $db->query(
        'SELECT code, id FROM risks'
    )->fetchAll(PDO::FETCH_KEY_PAIR);

    $statement = $db->prepare(
        'INSERT INTO missions
        (code, title, process, auditor, start_date, end_date, status, risk_id)
        VALUES(?, ?, ?, ?, ?, ?, ?, ?)'
    );

    $statement->execute([
        'MA-001',
        'Audit du processus Achats',
        'Achats',
        'Amadou Diop',
        '2026-08-03',
        '2026-08-21',
        'En cours',
        $risks['R-004'] ?? null
    ]);

    $statement->execute([
        'MA-002',
        'Audit de la trésorerie',
        'Finance',
        'Fatou Ndiaye',
        '2026-07-06',
        '2026-07-24',
        'Terminée',
        $risks['R-001'] ?? null
    ]);
}

if (!(int)$db->query('SELECT COUNT(*) FROM findings')->fetchColumn()) {

    $missions = $db->query(
        'SELECT code, id FROM missions'
    )->fetchAll(PDO::FETCH_KEY_PAIR);

    $risks = $db->query(
        'SELECT code, id FROM risks'
    )->fetchAll(PDO::FETCH_KEY_PAIR);

    $statement = $db->prepare(
        'INSERT INTO findings
        (code, mission_id, title, severity, risk_id, description)
        VALUES(?, ?, ?, ?, ?, ?)'
    );

    $statement->execute([
        'C-001',
        $missions['MA-001'] ?? null,
        'Absence de séparation des fonctions',
        'Élevée',
        $risks['R-004'] ?? null,
        'La commande et la validation ne sont pas suffisamment séparées.'
    ]);

    $statement->execute([
        'C-002',
        $missions['MA-002'] ?? null,
        'Rapprochements bancaires tardifs',
        'Moyenne',
        $risks['R-001'] ?? null,
        'Les rapprochements sont réalisés après le délai prévu.'
    ]);
}

if (!(int)$db->query('SELECT COUNT(*) FROM recommendations')->fetchColumn()) {

    $findings = $db->query(
        'SELECT code, id FROM findings'
    )->fetchAll(PDO::FETCH_KEY_PAIR);

    $statement = $db->prepare(
        'INSERT INTO recommendations
        (code, finding_id, title, owner, due_date, priority, status)
        VALUES(?, ?, ?, ?, ?, ?, ?)'
    );

    $statement->execute([
        'REC-001',
        $findings['C-001'] ?? null,
        'Formaliser la séparation commande/validation',
        'Responsable achats',
        '2026-09-15',
        'Haute',
        'En cours'
    ]);

    $statement->execute([
        'REC-002',
        $findings['C-002'] ?? null,
        'Mettre en place un calendrier de rapprochement',
        'Chef comptable',
        '2026-08-15',
        'Haute',
        'En retard'
    ]);
}


/* =========================================================
   DÉCONNEXION
   ========================================================= */

if (isset($_GET['logout'])) {

    session_unset();
    session_destroy();

    header('Location: ?page=login');
    exit;
}


/* =========================================================
   CONNEXION
   ========================================================= */

$err = null;
$page = $_GET['page'] ?? 'dashboard';

if (isset($_POST['login'])) {

    $page = 'login';

    try {

        $statement = $db->prepare(
            'SELECT * FROM users
             WHERE username = ?
             LIMIT 1'
        );

        $statement->execute([
            trim((string)($_POST['username'] ?? ''))
        ]);

        $user = $statement->fetch();

        if (
            $user &&
            password_verify(
                (string)($_POST['password'] ?? ''),
                $user['password']
            )
        ) {

            session_regenerate_id(true);

            $_SESSION['user'] = [
                'username' => $user['username'],
                'name' => $user['name'],
                'role' => $user['role']
            ];

            csrf_token();

            logx('Connexion');

            header('Location: ?page=dashboard');
            exit;
        }

        $err = 'Identifiant ou mot de passe incorrect.';

    } catch (Throwable $exception) {

        $err = 'Erreur de connexion : ' .
               $exception->getMessage();
    }
}

if ($page !== 'login' && !isset($_SESSION['user'])) {

    header('Location: ?page=login');
    exit;
}


/* =========================================================
   ACTIONS POST
   ========================================================= */

if (isset($_POST['action'])) {

    try {

        verify_csrf();

        switch ($_POST['action']) {

            /* ---------------- RISQUE ---------------- */

            case 'new_risk':

                $probability = (int)($_POST['probability'] ?? 0);
                $impact = (int)($_POST['impact'] ?? 0);

                if ($probability < 1 || $probability > 5) {
                    throw new InvalidArgumentException(
                        'La probabilité doit être comprise entre 1 et 5.'
                    );
                }

                if ($impact < 1 || $impact > 5) {
                    throw new InvalidArgumentException(
                        'L’impact doit être compris entre 1 et 5.'
                    );
                }

                $statement = $db->prepare(
                    'INSERT INTO risks
                    (code, title, process, probability, impact, owner, status)
                    VALUES(?, ?, ?, ?, ?, ?, ?)'
                );

                $statement->execute([
                    next_code('risks', 'R-'),
                    trim((string)$_POST['title']),
                    trim((string)$_POST['process']),
                    $probability,
                    $impact,
                    trim((string)$_POST['owner']),
                    'Ouvert'
                ]);

                logx('Création risque');

                header('Location: ?page=risks');
                exit;


            /* ---------------- MISSION ---------------- */

            case 'new_mission':

                $startDate = (string)($_POST['start_date'] ?? '');
                $endDate = (string)($_POST['end_date'] ?? '');

                if ($startDate > $endDate) {

                    throw new InvalidArgumentException(
                        'La date de début doit être antérieure ou égale à la date de fin.'
                    );
                }

                $riskId = !empty($_POST['risk_id'])
                    ? (int)$_POST['risk_id']
                    : null;

                $statement = $db->prepare(
                    'INSERT INTO missions
                    (code, title, process, auditor, start_date, end_date, status, risk_id)
                    VALUES(?, ?, ?, ?, ?, ?, ?, ?)'
                );

                $statement->execute([
                    next_code('missions', 'MA-'),
                    trim((string)$_POST['title']),
                    trim((string)$_POST['process']),
                    trim((string)$_POST['auditor']),
                    $startDate,
                    $endDate,
                    'Planifiée',
                    $riskId
                ]);

                logx('Création mission');

                header('Location: ?page=missions');
                exit;


            /* ---------------- CONSTAT ---------------- */

            case 'new_finding':

                $missionId = (int)($_POST['mission_id'] ?? 0);
                $severity = (string)($_POST['severity'] ?? '');

                if (!in_array(
                    $severity,
                    ['Faible', 'Moyenne', 'Élevée', 'Critique'],
                    true
                )) {
                    throw new InvalidArgumentException(
                        'Criticité invalide.'
                    );
                }

                $riskId = !empty($_POST['risk_id'])
                    ? (int)$_POST['risk_id']
                    : null;

                $statement = $db->prepare(
                    'INSERT INTO findings
                    (code, mission_id, title, severity, risk_id, description)
                    VALUES(?, ?, ?, ?, ?, ?)'
                );

                $statement->execute([
                    next_code('findings', 'C-'),
                    $missionId,
                    trim((string)$_POST['title']),
                    $severity,
                    $riskId,
                    trim((string)$_POST['description'])
                ]);

                logx('Création constat');

                header('Location: ?page=findings');
                exit;


            /* ---------------- RECOMMANDATION ---------------- */

            case 'new_rec':

                $priority = (string)($_POST['priority'] ?? '');

                if (!in_array(
                    $priority,
                    ['Haute', 'Moyenne', 'Basse'],
                    true
                )) {
                    throw new InvalidArgumentException(
                        'Priorité invalide.'
                    );
                }

                $statement = $db->prepare(
                    'INSERT INTO recommendations
                    (code, finding_id, title, owner, due_date, priority, status)
                    VALUES(?, ?, ?, ?, ?, ?, ?)'
                );

                $statement->execute([
                    next_code('recommendations', 'REC-'),
                    (int)$_POST['finding_id'],
                    trim((string)$_POST['title']),
                    trim((string)$_POST['owner']),
                    (string)$_POST['due_date'],
                    $priority,
                    'À faire'
                ]);

                logx('Création recommandation');

                header('Location: ?page=recommendations');
                exit;


            /* ---------------- AVANCER RECOMMANDATION ---------------- */

            case 'advance':

                $statement = $db->prepare(
                    'SELECT status
                     FROM recommendations
                     WHERE id = ?'
                );

                $statement->execute([
                    (int)$_POST['id']
                ]);

                $recommendation = $statement->fetch();

                if (!$recommendation) {

                    throw new RuntimeException(
                        'Recommandation introuvable.'
                    );
                }

                $nextStatus = [
                    'À faire' => 'En cours',
                    'En cours' => 'Réalisée',
                    'En retard' => 'Réalisée',
                    'Réalisée' => 'Réalisée'
                ];

                $newStatus =
                    $nextStatus[$recommendation['status']]
                    ?? 'En cours';

                $statement = $db->prepare(
                    'UPDATE recommendations
                     SET status = ?
                     WHERE id = ?'
                );

                $statement->execute([
                    $newStatus,
                    (int)$_POST['id']
                ]);

                logx('Mise à jour recommandation');

                header('Location: ?page=recommendations');
                exit;
        }

    } catch (Throwable $exception) {

        $err = $exception->getMessage();
    }
}


/* =========================================================
   LAYOUT
   ========================================================= */

function startPage(string $title): void
{
    global $page, $err;
    ?>

    <!doctype html>
    <html lang="fr">

    <head>

        <meta charset="utf-8">

        <meta
            name="viewport"
            content="width=device-width, initial-scale=1"
        >

        <title>
            <?= e($title) ?> — AuditFlow
        </title>

        <style>

            :root {
                --bg:#f5f7fb;
                --text:#172033;
                --muted:#667085;
                --border:#e5e7eb;
                --blue:#2563eb;
                --side:#101828;
            }

            * {
                box-sizing:border-box;
            }

            body {
                margin:0;
                font:14px system-ui,-apple-system,
                    BlinkMacSystemFont,"Segoe UI",Arial,sans-serif;
                background:var(--bg);
                color:var(--text);
            }

            a {
                text-decoration:none;
            }

            .side {
                position:fixed;
                width:245px;
                inset:0 auto 0 0;
                background:var(--side);
                color:#fff;
                padding:22px 14px;
            }

            .brand {
                display:flex;
                gap:10px;
                align-items:center;
                padding:5px 10px 25px;
            }

            .mark {
                width:38px;
                height:38px;
                border-radius:11px;
                background:#2563eb;
                display:grid;
                place-items:center;
                font-weight:800;
                flex-shrink:0;
            }

            .brand small {
                display:block;
                color:#98a2b3;
                font-size:11px;
                margin-top:2px;
            }

            .nav a {
                display:block;
                color:#cbd5e1;
                padding:11px 12px;
                border-radius:9px;
                margin:4px 0;
            }

            .nav a.active,
            .nav a:hover {
                background:#1e293b;
                color:#fff;
            }

            .main {
                margin-left:245px;
                min-height:100vh;
            }

            .top {
                height:70px;
                background:#fff;
                border-bottom:1px solid var(--border);
                display:flex;
                justify-content:space-between;
                align-items:center;
                padding:0 30px;
            }

            .content {
                padding:28px 30px;
                max-width:1450px;
                margin:auto;
            }

            .head {
                display:flex;
                justify-content:space-between;
                align-items:flex-start;
                margin-bottom:22px;
                gap:15px;
            }

            .head h1 {
                margin:0 0 5px;
                font-size:25px;
            }

            .muted {
                color:var(--muted);
                font-size:12px;
            }

            .grid {
                display:grid;
                gap:16px;
            }

            .stats {
                grid-template-columns:repeat(4,1fr);
            }

            .two {
                grid-template-columns:1.3fr 1fr;
            }

            .card {
                background:#fff;
                border:1px solid var(--border);
                border-radius:14px;
                box-shadow:0 8px 28px #1018280f;
            }

            .stat,
            .panel {
                padding:18px;
            }

            .label {
                color:var(--muted);
                font-size:12px;
            }

            .value {
                font-size:29px;
                font-weight:800;
                margin:7px 0;
            }

            .btn {
                display:inline-block;
                border:1px solid var(--border);
                background:#fff;
                color:var(--text);
                padding:9px 13px;
                border-radius:9px;
                font-weight:700;
                cursor:pointer;
            }

            button.btn {
                font-family:inherit;
            }

            .primary {
                background:var(--blue);
                border-color:var(--blue);
                color:#fff;
            }

            .table-wrap {
                overflow:auto;
            }

            .table {
                width:100%;
                border-collapse:collapse;
                font-size:12px;
            }

            .table th,
            .table td {
                padding:11px;
                border-bottom:1px solid #eef0f4;
                text-align:left;
                vertical-align:top;
            }

            .table th {
                background:#f8fafc;
                color:var(--muted);
                white-space:nowrap;
            }

            .badge {
                display:inline-block;
                padding:4px 8px;
                border-radius:99px;
                font-size:10px;
                font-weight:800;
            }

            .red {
                background:#fee2e2;
                color:#991b1b;
            }

            .orange {
                background:#ffedd5;
                color:#9a3412;
            }

            .blue {
                background:#dbeafe;
                color:#1e40af;
            }

            .green {
                background:#dcfce7;
                color:#166534;
            }

            .gray {
                background:#f2f4f7;
                color:#475467;
            }

            .field {
                margin-bottom:13px;
            }

            .field label {
                display:block;
                font-size:12px;
                font-weight:800;
                margin-bottom:6px;
            }

            .field input,
            .field select,
            .field textarea {
                width:100%;
                padding:10px;
                border:1px solid var(--border);
                border-radius:8px;
                background:#fff;
                font:inherit;
            }

            .field textarea {
                min-height:90px;
                resize:vertical;
            }

            .two-fields {
                display:grid;
                grid-template-columns:1fr 1fr;
                gap:13px;
            }

            .matrix {
                display:grid;
                grid-template-columns:40px repeat(5,1fr);
                grid-template-rows:repeat(6,44px);
                gap:4px;
                margin-top:12px;
            }

            .matrix div {
                display:grid;
                place-items:center;
                border-radius:6px;
                font-size:10px;
                font-weight:800;
            }

            .lab {
                background:#f8fafc;
                color:var(--muted);
            }

            .low {
                background:#dcfce7;
            }

            .medium {
                background:#fef3c7;
            }

            .high {
                background:#fed7aa;
            }

            .critical {
                background:#fecaca;
            }

            .alert {
                padding:10px 12px;
                border-radius:9px;
                margin-bottom:15px;
            }

            .alert-error {
                background:#fee2e2;
                color:#991b1b;
                border:1px solid #fecaca;
            }

            @media(max-width:900px) {

                .stats {
                    grid-template-columns:1fr 1fr;
                }

                .two {
                    grid-template-columns:1fr;
                }

                .side {
                    width:72px;
                }

                .side span,
                .brand div:last-child {
                    display:none;
                }

                .main {
                    margin-left:72px;
                }

                .content {
                    padding:20px 15px;
                }
            }

            @media(max-width:600px) {

                .stats,
                .two-fields {
                    grid-template-columns:1fr;
                }

                .head {
                    flex-direction:column;
                }

                .top {
                    padding:0 15px;
                    font-size:12px;
                }

                .top > span:first-child {
                    display:none;
                }
            }

            @media print {

                .side,
                .top,
                .no-print {
                    display:none !important;
                }

                .main {
                    margin-left:0;
                }

                .content {
                    max-width:none;
                    padding:0;
                }

                .card {
                    box-shadow:none;
                }
            }

        </style>

    </head>

    <body>

        <aside class="side">

            <div class="brand">

                <div class="mark">
                    AI
                </div>

                <div>
                    <b>AuditFlow</b>

                    <small>
                        V3 PHP · Audit interne
                    </small>
                </div>

            </div>

            <nav class="nav">

                <?php

                $navigation = [
                    ['dashboard','▦','Tableau de bord'],
                    ['risks','◈','Risques'],
                    ['missions','◌','Missions'],
                    ['findings','!','Constats'],
                    ['recommendations','✓','Recommandations'],
                    ['reports','▤','Rapports'],
                    ['logs','◫','Journal']
                ];

                foreach ($navigation as $item):

                ?>

                    <a
                        class="<?= $page === $item[0] ? 'active' : '' ?>"
                        href="?page=<?= e($item[0]) ?>"
                    >
                        <?= e($item[1]) ?>
                        <span>
                            <?= e($item[2]) ?>
                        </span>
                    </a>

                <?php endforeach; ?>

                <a href="?logout=1">
                    ↪
                    <span>Déconnexion</span>
                </a>

            </nav>

        </aside>

        <main class="main">

            <header class="top">

                <span class="muted">
                    Gestion de la fonction d’audit interne
                </span>

                <span>
                    <b>
                        <?= e($_SESSION['user']['name'] ?? '') ?>
                    </b>
                    ·
                    <?= e($_SESSION['user']['role'] ?? '') ?>
                </span>

            </header>

            <section class="content">

                <?php if ($err): ?>

                    <div class="alert alert-error">
                        <?= e($err) ?>
                    </div>

                <?php endif; ?>

    <?php
}

function endPage(): void
{
    ?>

            </section>

        </main>

    </body>

    </html>

    <?php
}


/* =========================================================
   PAGE LOGIN
   ========================================================= */

if ($page === 'login'):

?>

<!doctype html>

<html lang="fr">

<head>

    <meta charset="utf-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1"
    >

    <title>AuditFlow — Connexion</title>

    <style>

        body {
            margin:0;
            min-height:100vh;
            background:#eef3ff;
            font:14px system-ui,-apple-system,
                BlinkMacSystemFont,"Segoe UI",Arial,sans-serif;
            display:flex;
            align-items:center;
            justify-content:center;
        }

        .box {
            width:min(400px,90vw);
            background:#fff;
            padding:30px;
            border-radius:16px;
            box-shadow:0 12px 40px #10182818;
        }

        .mark {
            width:48px;
            height:48px;
            background:#2563eb;
            color:#fff;
            display:grid;
            place-items:center;
            border-radius:13px;
            font-weight:800;
        }

        .f {
            margin:14px 0;
        }

        .f label {
            display:block;
            font-weight:700;
            font-size:12px;
            margin-bottom:6px;
        }

        .f input {
            width:100%;
            padding:11px;
            border:1px solid #ddd;
            border-radius:8px;
            box-sizing:border-box;
            font:inherit;
        }

        button {
            padding:11px;
            border:0;
            border-radius:8px;
            background:#2563eb;
            color:#fff;
            font-weight:800;
            width:100%;
            cursor:pointer;
        }

        .err {
            background:#fee2e2;
            color:#991b1b;
            padding:10px;
            border-radius:8px;
        }

    </style>

</head>

<body>

    <div class="box">

        <div class="mark">
            AI
        </div>

        <h1>AuditFlow</h1>

        <p style="color:#667085">
            Gestion de la fonction d’audit interne
        </p>

        <?php if ($err): ?>

            <div class="err">
                <?= e($err) ?>
            </div>

        <?php endif; ?>

        <form method="post">

            <div class="f">

                <label>
                    Identifiant
                </label>

                <input
                    name="username"
                    autocomplete="username"
                    required
                >

            </div>

            <div class="f">

                <label>
                    Mot de passe
                </label>

                <input
                    type="password"
                    name="password"
                    autocomplete="current-password"
                    required
                >

            </div>

            <button
                type="submit"
                name="login"
                value="1"
            >
                Se connecter
            </button>

        </form>

        <p style="font-size:11px;color:#667085">
            Démo :
            admin/admin123 ·
            auditeur/audit123 ·
            manager/manager123
        </p>

    </div>

</body>

</html>

<?php

exit;

endif;


/* =========================================================
   TABLEAU DE BORD
   ========================================================= */

if ($page === 'dashboard'):

    startPage('Tableau de bord');

    $risks = $db->query(
        'SELECT *
         FROM risks
         ORDER BY probability * impact DESC'
    )->fetchAll();

    $missions = $db->query(
        'SELECT *
         FROM missions
         ORDER BY id DESC
         LIMIT 5'
    )->fetchAll();

    $recommendations = $db->query(
        'SELECT *
         FROM recommendations
         ORDER BY id DESC
         LIMIT 5'
    )->fetchAll();

    $critical = 0;

    foreach ($risks as $risk) {

        if (
            lvl(
                (int)$risk['probability'],
                (int)$risk['impact']
            ) === 'Critique'
        ) {
            $critical++;
        }
    }

    $activeMissions = (int)$db->query(
        "SELECT COUNT(*)
         FROM missions
         WHERE status = 'En cours'"
    )->fetchColumn();

    $openRecommendations = (int)$db->query(
        "SELECT COUNT(*)
         FROM recommendations
         WHERE status != 'Réalisée'"
    )->fetchColumn();

?>

<div class="head">

    <div>

        <h1>
            Tableau de bord
        </h1>

        <p class="muted">
            Vue synthétique de la fonction d’audit interne.
        </p>

    </div>

    <a
        class="btn primary"
        href="?page=risks"
    >
        ＋ Nouveau risque
    </a>

</div>

<div class="grid stats">

    <div class="card stat">

        <div class="label">
            Risques identifiés
        </div>

        <div class="value">
            <?= count($risks) ?>
        </div>

    </div>

    <div class="card stat">

        <div class="label">
            Risques critiques
        </div>

        <div class="value">
            <?= $critical ?>
        </div>

    </div>

    <div class="card stat">

        <div class="label">
            Missions en cours
        </div>

        <div class="value">
            <?= $activeMissions ?>
        </div>

    </div>

    <div class="card stat">

        <div class="label">
            Recommandations ouvertes
        </div>

        <div class="value">
            <?= $openRecommendations ?>
        </div>

    </div>

</div>

<div
    class="grid two"
    style="margin-top:16px"
>

    <div class="card panel">

        <h3>
            Cartographie des risques
        </h3>

        <span class="muted">
            Probabilité × impact
        </span>

        <div class="matrix">

            <div></div>

            <?php for ($impact = 1; $impact <= 5; $impact++): ?>

                <div class="lab">
                    <?= $impact ?>
                </div>

            <?php endfor; ?>

            <?php for ($probability = 5; $probability >= 1; $probability--): ?>

                <div class="lab">
                    P<?= $probability ?>
                </div>

                <?php for ($impact = 1; $impact <= 5; $impact++): ?>

                    <?php

                    $count = 0;

                    foreach ($risks as $risk) {

                        if (
                            (int)$risk['probability'] === $probability &&
                            (int)$risk['impact'] === $impact
                        ) {
                            $count++;
                        }
                    }

                    $score = $probability * $impact;

                    $class =
                        $score >= 16
                            ? 'critical'
                            : (
                                $score >= 10
                                    ? 'high'
                                    : (
                                        $score >= 5
                                            ? 'medium'
                                            : 'low'
                                    )
                            );

                    ?>

                    <div class="<?= $class ?>">
                        <?= $count ?: '' ?>
                    </div>

                <?php endfor; ?>

            <?php endfor; ?>

        </div>

    </div>

    <div class="card panel">

        <h3>
            Recommandations récentes
        </h3>

        <?php foreach ($recommendations as $recommendation): ?>

            <p>

                <b>
                    <?= e($recommendation['code']) ?>
                </b>

                —
                <?= e($recommendation['title']) ?>

                <br>

                <span
                    class="badge <?= bc($recommendation['status']) ?>"
                >
                    <?= e($recommendation['status']) ?>
                </span>

            </p>

        <?php endforeach; ?>

    </div>

</div>

<div
    class="card panel"
    style="margin-top:16px"
>

    <h3>
        Dernières missions
    </h3>

    <div class="table-wrap">

        <table class="table">

            <tr>
                <th>ID</th>
                <th>Mission</th>
                <th>Processus</th>
                <th>Statut</th>
            </tr>

            <?php foreach ($missions as $mission): ?>

                <tr>

                    <td>
                        <?= e($mission['code']) ?>
                    </td>

                    <td>
                        <?= e($mission['title']) ?>
                    </td>

                    <td>
                        <?= e($mission['process']) ?>
                    </td>

                    <td>
                        <?= e($mission['status']) ?>
                    </td>

                </tr>

            <?php endforeach; ?>

        </table>

    </div>

</div>

<?php

    endPage();
    exit;

endif;


/* =========================================================
   RISQUES
   ========================================================= */

if ($page === 'risks'):

    startPage('Risques');

    $risks = $db->query(
        'SELECT *
         FROM risks
         ORDER BY probability * impact DESC'
    )->fetchAll();

?>

<div class="head">

    <div>

        <h1>
            Cartographie des risques
        </h1>

        <p class="muted">
            Identifier, évaluer et suivre les risques.
        </p>

    </div>

</div>

<div class="grid two">

    <div class="card panel">

        <h3>
            Ajouter un risque
        </h3>

        <form method="post">

            <input
                type="hidden"
                name="csrf"
                value="<?= e(csrf_token()) ?>"
            >

            <input
                type="hidden"
                name="action"
                value="new_risk"
            >

            <div class="field">

                <label>
                    Intitulé
                </label>

                <input
                    name="title"
                    required
                >

            </div>

            <div class="two-fields">

                <div class="field">

                    <label>
                        Processus
                    </label>

                    <input
                        name="process"
                        required
                    >

                </div>

                <div class="field">

                    <label>
                        Responsable
                    </label>

                    <input
                        name="owner"
                        required
                    >

                </div>

            </div>

            <div class="two-fields">

                <div class="field">

                    <label>
                        Probabilité
                    </label>

                    <select name="probability">

                        <?php for ($i = 1; $i <= 5; $i++): ?>

                            <option value="<?= $i ?>">
                                <?= $i ?>
                            </option>

                        <?php endfor; ?>

                    </select>

                </div>

                <div class="field">

                    <label>
                        Impact
                    </label>

                    <select name="impact">

                        <?php for ($i = 1; $i <= 5; $i++): ?>

                            <option value="<?= $i ?>">
                                <?= $i ?>
                            </option>

                        <?php endfor; ?>

                    </select>

                </div>

            </div>

            <button
                class="btn primary"
                type="submit"
            >
                Enregistrer
            </button>

        </form>

    </div>

    <div class="card panel">

        <h3>
            Risques
        </h3>

        <div class="table-wrap">

            <table class="table">

                <tr>
                    <th>ID</th>
                    <th>Risque</th>
                    <th>Processus</th>
                    <th>Niveau</th>
                    <th>Responsable</th>
                </tr>

                <?php foreach ($risks as $risk): ?>

                    <?php

                    $level = lvl(
                        (int)$risk['probability'],
                        (int)$risk['impact']
                    );

                    ?>

                    <tr>

                        <td>
                            <?= e($risk['code']) ?>
                        </td>

                        <td>
                            <?= e($risk['title']) ?>
                        </td>

                        <td>
                            <?= e($risk['process']) ?>
                        </td>

                        <td>

                            <span
                                class="badge <?= bc($level) ?>"
                            >
                                <?= e($level) ?>
                            </span>

                        </td>

                        <td>
                            <?= e($risk['owner']) ?>
                        </td>

                    </tr>

                <?php endforeach; ?>

            </table>

        </div>

    </div>

</div>

<?php

    endPage();
    exit;

endif;


/* =========================================================
   MISSIONS
   ========================================================= */

if ($page === 'missions'):

    startPage('Missions');

    $missions = $db->query(
        'SELECT
            m.*,
            r.code AS risk_code
         FROM missions m
         LEFT JOIN risks r ON r.id = m.risk_id
         ORDER BY m.id DESC'
    )->fetchAll();

    $risks = $db->query(
        'SELECT id, code, title
         FROM risks
         ORDER BY code'
    )->fetchAll();

?>

<div class="head">

    <div>

        <h1>
            Missions d’audit
        </h1>

        <p class="muted">
            Planifier et suivre les missions.
        </p>

    </div>

</div>

<div class="grid two">

    <div class="card panel">

        <h3>
            Nouvelle mission
        </h3>

        <form method="post">

            <input
                type="hidden"
                name="csrf"
                value="<?= e(csrf_token()) ?>"
            >

            <input
                type="hidden"
                name="action"
                value="new_mission"
            >

            <div class="field">

                <label>
                    Intitulé
                </label>

                <input
                    name="title"
                    required
                >

            </div>

            <div class="two-fields">

                <div class="field">

                    <label>
                        Processus
                    </label>

                    <input
                        name="process"
                        required
                    >

                </div>

                <div class="field">

                    <label>
                        Auditeur
                    </label>

                    <input
                        name="auditor"
                        value="<?= e($_SESSION['user']['name']) ?>"
                        required
                    >

                </div>

            </div>

            <div class="two-fields">

                <div class="field">

                    <label>
                        Début
                    </label>

                    <input
                        type="date"
                        name="start_date"
                        required
                    >

                </div>

                <div class="field">

                    <label>
                        Fin
                    </label>

                    <input
                        type="date"
                        name="end_date"
                        required
                    >

                </div>

            </div>

            <div class="field">

                <label>
                    Risque principal
                </label>

                <select name="risk_id">

                    <option value="">
                        — Aucun —
                    </option>

                    <?php foreach ($risks as $risk): ?>

                        <option
                            value="<?= (int)$risk['id'] ?>"
                        >
                            <?= e(
                                $risk['code'] .
                                ' — ' .
                                $risk['title']
                            ) ?>
                        </option>

                    <?php endforeach; ?>

                </select>

            </div>

            <button
                class="btn primary"
                type="submit"
            >
                Créer
            </button>

        </form>

    </div>

    <div class="card panel">

        <h3>
            Missions
        </h3>

        <div class="table-wrap">

            <table class="table">

                <tr>
                    <th>ID</th>
                    <th>Mission</th>
                    <th>Risque</th>
                    <th>Statut</th>
                </tr>

                <?php foreach ($missions as $mission): ?>

                    <tr>

                        <td>
                            <?= e($mission['code']) ?>
                        </td>

                        <td>
                            <?= e($mission['title']) ?>
                        </td>

                        <td>
                            <?= e(
                                $mission['risk_code'] ?? '—'
                            ) ?>
                        </td>

                        <td>
                            <?= e($mission['status']) ?>
                        </td>

                    </tr>

                <?php endforeach; ?>

            </table>

        </div>

    </div>

</div>

<?php

    endPage();
    exit;

endif;


/* =========================================================
   CONSTATS
   ========================================================= */

if ($page === 'findings'):

    startPage('Constats');

    $findings = $db->query(
        'SELECT
            f.*,
            m.code AS mission_code,
            r.code AS risk_code
         FROM findings f
         JOIN missions m ON m.id = f.mission_id
         LEFT JOIN risks r ON r.id = f.risk_id
         ORDER BY f.id DESC'
    )->fetchAll();

    $missions = $db->query(
        'SELECT id, code, title
         FROM missions
         ORDER BY code'
    )->fetchAll();

    $risks = $db->query(
        'SELECT id, code, title
         FROM risks
         ORDER BY code'
    )->fetchAll();

?>

<div class="head">

    <div>

        <h1>
            Constats d’audit
        </h1>

        <p class="muted">
            Relier les observations aux missions et aux risques.
        </p>

    </div>

</div>

<div class="grid two">

    <div class="card panel">

        <h3>
            Nouveau constat
        </h3>

        <form method="post">

            <input
                type="hidden"
                name="csrf"
                value="<?= e(csrf_token()) ?>"
            >

            <input
                type="hidden"
                name="action"
                value="new_finding"
            >

            <div class="field">

                <label>
                    Mission
                </label>

                <select
                    name="mission_id"
                    required
                >

                    <?php foreach ($missions as $mission): ?>

                        <option
                            value="<?= (int)$mission['id'] ?>"
                        >
                            <?= e(
                                $mission['code'] .
                                ' — ' .
                                $mission['title']
                            ) ?>
                        </option>

                    <?php endforeach; ?>

                </select>

            </div>

            <div class="field">

                <label>
                    Intitulé
                </label>

                <input
                    name="title"
                    required
                >

            </div>

            <div class="two-fields">

                <div class="field">

                    <label>
                        Criticité
                    </label>

                    <select name="severity">

                        <option>
                            Faible
                        </option>

                        <option>
                            Moyenne
                        </option>

                        <option>
                            Élevée
                        </option>

                        <option>
                            Critique
                        </option>

                    </select>

                </div>

                <div class="field">

                    <label>
                        Risque
                    </label>

                    <select name="risk_id">

                        <option value="">
                            — Aucun —
                        </option>

                        <?php foreach ($risks as $risk): ?>

                            <option
                                value="<?= (int)$risk['id'] ?>"
                            >
                                <?= e(
                                    $risk['code'] .
                                    ' — ' .
                                    $risk['title']
                                ) ?>
                            </option>

                        <?php endforeach; ?>

                    </select>

                </div>

            </div>

            <div class="field">

                <label>
                    Description
                </label>

                <textarea
                    name="description"
                    required
                ></textarea>

            </div>

            <button
                class="btn primary"
                type="submit"
            >
                Enregistrer
            </button>

        </form>

    </div>

    <div class="card panel">

        <h3>
            Constats
        </h3>

        <div class="table-wrap">

            <table class="table">

                <tr>
                    <th>ID</th>
                    <th>Mission</th>
                    <th>Constat</th>
                    <th>Criticité</th>
                </tr>

                <?php foreach ($findings as $finding): ?>

                    <tr>

                        <td>
                            <?= e($finding['code']) ?>
                        </td>

                        <td>
                            <?= e($finding['mission_code']) ?>
                        </td>

                        <td>
                            <?= e($finding['title']) ?>
                        </td>

                        <td>

                            <span
                                class="badge <?= bc($finding['severity']) ?>"
                            >
                                <?= e($finding['severity']) ?>
                            </span>

                        </td>

                    </tr>

                <?php endforeach; ?>

            </table>

        </div>

    </div>

</div>

<?php

    endPage();
    exit;

endif;


/* =========================================================
   RECOMMANDATIONS
   ========================================================= */

if ($page === 'recommendations'):

    startPage('Recommandations');

    $recommendations = $db->query(
        'SELECT
            r.*,
            f.code AS finding_code
         FROM recommendations r
         JOIN findings f ON f.id = r.finding_id
         ORDER BY r.id DESC'
    )->fetchAll();

    $findings = $db->query(
        'SELECT id, code, title
         FROM findings
         ORDER BY code'
    )->fetchAll();

?>

<div class="head">

    <div>

        <h1>
            Recommandations
        </h1>

        <p class="muted">
            Suivre les actions correctives jusqu’à leur réalisation.
        </p>

    </div>

</div>

<div class="grid two">

    <div class="card panel">

        <h3>
            Nouvelle recommandation
        </h3>

        <form method="post">

            <input
                type="hidden"
                name="csrf"
                value="<?= e(csrf_token()) ?>"
            >

            <input
                type="hidden"
                name="action"
                value="new_rec"
            >

            <div class="field">

                <label>
                    Constat
                </label>

                <select
                    name="finding_id"
                    required
                >

                    <?php foreach ($findings as $finding): ?>

                        <option
                            value="<?= (int)$finding['id'] ?>"
                        >
                            <?= e(
                                $finding['code'] .
                                ' — ' .
                                $finding['title']
                            ) ?>
                        </option>

                    <?php endforeach; ?>

                </select>

            </div>

            <div class="field">

                <label>
                    Recommandation
                </label>

                <textarea
                    name="title"
                    required
                ></textarea>

            </div>

            <div class="two-fields">

                <div class="field">

                    <label>
                        Responsable
                    </label>

                    <input
                        name="owner"
                        required
                    >

                </div>

                <div class="field">

                    <label>
                        Échéance
                    </label>

                    <input
                        type="date"
                        name="due_date"
                        required
                    >

                </div>

            </div>

            <div class="field">

                <label>
                    Priorité
                </label>

                <select name="priority">

                    <option>
                        Haute
                    </option>

                    <option>
                        Moyenne
                    </option>

                    <option>
                        Basse
                    </option>

                </select>

            </div>

            <button
                class="btn primary"
                type="submit"
            >
                Créer
            </button>

        </form>

    </div>

    <div class="card panel">

        <h3>
            Suivi
        </h3>

        <div class="table-wrap">

            <table class="table">

                <tr>
                    <th>ID</th>
                    <th>Recommandation</th>
                    <th>Échéance</th>
                    <th>Statut</th>
                    <th></th>
                </tr>

                <?php foreach ($recommendations as $recommendation): ?>

                    <tr>

                        <td>
                            <?= e($recommendation['code']) ?>
                        </td>

                        <td>

                            <?= e($recommendation['title']) ?>

                            <br>

                            <span class="muted">
                                <?= e(
                                    $recommendation['finding_code']
                                ) ?>
                            </span>

                        </td>

                        <td>
                            <?= e($recommendation['due_date']) ?>
                        </td>

                        <td>

                            <span
                                class="badge <?= bc($recommendation['status']) ?>"
                            >
                                <?= e($recommendation['status']) ?>
                            </span>

                        </td>

                        <td>

                            <?php if (
                                $recommendation['status'] !== 'Réalisée'
                            ): ?>

                                <form
                                    method="post"
                                    class="no-print"
                                >

                                    <input
                                        type="hidden"
                                        name="csrf"
                                        value="<?= e(csrf_token()) ?>"
                                    >

                                    <input
                                        type="hidden"
                                        name="action"
                                        value="advance"
                                    >

                                    <input
                                        type="hidden"
                                        name="id"
                                        value="<?= (int)$recommendation['id'] ?>"
                                    >

                                    <button
                                        class="btn"
                                        type="submit"
                                    >
                                        Avancer
                                    </button>

                                </form>

                            <?php else: ?>

                                <span class="muted">
                                    Terminé
                                </span>

                            <?php endif; ?>

                        </td>

                    </tr>

                <?php endforeach; ?>

            </table>

        </div>

    </div>

</div>

<?php

    endPage();
    exit;

endif;


/* =========================================================
   RAPPORTS
   ========================================================= */

if ($page === 'reports'):

    startPage('Rapports');

    $risks = $db->query(
        'SELECT * FROM risks'
    )->fetchAll();

    $missions = $db->query(
        'SELECT * FROM missions'
    )->fetchAll();

    $recommendations = $db->query(
        'SELECT * FROM recommendations'
    )->fetchAll();

    $done = count(
        array_filter(
            $recommendations,
            static fn(array $recommendation): bool =>
                $recommendation['status'] === 'Réalisée'
        )
    );

?>

<div class="head">

    <div>

        <h1>
            Rapports & indicateurs
        </h1>

        <p class="muted">
            Vue de synthèse pour la restitution.
        </p>

    </div>

    <button
        class="btn no-print"
        type="button"
        onclick="window.print()"
    >
        Imprimer / PDF
    </button>

</div>

<div class="grid stats">

    <div class="card stat">

        <div class="label">
            Risques
        </div>

        <div class="value">
            <?= count($risks) ?>
        </div>

    </div>

    <div class="card stat">

        <div class="label">
            Missions
        </div>

        <div class="value">
            <?= count($missions) ?>
        </div>

    </div>

    <div class="card stat">

        <div class="label">
            Recommandations
        </div>

        <div class="value">
            <?= count($recommendations) ?>
        </div>

    </div>

    <div class="card stat">

        <div class="label">
            Réalisées
        </div>

        <div class="value">
            <?= $done ?>
        </div>

    </div>

</div>

<div
    class="card panel"
    style="margin-top:16px"
>

    <h3>
        Structure recommandée
    </h3>

    <ol>

        <li>
            Synthèse exécutive
        </li>

        <li>
            Cartographie et évolution des risques
        </li>

        <li>
            Missions réalisées et en cours
        </li>

        <li>
            Principaux constats
        </li>

        <li>
            État des recommandations
        </li>

        <li>
            Plan d’actions prioritaire
        </li>

    </ol>

</div>

<?php

    endPage();
    exit;

endif;


/* =========================================================
   JOURNAL
   ========================================================= */

if ($page === 'logs'):

    startPage('Journal');

    $logs = $db->query(
        'SELECT *
         FROM audit_log
         ORDER BY id DESC
         LIMIT 100'
    )->fetchAll();

?>

<div class="head">

    <div>

        <h1>
            Journal de traçabilité
        </h1>

        <p class="muted">
            Historique des actions.
        </p>

    </div>

</div>

<div class="card panel">

    <div class="table-wrap">

        <table class="table">

            <tr>
                <th>Date</th>
                <th>Utilisateur</th>
                <th>Action</th>
            </tr>

            <?php foreach ($logs as $log): ?>

                <tr>

                    <td>
                        <?= e($log['created_at']) ?>
                    </td>

                    <td>
                        <?= e($log['username']) ?>
                    </td>

                    <td>
                        <?= e($log['action']) ?>
                    </td>

                </tr>

            <?php endforeach; ?>

        </table>

    </div>

</div>

<?php

    endPage();
    exit;

endif;


/* =========================================================
   PAGE PAR DÉFAUT
   ========================================================= */

header('Location: ?page=dashboard');
exit;