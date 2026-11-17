# LAN-Dateitausch für Windows

Dateien und Ordner direkt zwischen Windows-PCs im selben Heimnetz übertragen. Laufende LAN-Dateitausch-Apps erkennen einander automatisch. Dateiübertragungen verwenden TLS 1.3; beim ersten Verbinden wird auf beiden PCs ein Sicherheitscode verglichen und bestätigt. Gekoppelte Geräte werden anschließend über ihre gespeicherten Zertifikate geprüft. Jede neue Sendung braucht eine Empfangsbestätigung.

**Installation auf dem anderen PC:** PowerShell öffnen und diesen Befehl einfügen:

```powershell
& ([scriptblock]::Create((Invoke-RestMethod 'https://raw.githubusercontent.com/Jebroa774/LAN-Dateitausch/main/install.ps1')))
```

Der Befehl lädt den Einzelinstaller aus dem GitHub-Release, prüft die fest hinterlegte SHA-256-Prüfsumme und alle Paketdateien, installiert ausschließlich LAN-Dateitausch für das aktuelle Benutzerkonto und öffnet die App. Die Node-Laufzeit ist enthalten. Benötigt werden ein Windows-PC mit 64-Bit-Unterstützung, Microsoft Edge und .NET Framework 4.8 oder neuer. Ein Administratorkonto ist für die Appinstallation nicht nötig.

Alternativ das [ZIP aus dem Release herunterladen](https://github.com/Jebroa774/LAN-Dateitausch/releases/latest), vollständig entpacken, PowerShell im entpackten Ordner öffnen und ausführen:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\Installieren.ps1' -LaunchApp transfer
```

Danach LAN-Dateitausch auf beiden PCs öffnen, das andere Gerät koppeln und den identischen Sicherheitscode auf beiden Seiten bestätigen. Dateien bewusst auswählen; auf dem Empfänger die neue Sendung annehmen. Bei einer Windows-Firewall-Abfrage den Zugriff im privaten Netzwerk erlauben. Gastnetze, WLAN-Isolation und getrennte VLANs können die automatische Erkennung verhindern. Die App verändert keine Firewallregeln.

Version **1.1.0** wurde mit 109 Tests sowie mit zwei lokalen App-Instanzen einschließlich tatsächlichem TLS-Verkehr und unabhängig geprüften Datei-Prüfsummen getestet. Ein automatischer Online-Updater ist in dieser Version nicht enthalten.

Dieses Repository verteilt den Einzelinstaller und den geprüften Download-Bootstrap. Geräteidentitäten und private Schlüssel entstehen erst auf dem jeweiligen PC; Einstellungen und Empfangsdateien bleiben dort lokal. Das ZIP enthält die Node-Laufzeit samt Lizenzhinweisen unter `runtime/node-LICENSE.txt`.
