# LAN-Dateitausch für Windows

Dateien und Ordner direkt zwischen Windows-PCs im selben Heimnetz übertragen. Laufende LAN-Dateitausch-Apps erkennen einander automatisch. Zum Verbinden eine Anfrage senden und am anderen PC **Annehmen** anklicken. Eine Codeeingabe oder ein Codevergleich ist nicht erforderlich. Dateiübertragungen verwenden TLS 1.3; angenommene Geräte werden anschließend über ihre gespeicherten Zertifikate geprüft. Jede neue Sendung braucht eine Empfangsbestätigung.

**Installation auf dem anderen PC:** PowerShell öffnen und diesen Befehl einfügen:

```powershell
& ([scriptblock]::Create((Invoke-RestMethod 'https://raw.githubusercontent.com/Jebroa774/LAN-Dateitausch/main/install.ps1')))
```

Der Befehl lädt den Einzelinstaller aus dem GitHub-Release, prüft die fest hinterlegte SHA-256-Prüfsumme und alle Paketdateien, installiert ausschließlich LAN-Dateitausch für das aktuelle Benutzerkonto und öffnet die App. Die Node-Laufzeit ist enthalten. Benötigt werden ein Windows-PC mit 64-Bit-Unterstützung, Microsoft Edge und .NET Framework 4.8 oder neuer. Ein Administratorkonto ist für die Appinstallation nicht nötig.

Alternativ das [ZIP aus dem Release herunterladen](https://github.com/Jebroa774/LAN-Dateitausch/releases/latest), vollständig entpacken, PowerShell im entpackten Ordner öffnen und ausführen:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\Installieren.ps1' -LaunchApp transfer
```

LAN-Dateitausch auf beiden PCs aktualisieren und öffnen, beim anderen Gerät **Verbinden** anklicken und dort die Anfrage **Annehmen**. Der Sender braucht keine zweite Bestätigung. Dateien bewusst auswählen; auf dem Empfänger die neue Sendung annehmen. Bei einer Windows-Firewall-Abfrage den Zugriff im privaten Netzwerk erlauben. Gastnetze, WLAN-Isolation und getrennte VLANs können die automatische Erkennung verhindern. Die App verändert keine Firewallregeln.

Beim ersten Annehmen wird dem angefragten Gerät vertraut. Ohne unabhängigen Vergleich ist diese erste Zuordnung nicht gegen aktive Nachahmung eines Gerätenamens abgesichert; gespeicherte Schlüsselwechsel bleiben danach gesperrt. Dieses Prinzip des Vertrauens beim ersten Kontakt und seine Grenzen sind in [RFC 4251, Abschnitt 9.3.4](https://www.rfc-editor.org/rfc/rfc4251.html#section-9.3.4) beschrieben. Eine Namensanzeige ist kein unabhängig geprüfter Identitätsnachweis.

Mit **Version 1.3.0** kann die Prototypen-Werkbank ab Version 1.10.0 ausgewählte Projektdokumentation mit einem gekoppelten PC abgleichen. Die Freigabe wird auf beiden PCs in der Werkbank unter **Daten & Sicherung → Projektsynchronisierung** eingerichtet. Dateiübertragungen brauchen weiterhin eine Empfangsbestätigung.

Dieses Repository verteilt den Einzelinstaller und den geprüften Download-Bootstrap. Geräteidentitäten und private Schlüssel entstehen erst auf dem jeweiligen PC; Einstellungen und Empfangsdateien bleiben dort lokal. Das ZIP enthält die Node-Laufzeit samt Lizenzhinweisen unter `runtime/node-LICENSE.txt`.
