# Rollenmodell: Bootstrap-Phase und Normalbetrieb

## Zweck

Dieses Dokument trennt zwei Betriebsmodi des Phantom-Coin Netzwerks sauber:

- `Bootstrap-Phase`: einmalige Startausnahme fuer das allererste Netz
- `Normalbetrieb`: dauerhaftes Zielmodell mit strikt getrennten Rollen

Die Bootstrap-Phase ist kein Widerspruch zum spaeteren Rollenmodell, sondern die definierte Ausnahme, damit das Netzwerk ueberhaupt aus dem Nullzustand heraus entstehen kann.

## Rollen

Phantom-Coin kennt drei fachliche Rollen:

1. `Miner`
2. `Validator`
3. `Fullnode`

### Miner

- suchen gueltige Mint-/Block-Loesungen, um neue Coins zu verdienen
- reichen Mint-Ergebnisse in das Netzwerk ein
- finalisieren nicht selbst die Kette

### Validator

- validieren Payloads, Header, Evidences und Mint-Events
- finalisieren Transaktionen und Mint-Events in der Graphkette
- muessen im Normalbetrieb on-chain gestakt sein

### Fullnode

- verifizieren Netzwerkdaten lokal
- pruefen Validatoren und Miner durch unabhaengige Verifikation
- nehmen ohne Validator-Rolle nicht an der Finalisierung teil

## 1. Bootstrap-Phase

### 1.1 Ziel

Die Bootstrap-Phase loest das Startproblem eines leeren Netzwerks:

- es gibt anfangs keine bereits existierenden Coins
- ohne Coins kann kein regulaerer Stake hinterlegt werden
- ohne Validator kann ein Minergebnis nicht finalisiert werden
- ohne finalisierte Minergebnisse entstehen keine Coins fuer den ersten Stake

Daraus folgt: Das Netzwerk braucht fuer den initialen Start genau eine definierte Ausnahme.

### 1.2 Bootstrap-Node

In der Bootstrap-Phase DARF genau ein `Genesis-/Bootstrap-Node` gleichzeitig alle drei Rollen in sich vereinen:

- `Miner`
- `Validator`
- `Fullnode`

Diese Ausnahme ist zulaessig, solange das Netzwerk sich noch im Nullzustand befindet und ohne diese Mehrfachrolle nicht lauffaehig waere.

### 1.3 Eigenschaften der Ausnahme

Der Bootstrap-Node MUSS als Sonderfall verstanden werden und darf nicht als regulaeres Rollenmodell interpretiert werden.

Normative Regeln:

- Es DARF genau einen Bootstrap-Node geben.
- Die Mehrfachrolle gilt nur fuer die initiale Netzentstehung.
- Die Ausnahme ist an die Genesis-/Bootstrap-Identitaet gebunden.
- Weitere Nodes DUERFEN diese Ausnahme nicht parallel beanspruchen.
- Die Ausnahme dient ausschliesslich dazu, initiale Coins zu minen, zu finalisieren und den ersten regulaeren Stake zu ermoeglichen.

### 1.4 Aufgaben des Bootstrap-Node

Der Bootstrap-Node MUSS in der Lage sein:

- initiale Mint-/Mining-Ergebnisse zu erzeugen
- diese Ergebnisse selbst als Validator zu validieren und zu finalisieren
- den Zustand der Kette als Fullnode lokal zu verifizieren
- den ersten on-chain ueberfuehrbaren Stake zu erzeugen

### 1.5 Bootstrap-Validator als Sonderfall

In der Bootstrap-Phase DARF die Validator-Eignung aus der Genesis-/Bootstrap-Definition abgeleitet werden, auch wenn noch kein regulaerer Stake vorhanden ist.

Diese Ausnahme gilt nur fuer die Bootstrap-Phase. Sie ersetzt nicht die spaetere Pflicht zu on-chain Stake im Normalbetrieb.

### 1.6 Ende der Bootstrap-Phase

Die Bootstrap-Phase MUSS beendet werden, sobald das Netzwerk ohne Mehrfachrolle lebensfaehig ist.

Dazu muessen mindestens die folgenden Bedingungen erfuellt sein:

1. Es existiert finalisierte Coin-Supply aus dem Bootstrap-Mining.
2. Es existiert mindestens ein regulaer nutzbarer on-chain Stake.
3. Es existiert mindestens eine regulaere Validator-Identitaet mit Validator-Record und ausreichendem Stake.
4. Das Netzwerk kann Mining, Validierung und Fullnode-Verifikation ohne Bootstrap-Ausnahme weiterbetreiben.

## 2. Uebergangsphase

Zwischen Bootstrap-Phase und Normalbetrieb gibt es eine kurze Migrationsphase.

Diese Migrationsphase MUSS mindestens folgende Schritte enthalten:

1. Mining-Ertraege werden finalisiert und in spend-/bondbare Coins ueberfuehrt.
2. Ein regulaerer Validator wird on-chain registriert.
3. Der erforderliche Mindeststake wird gebondet.
4. Ein dedizierter Validator-Node wird mit eigener Validator-Identitaet gestartet.
5. Mining wird auf eine dedizierte Miner-Instanz verschoben.
6. Fullnodes werden ohne Mining- und ohne Validator-Funktion betrieben.
7. Die Bootstrap-Mehrfachrolle wird deaktiviert.

## 3. Normalbetrieb

Im Normalbetrieb gilt strikte Rollentrennung.

### 3.1 Allgemeine Exklusivitaet

Normative Regeln:

- Ein Miner DARF NICHT gleichzeitig Validator sein.
- Ein Miner DARF NICHT gleichzeitig Fullnode im fachlichen Sinn der Betriebsrolle sein.
- Ein Validator DARF NICHT gleichzeitig Miner sein.
- Ein Validator DARF NICHT gleichzeitig Fullnode-only sein.
- Ein Fullnode DARF NICHT gleichzeitig Miner sein.
- Ein Fullnode DARF NICHT gleichzeitig Validator sein.

Die einzige Ausnahme von diesen Regeln ist der explizite Bootstrap-Node waehrend der Bootstrap-Phase.

### 3.2 Miner im Normalbetrieb

Miner im Normalbetrieb:

- MUESSEN auf Mining begrenzt sein
- DUERFEN keine Validator-Finalisierung ausfuehren
- DUERFEN nicht mit einer Validator-Identitaet betrieben werden
- SOLLTEN als dedizierter `phantom-miner` Worker oder gleichwertig getrennte Miner-Instanz laufen

### 3.3 Validatoren im Normalbetrieb

Validatoren im Normalbetrieb:

- MUESSEN einen gueltigen on-chain Validator-Record besitzen
- MUESSEN ausreichenden on-chain Stake halten
- MUESSEN Payloads/Header finalisieren
- DUERFEN nicht minen
- MUESSEN bei Aufgabe der Rolle zuerst entstaken bzw. die Validator-Rolle beenden, bevor sie wieder als reine Fullnode betrieben werden

### 3.4 Fullnodes im Normalbetrieb

Fullnodes im Normalbetrieb:

- MUESSEN Header, Payloads, Signaturen, Finality und Mint-PoW lokal verifizieren
- DUERFEN nicht finalisieren
- DUERFEN nicht minen
- KOENNEN spaeter Validator werden, aber erst nach Stake, Validator-Record und klarer Rollenumschaltung

## 4. Wer kontrolliert wen

Im Zielmodell gilt folgende Kontrollbeziehung:

### Validatoren kontrollieren Miner

Validatoren kontrollieren Miner durch:

- Pruefung der Mint-Gueltigkeit
- Pruefung der PoW-Bedingungen
- Pruefung der Role-Policy fuer Miner
- Finalisierung oder Ablehnung der von Minern eingebrachten Ergebnisse

### Fullnodes kontrollieren Validatoren

Fullnodes kontrollieren Validatoren durch:

- Verifikation von Headern
- Verifikation aggregierter Signaturen
- Verifikation von Payload-Anwendung und State-Transition
- Verifikation von Slashing-Evidences und Inkonsistenzen

### Fullnodes kontrollieren indirekt auch Miner

Fullnodes kontrollieren Miner ebenfalls indirekt, weil sie:

- Mint-PoW verifizieren
- Payloads und enthaltene Mint-Events pruefen
- ungueltige Daten verwerfen
- Evidences weiterverbreiten koennen

## 5. Identitaet und Policy

Im Normalbetrieb MUSS die Rollenexklusivitaet auch auf Identitaetsebene gelten.

Das bedeutet:

- Miner-Identitaeten und Validator-Identitaeten duerfen sich nicht ueberlappen.
- Eine `role_policy.json` MUSS Ueberlappungen zwischen `mint_locks` und `validator_ids` verbieten.
- Fullnode ist die Default-Rolle, wenn weder Miner- noch Validator-Rolle aktiv ist.

Die Bootstrap-Ausnahme hebelt diese Policy nicht allgemein aus, sondern nur einmalig und nur fuer den Genesis-/Bootstrap-Node.

## 6. Beobachtbarkeit

Der Bootstrap-Sonderfall MUSS operativ klar sichtbar sein.

Anforderungen:

- Ein Node im Bootstrap-Modus MUSS explizit als solcher erkennbar sein.
- Mehrfachrollen duerfen nicht stillschweigend als normale Einzelrolle dargestellt werden.
- Observability und Logs MUESSEN zwischen `Bootstrap-Ausnahme` und `Normalbetrieb` unterscheiden.

Insbesondere ist eine einzelne Rollenmetrik mit nur einem Wert fuer den Bootstrap-Fall fachlich nicht ausreichend, weil sie die gleichzeitige Mehrfachrolle verdecken kann.

## 7. Zusammenfassung

Das fachliche Zielmodell von Phantom-Coin ist eine strikte Rollentrennung.

Der Bootstrap-Node ist die definierte einmalige Startausnahme:

- nicht das Zielmodell
- nicht der Regelbetrieb
- nicht fuer mehrere Nodes
- nur fuer die Netzinitialisierung

Sobald regulaere Coins, regulaerer Stake und regulaere Validatoren existieren, MUSS das Netzwerk in den Normalbetrieb mit getrennten Rollen uebergehen.
