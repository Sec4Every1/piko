# Advisory locali: formato e uso

In **Permessi app → Vulnerabilità e fine supporto** importa un file JSON UTF-8,
poi associa manualmente una voce dell'inventario al prodotto del feed e alla
versione esatta che hai verificato. Nome, editore e versione dell'installer sono
dichiarazioni: piko non indovina un CPE/CVE dal nome. Quando questi metadati
cambiano, sospende il confronto fino a una nuova associazione.

Il feed deve essere preparato da dati del fornitore o da un curatore che conosce
prodotto e versioni interessate. Non importa direttamente NVD, OSV o CSAF; non
scarica né carica dati. L'importazione sostituisce atomicamente il feed locale,
preservando il precedente se la validazione fallisce. Non è necessario un feed
per aprire piko; non viene installato alcun esempio nel prodotto.

## Schema v1

Ogni campo indicato è obbligatorio; proprietà sconosciute o duplicate falliscono.
Tutti gli istanti sono secondi Unix UTC. `schema_version` deve essere `1`.

| Campo del feed | Contratto |
|---|---|
| `source_name`, `source_url` | Nome del curatore (120 byte) e fonte HTTPS (2048 byte) |
| `generated_at`, `expires_at` | Generazione non oltre 5 minuti nel futuro; scadenza successiva, entro 90 giorni dalla generazione |
| `products` | 1–256 prodotti: `product_id`, `display_name`, `covered_versions` |
| `advisories` | 0–1000 record del tipo descritto sotto |

`product_id` è un identificatore scelto dal curatore (massimo 120 byte ASCII,
lettere, cifre, `-_.:`), per esempio `vendor:product`. Non certifica l'identità.
`covered_versions` contiene 1–100 stringhe esatte uniche per prodotto, massimo
80 byte ASCII, lettere, cifre, `-_.+`. Non sono intervalli e non vengono applicate
regole semver. `1.0` e `1.0.0` restano versioni diverse. Specificare esplicitamente
solo le versioni realmente esaminate, senza suggerire una copertura generale.

| Campo advisory | Contratto |
|---|---|
| `id`, `product_id` | Identificatori; ID advisory unico nell'intero feed, prodotto dichiarato in `products` |
| `affected_versions` | 1–100 versioni esatte uniche, tutte incluse nella copertura del prodotto |
| `kind` | `vulnerability` oppure `end_of_support` |
| `title`, `summary` | Testo rispettivamente entro 160 e 1000 byte |
| `cvss_x100`, `cvss_version`, `cvss_vector` | Tutti `null` se sconosciuti; altrimenti punteggio 0–1000 a passi di 10, versione `3.0`/`3.1`/`4.0`, vettore della fonte entro 512 byte. Per fine supporto tutti `null` |
| `source_url`, `published_at` | URL HTTPS della fonte e data pubblicazione non successiva alla generazione |
| `remediation` | 1–8 indicazioni manuali, ciascuna entro 512 byte |

Il controllo CVSS verifica presenza coerente, prefisso/versione e sintassi dei
token. Non ricalcola il punteggio né certifica la correttezza del vettore. Piko
visualizza punteggio, versione e vettore dichiarati dalla fonte; non sono una
probabilità di sfruttamento o un rischio personalizzato del PC. CVSS appartiene
a FIRST ed è usato con permesso. [Specifiche FIRST](https://www.first.org/cvss/).

Gli URL ammettono soltanto HTTPS con hostname DNS ASCII; credenziali, IP,
porte esplicite, frammenti, percent-encoding e caratteri ambigui sono rifiutati.
Sono mostrati come testo per consultarli personalmente: l'importazione non li
apre né li contatta. Non inserire comandi nelle indicazioni di remediation.

## Interpretazione e conservazione

Un avviso significa che il feed dichiara interessata la versione associata,
non che piko abbia verificato il binario o rilevato un exploit. Un prodotto o
una versione non coperti sono dichiarati esplicitamente. **Nessun avviso nel
feed non prova l'assenza di vulnerabilità.** Feed scaduti conservano gli avvisi
con un avvertimento; non suggeriscono dati aggiornati.

Il feed è importato dall'utente: **autenticità e firma non sono verificate**.
SHA-256 rileva incoerenze rispetto al digest della copia locale, ma non protegge
da chi può modificare insieme archivio e digest. Il database per utente si trova
in `%LOCALAPPDATA%\local.piko.desktop\advisories.sqlite`, con limite 16 MiB,
rollback journal e massimo 512 associazioni. Percorsi reparse e archivi anomali
falliscono. I dati restano sul PC; nessuna patch, installazione o blocco è
applicato da questa sezione. Le mitigazioni rete e sandbox richiedono le loro
azioni separate in piko.

Un esempio esclusivamente di sviluppo è nel repository in
`apps/desktop-ui/tests/fixtures/advisory-feed.example.json`; usa identificatori
`TEST-*` e un dominio di esempio, è intenzionalmente scaduto e non costituisce
informazione di sicurezza su software reale. Non è incluso nel pacchetto.
