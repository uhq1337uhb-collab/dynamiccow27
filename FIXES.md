# DynamicCow 1.2 — Rapport de correctifs (FIXES.md)

## ⚠️ La vérité sur iOS 27 beta 3 (à lire en premier)

DynamicCow repose sur **une seule** faille : **CVE-2022-46689** (« MacDirtyCow »), un bug
du noyau XNU dans `vm_read_overwrite` / `copy_unaligned`. Cette faille a été **corrigée par
Apple le 13 décembre 2022** dans **iOS 16.2** et iOS 15.7.2.

**Sur iOS 27 beta 3, aucun exploit public compatible n'existe.** Trouver « une faille » pour
cette version reviendrait à découvrir un 0-day kernel inédit — ce n'est pas quelque chose
qu'on peut produire en modifiant ce dépôt, et personne ne peut te le garantir. Ce que fait
cette version corrigée :

- elle **détecte ta version d'iOS** au démarrage ;
- si iOS ≥ 16.2 (donc iOS 27 beta 3 aussi) : bannière rouge explicite, bouton **Enable
  verrouillé**, message clair « exploit corrigé par Apple depuis iOS 16.2, rien n'a été
  modifié » — au lieu du comportement d'avant : freeze de plusieurs minutes, puis faux
  message « plist corrupted », voire crash pur et simple ;
- si iOS 16.0 → 16.1.2 : l'application fonctionne comme prévu.

En résumé : **le bug que tu voyais sur iOS 27 beta 3 n'était pas un bug de code de l'app,
c'était l'exploit qui échouait silencieusement** (faille corrigée par Apple) et l'app qui
mal interprétait cet échec. Ça, c'est réglé : l'app dit maintenant la vérité.

> Pour info : DynamicCow officiel supporte iOS 16.0 → 16.1.2 (et DynamicCow UI sur 16.2+ 
> via CoreServices, hors périmètre ici). Si tu veux l'île dynamique sur iOS 27, il faudra
> attendre qu'un chercheur publie un nouvel exploit kernel — surveille les repos du milieu
> (leminlimez, sourcelocation, etc.).

---

## Failles et bugs corrigés dans cette version

### 🔴 Critiques

**1. Faux succès quand `mlock` échoue — `ContentView.swift` / `overwriteFile()`**
```swift
// AVANT : guard mlock(fileMap, replacementData.count) == 0 else { return true }
```
Si `mlock` échouait, la fonction renvoyait `true` (succès) alors que **rien n'avait été
écrit**. L'app passait en état « activé », écrivait `isEnabled = true`, alors que le plist
n'avait jamais changé → île dynamique absente alors que l'app disait qu'elle était active.
C'est exactement le symptôme décrit dans les réglages (« l'app pense que l'île est activée
mais elle est désactivée »). **Corrigé : renvoie `false`, la région mappée est libérée.**

**2. `exit(1)` dans l'exploit — `vm_unaligned_copy_switch_race.c`**
Les macros `T_ASSERT_*` (héritées des tests XNU) appelaient `exit(1)` : si le noyau se
comportait différemment de ce que le code attend (typique d'un iOS récent comme iOS 27
beta 3), **toute l'app mourait instantanément, sans aucun message**. **Corrigé : chaque
assertion fait maintenant un `goto cleanup` et la fonction renvoie `false` gracieusement.**

**3. Crash garanti si le plist est illisible — `ContentView.swift` / `plistChange()`**
```swift
// AVANT : let stringsData = try! Data(contentsOf: ...) / ... as! [String: Any]
```
Moindre problème de lecture (sandbox, plist corrompu, layout MobileGestalt différent) =
**crash de l'app** au lieu de l'alerte prévue à cet effet. **Corrigé : do/catch complet,
résultat passé en completion, plus aucun `try!`/`as!` dans le chemin d'exécution.**

**4. Crash si `tccd` introuvable — `grant_full_disk_access.m`**
Si les deux chemins de `tccd` échouaient à l'`open()` (chemin déplacé par une nouvelle
version d'iOS), le code enchaînait `lseek(-1)` puis `mmap()` de longueur `-1` :
comportement indéfini / crash. **Corrigé : garde `fd == -1` avec erreur propre (code 7).**

**5. Risque de corruption Gestalt au Disable — `ContentView.swift`**
Si `originalDeviceSubType` n'avait jamais été capturé (valeur 0), le bouton Disable
écrivait **0** dans `ArtworkDeviceSubType` — valeur invalide pouvant casser MobileGestalt
(risque de bootloop, mentionné dans le README d'origine). **Corrigé : guard + alerte.**

### 🟠 Bloquants (l'app « buggée » au quotidien)

**6. `isDoing` jamais remis à `false` — `ContentView.swift`**
Après le premier Enable/Disable, le spinner tournait **pour toujours** et toute l'UI restait
désactivée jusqu'au relaunch de l'app. **Corrigé : remis à `false` dans le completion.**

**7. Exploit exécuté sur le thread principal — `ContentView.swift`**
La course kernel tourne jusqu'à **10 s par tranche de 16 Ko** ; sur un noyau non vulnérable,
l'UI gelait des **minutes**. **Corrigé : tout tourne sur une file d'arrière-plan
(`userInitiated`), l'UI reste réactive.**

**8. Probe d'exploit rapide (nouveau) — `ContentView.swift` / `probeExploitAvailable()`**
Avant toute écriture réelle, l'app teste la vulnérabilité sur un fichier jetable dans
`/var/tmp` avec une course de **2 s**. Si ça échoue : message clair « appareil non
vulnérable, rien n'a été écrit » en quelques secondes au lieu d'un freeze + faux message.

**9. Course (race condition) du sous-type — `ContentView.swift` / `getDefaultSubtype()`**
Le fetch réseau de `DefaultSubTypes.json` (GitHub) écrivait `deviceSubType` **après** le
retour de la fonction : hors-ligne → 0 → fausse alerte ; et le fallback plist faisait
`as! Int` (crash si la clé manque). **Corrigé : plus de dépendance réseau — le JSON est
embarqué dans le bundle (voir n°12) et le plist est parsé sans force unwrap.**

**10. État UI / état réel désynchronisés — `ContentView.swift`**
`isEnabled` et `currentSet` étaient écrits **avant** de savoir si l'écriture avait réussi.
**Corrigé : l'état n'est engagé qu'après un vrai succès.**

**11. Clé `ArtworkDeviceSubType` absente = faux succès — `ContentView.swift`**
`changeValue()` récursif ne remontait pas si la clé existait : l'app réécrivait une copie
identique du plist et déclarait succès. **Corrigé : `foundKey` suivi ; sinon alerte
« clé introuvable, iOS non compatible, rien n'a été écrit ».**

### 🟡 Robustesse / propreté

**12. `DefaultSubTypes.json` embarqué invalide** — le fichier était du JSON mal formé
(tableau avec paires `clé: valeur` au lieu d'un objet) : impossible à parser, d'où le
recours au réseau. **Corrigé : JSON valide, déplacé dans `DynamicCow/` et ajouté aux
ressources du projet (`project.pbxproj`).**

**13. `Info.plist` vide** — le commentaire de `grant_full_disk_access.m` exige
`NSAppleMusicUsageDescription` (preflight TCC) : il était absent, le plist était un dict
vide. **Corrigé : clé ajoutée + `CFBundleDisplayName` + `UILaunchScreen`.**

**14. Force unwraps divers** — `respring()` (`first!.windows.first!`) dans `ContentView` et
`SettingsView`, et `Bundle.main.infoDictionary!["CFBundleShortVersionString"]!` :
crashs potentiels. **Corrigé : `guard let` avec repli sur `respringBackboard()`, et
`?? "1.2"`.**

**15. Fuites mémoire dans l'exploit** — mapping du fichier, sémaphore dispatch, mutex,
`e5` et handles `mach_make_memory_entry_64` fuyaient sur les sorties anticipées
(« no diff? », assertions). **Corrigé : chemin `cleanup:` unique et sûr, avec suivi de
l'état (mutex initialisé, lock détenu, thread démarré).**

**16. Nouveau paramètre `duration_seconds`** — `unaligned_copy_switch_race()` accepte
maintenant une durée de course par tranche (10 s en réel, 2 s pour la probe).

**17. Réglages** — ajout de la ligne « iOS version » pour vérifier d'un coup d'œil ce que
l'app a détecté ; `MARKETING_VERSION` passé à 1.2.

---

## Ce qui n'a PAS changé

- Le mécanisme d'exploitation lui-même (CVE-2022-46689) : c'est la seule faille connue
  publiquement compatible avec cette technique ; elle reste **patchée depuis iOS 16.2**.
- Les chemins Gestalt (`oPeik/9e8lQWMszEjbPzng` → `ArtworkDeviceSubType`), le fix barre
  rouge (iPhone XR / 11), les valeurs 2556 / 2796, le comportement « Restore plist ».

## Compiler

1. Ouvrir `DynamicCow.xcodeproj` dans Xcode (14+) sur macOS.
2. Signing & Capabilities → mettre ton équipe / ton Apple ID (signing automatique).
3. Build sur l'appareil cible (iOS **16.0 – 16.1.2** pour que l'exploit fonctionne).
4. Sur iOS ≥ 16.2, l'app s'installe et se lance, mais le bouton Enable restera verrouillé
   avec le message d'explication — c'est le comportement voulu.

## Tests rapides à faire après installation

| Test | Résultat attendu |
|---|---|
| Lancer l'app sur iOS 27 beta 3 | Bannière rouge + Enable verrouillé, aucun crash |
| Lancer l'app sur iOS 16.1.2, Enable | Probe OK → écriture → respring → île dynamique |
| Avion + Enable sur 16.1.2 ( appareil non listé ) | Fallback JSON embarqué, pas d'attente réseau |
| Enable sur un appareil non vulnérable | Alert « Exploit unavailable » en ~2 s, UI non gelée |
| Disable | Retour au sous-type d'origine, pas d'écriture de 0 |

---
*DynamicCow original : ethernal (zeph) — crédits complets dans le README d'origine.*
*Correctifs 1.2 : audit statique du code source fourni (DynamicCow-1.1).*
