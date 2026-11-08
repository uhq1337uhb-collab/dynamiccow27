//
//  ContentView.swift
//  DynamicCow
//
//  Created by ethernal on 08/01/23.
//  Fixed build 1.2 — see FIXES.md at the root of the project.
//
//  Fixes in this file:
//   1. overwriteFile(): mlock failure returned `true` (fake success) -> now `false`.
//   2. overwriteFile(): mapped region is now unmapped (was leaked).
//   3. plistChange(): `try!`/`as!` chain crashed the app on any read error
//      -> proper do/catch, completion-based, runs off the main thread.
//   4. plistChange(): if "ArtworkDeviceSubType" was not found in the plist,
//      an unchanged copy was written and reported as success -> key now tracked.
//   5. isDoing was never reset -> the UI stayed stuck on the spinner after the
//      first Enable/Disable until relaunch. Now reset in the completion.
//   6. isEnabled/currentSet were written BEFORE knowing if the write succeeded
//      -> app state could desync from the device ("island enabled but not shown").
//      State is now only committed after a real success.
//   7. The exploit ran on the main thread (UI frozen for up to minutes on
//      patched kernels) -> everything runs on a background queue.
//   8. Disable with originalDeviceSubType == 0 would write 0 into MobileGestalt
//      (gestalt corruption / bootloop risk) -> guarded.
//   9. iOS version gate: CVE-2022-46689 is patched since iOS 16.2 (Dec 2022).
//      On iOS >= 16.2 (incl. iOS 27 beta) the app now explains the truth and
//      locks Enable instead of freezing then lying with "plist corrupted".
//  10. Exploit probe: a 2-second capability probe on a scratch file runs before
//      any real write, so patched devices fail fast with a clear message.
//  11. getDefaultSubtype(): async GitHub fetch raced with the function return
//      and force-unwrapped plist values (crash) -> bundled valid JSON fallback
//      + safe plist parsing.
//  12. respring(): force-unwrapped scene/window -> safe fallback.
//

import SwiftUI

// MARK: - iOS support gate

enum IOSSupportStatus: Equatable {
    case checking
    case supported            // 16.0 – 16.1.2
    case tooNew(version: String)  // >= 16.2 : MacDirtyCow (CVE-2022-46689) is patched
    case tooOld(version: String)  // < 16.0  : never supported, bootloop risk

    var isSupported: Bool { self == .supported }
}

func detectIOSSupportStatus() -> IOSSupportStatus {
    let version = UIDevice.current.systemVersion
    let parts = version.split(separator: ".").compactMap { Int($0) }
    let major = parts.first ?? 0
    let minor = parts.count > 1 ? parts[1] : 0
    // CVE-2022-46689 was patched by Apple in iOS 16.2 / iPadOS 16.2 (13 Dec 2022).
    if major > 16 || (major == 16 && minor >= 2) {
        return .tooNew(version: version)
    }
    if major < 16 {
        return .tooOld(version: version)
    }
    return .supported
}

// MARK: - plist change result

enum PlistChangeResult {
    case success
    case readError(String)
    case keyNotFound
    case overwriteFailed
}

struct ContentView: View {
    
    @AppStorage(DynamicKeys.isEnabled.rawValue) private var isEnabled: Bool = false
    @AppStorage(DynamicKeys.currentSet.rawValue) private var currentSet: Int = 0
    @AppStorage(DynamicKeys.originalDeviceSubType.rawValue) private var originalDeviceSubType: Int = 0
    
    
    @State private var isDoing: Bool = false
    
    private let dynamicPath = "/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches/com.apple.MobileGestalt.plist"
    
    @State private var deviceSize: Int = 0
    
    @State var checkedPro: Bool = false
    @State var checkedProMax: Bool = false
    
    @State var tappedOnSettings: Bool = false
    
    @State var shouldAlertDeviceSubTypeError: Bool = false
    @State var shouldAlertPlistCorrupted: Bool = false
    @State var shouldAlertKeyNotFound: Bool = false
    @State var shouldAlertNotVulnerable: Bool = false
    
    @State var shouldRedBarFix: Bool = false
    
    @State var iosSupport: IOSSupportStatus = .checking
    
    var body: some View {
        NavigationStack{
            VStack{
   
                AppearanceCellView(checkedPro: $checkedPro, checkedProMax: $checkedProMax)
                    .disabled(isEnabled)
                    .disabled(isDoing)
                    .opacity(isEnabled ? 0.8 : 1)
                    .opacity(isDoing ? 0.8 : 1)
                
                supportBanner

                Spacer()
                
                Button {
                    let impact = UIImpactFeedbackGenerator(style: .medium)
                    impact.impactOccurred()
                    
                    guard !isDoing else { return }
                    
                    if isEnabled{
                        // disable — FIX 8: never write 0 into ArtworkDeviceSubType
                        guard originalDeviceSubType != 0 else {
                            shouldAlertDeviceSubTypeError = true
                            return
                        }
                        isDoing = true
                        plistChange(plistPath: dynamicPath, key: "ArtworkDeviceSubType", value: originalDeviceSubType) { result in
                            handlePlistResult(result, targetSubtype: originalDeviceSubType, enable: false)
                        }
                    }else{
                        // enable — FIX 9: refuse cleanly on unsupported iOS versions
                        guard iosSupport.isSupported else {
                            UIApplication.shared.alert(title: "Unsupported iOS version", body: unsupportedMessage)
                            return
                        }
                        guard checkedPro || checkedProMax else { return }
                        
                        let targetSubtype = checkedProMax ? 2796 : 2556
                        isDoing = true
                        
                        // FIX 10: 2-second probe on a scratch file first, so a patched
                        // kernel fails in seconds with a clear message instead of
                        // freezing the UI for minutes on the real plist.
                        probeExploitAvailable { vulnerable in
                            guard vulnerable else {
                                isDoing = false
                                shouldAlertNotVulnerable = true
                                return
                            }
                            plistChange(plistPath: dynamicPath, key: "ArtworkDeviceSubType", value: targetSubtype) { result in
                                handlePlistResult(result, targetSubtype: targetSubtype, enable: true)
                            }
                        }
                    }
                } label: {
                    RoundedRectangle(cornerRadius: 15)
                        .frame(height: 54)
                        .foregroundColor(.white.opacity(0.9))
                        .overlay {
                            if !isDoing{
                                Text(isEnabled ? "Disable" : "Enable")
                                    .foregroundColor(.black)
                                    .bold()
                            }else{
                                ProgressView()
                                    .tint(.black)
                            }
                        }
                }
                .padding()
                // FIX 9: Enable is locked while the version gate reports unsupported
                .disabled(!iosSupport.isSupported ? true : (checkedPro || checkedProMax ? false : true))
                .disabled(isDoing)
                .opacity(iosSupport.isSupported && (checkedPro || checkedProMax) ? 1 : 0.8)
                .opacity(isDoing ? 0.8 : 1)

                
            }
            .padding()
            .onAppear{
                if currentSet == 2556{
                    withAnimation{
                        checkedPro = true
                    }
                }else if currentSet == 2796{
                    withAnimation{
                        checkedProMax = true
                    }
                }
            }
            
            .navigationTitle("DynamicCow")
            .toolbar {
            
                NavigationLink {
                    SettingsView()
                } label: {
                    Image(systemName: "gear")
                        .foregroundColor(.white)
                }
                .disabled(isDoing)
                .opacity(isDoing ? 0.8 : 1)
            
                if !isDoing {
                    Image(systemName: isEnabled ? "checkmark.circle.fill" : "xmark.circle.fill")
                        .symbolRenderingMode(.hierarchical)
                        .foregroundColor(isEnabled ? .green : .red)
                        .font(.title2)
                        .animation(.spring(), value: isEnabled)
                }else{
                    ProgressView()
                        .tint(.white)
                }
                    
                
            }
        }.tint(.white)
            .onAppear{
                // FIX 9: version gate runs first
                iosSupport = detectIOSSupportStatus()
                
                grant_full_disk_access() { error in
                            print(error?.localizedDescription as Any)
                        }
                deviceSize = getDefaultSubtype()
                
                switch UIDevice().machineName {
                case "iPhone11,8":
                    shouldRedBarFix = true
                    break
                case "iPhone12,1":
                    shouldRedBarFix = true
                    break
                default:
                    break
                }
                
            }
            .alert(isPresented: $shouldAlertDeviceSubTypeError) {
                Alert(title: Text("Error"), message: Text("There was an error getting the deviceSubType, maybe your plist file is corrupted, please tap on Reset and reopen the app again.\nNote: Your device will respring."), dismissButton: .destructive(Text("Reset"),action: {
                    // restore plist
                    killMobileGestalt()
                    
                    DispatchQueue.main.asyncAfter(deadline: .now() + 2.0){
                        respring()
                    }
                }))
            }
            .alert(isPresented: $shouldAlertPlistCorrupted) {
                Alert(title: Text("Error"), message: Text("There was an error modifying the plist file, it may be corrupted. Please tap on Restore plist file in Settings.\nNote: Your device will respring."), dismissButton: .destructive(Text("Restore"),action: {
                    // restore plist
                    killMobileGestalt()
                    
                    DispatchQueue.main.asyncAfter(deadline: .now() + 2.0){
                        respring()
                    }
                }))
            }
            .alert(isPresented: $shouldAlertKeyNotFound) {
                Alert(title: Text("Key not found"), message: Text("\"ArtworkDeviceSubType\" was not found in com.apple.MobileGestalt.plist.\nThis iOS version uses a different MobileGestalt layout and is not compatible with DynamicCow.\nNothing was written to your device."), dismissButton: .default(Text("OK")))
            }
            .alert(isPresented: $shouldAlertNotVulnerable) {
                Alert(title: Text("Exploit unavailable"), message: Text("This device is not vulnerable to MacDirtyCow (CVE-2022-46689).\nThe bug was patched by Apple in iOS 16.2 (December 2022).\nDynamicCow only works on iOS 16.0 – 16.1.2.\nNothing was written to your device."), dismissButton: .default(Text("OK")))
            }
    }
    
    // MARK: - support banner
    
    var unsupportedMessage: String {
        switch iosSupport {
        case .tooNew(let v):
            return "iOS \(v): MacDirtyCow (CVE-2022-46689) was patched by Apple in iOS 16.2 (December 2022). There is currently no public exploit able to enable the Dynamic Island on this version. Nothing was modified."
        case .tooOld(let v):
            return "iOS \(v): this app requires iOS 16.0 – 16.1.2 and is NOT a tweak. Running it here can bootloop your device. Nothing was modified."
        default:
            return ""
        }
    }
    
    @ViewBuilder
    private var supportBanner: some View {
        switch iosSupport {
        case .tooNew(let v):
            bannerCard(text: "iOS \(v) detected — CVE-2022-46689 was patched in iOS 16.2 (December 2022). No public exploit exists for this version: the Dynamic Island cannot be enabled here. Enable is locked.", color: .red)
        case .tooOld(let v):
            bannerCard(text: "iOS \(v) detected — this app only supports iOS 16.0 – 16.1.2. Enable is locked to protect your device from a bootloop.", color: .orange)
        default:
            EmptyView()
        }
    }
    
    private func bannerCard(text: String, color: Color) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Label("Unsupported iOS version", systemImage: "exclamationmark.triangle.fill")
                .font(.headline)
                .foregroundColor(color)
            Text(text)
                .font(.footnote)
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 12).fill(color.opacity(0.12)))
        .padding(.horizontal)
    }
    
    // MARK: - exploit probe
    
    /// Quick capability probe for CVE-2022-46689 on a scratch file in /var/tmp.
    /// Uses a short (2 s) race window; the real overwrite keeps the 10 s window.
    func probeExploitAvailable(completion: @escaping (Bool) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async {
            var vulnerable = false
            
            let pageSize = 0x4000
            let probePath = "/var/tmp/.dynamiccow_probe.\(getpid())"
            defer { try? FileManager.default.removeItem(atPath: probePath) }
            
            if FileManager.default.createFile(atPath: probePath, contents: Data(repeating: 0x41, count: pageSize)) {
                // CVE-2022-46689 cannot overwrite the LAST byte of each page,
                // so the replacement keeps that byte identical to the original.
                var replacement = Data(repeating: 0x42, count: pageSize)
                replacement[pageSize - 1] = 0x41
                
                let fd = open(probePath, O_RDONLY | O_CLOEXEC)
                if fd != -1 {
                    replacement.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
                        if let base = raw.baseAddress {
                            vulnerable = unaligned_copy_switch_race(fd, 0, base, replacement.count, 2)
                        }
                    }
                    close(fd)
                }
            }
            
            DispatchQueue.main.async { completion(vulnerable) }
        }
    }
    
    // MARK: - result handling
    
    func handlePlistResult(_ result: PlistChangeResult, targetSubtype: Int, enable: Bool) {
        switch result {
        case .success:
            // FIX 6: state is committed only after a real success
            currentSet = enable ? targetSubtype : 0
            isEnabled = enable
            if shouldRedBarFix {
                setResolution()   // resprings internally
            } else {
                respring()
            }
        case .overwriteFailed:
            shouldAlertPlistCorrupted = true
        case .keyNotFound:
            shouldAlertKeyNotFound = true
        case .readError(let message):
            NSLog("DynamicCow: plist read error: %@", message)
            shouldAlertPlistCorrupted = true
        }
        // FIX 5: was never reset before — the UI stayed stuck on the spinner
        isDoing = false
    }
    
    func setResolution() {
            do {
                let tmpPlistURL = URL(fileURLWithPath: "/var/tmp/com.apple.iokit.IOMobileGraphicsFamily.plist")
                try? FileManager.default.removeItem(at: tmpPlistURL)
                
                try createPlist(at: tmpPlistURL)
                
                let aliasURL = URL(fileURLWithPath: "/private/var/mobile/Library/Preferences/com.apple.iokit.IOMobileGraphicsFamily.plist")
                try? FileManager.default.removeItem(at: aliasURL)
                try FileManager.default.createSymbolicLink(at: aliasURL, withDestinationURL: tmpPlistURL)
                
                respring()
            } catch {
                UIApplication.shared.alert(body: error.localizedDescription)
            }
        }
    
    func createPlist(at url: URL) throws {
        if isEnabled{
                let 💀 : [String: Any] = [
                    "canvas_height": 1792,
                    "canvas_width": 828,
                ]
                let data = NSDictionary(dictionary: 💀)
                data.write(toFile: url.path, atomically: true)
        }else{
            let 💀 : [String: Any] = [
                "canvas_height": 1971,
                "canvas_width": 911,
            ]
            let data = NSDictionary(dictionary: 💀)
            data.write(toFile: url.path, atomically: true)
        }
        }
    
    /// FIX 3 + 4 + 7: safe reads (no crash), key-not-found tracking,
    /// runs off the main thread, completion on the main queue.
    func plistChange(plistPath: String, key: String, value: Int, completion: @escaping (PlistChangeResult) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async {
            var result: PlistChangeResult
            
            do {
                let stringsData = try Data(contentsOf: URL(fileURLWithPath: plistPath))
                guard let plist = try PropertyListSerialization.propertyList(from: stringsData, options: [], format: nil) as? [String: Any] else {
                    DispatchQueue.main.async { completion(.readError("plist root is not a dictionary")) }
                    return
                }
                
                var foundKey = false
                func changeValue(_ dict: [String: Any], _ key: String, _ value: Int) -> [String: Any] {
                    var newDict = dict
                    for (k, v) in dict {
                        if k == key {
                            newDict[k] = value
                            foundKey = true
                        } else if let subDict = v as? [String: Any] {
                            newDict[k] = changeValue(subDict, key, value)
                        }
                    }
                    return newDict
                }
                
                let newPlist = changeValue(plist, key, value)
                
                guard foundKey else {
                    DispatchQueue.main.async { completion(.keyNotFound) }
                    return
                }
                
                let newData = try PropertyListSerialization.data(fromPropertyList: newPlist, format: .binary, options: 0)
                
                if overwriteFile(originPath: plistPath, replacementData: newData) {
                    result = .success
                } else {
                    result = .overwriteFailed
                }
            } catch {
                result = .readError(error.localizedDescription)
            }
            
            DispatchQueue.main.async { completion(result) }
        }
    }
    
    // MARK: - original subtype
    
    /// FIX 11: no more async network race — bundled valid JSON is used as the
    /// fallback table, and the plist path parses safely (no force unwraps).
    func getDefaultSubtype() -> Int {
        var deviceSubType: Int = originalDeviceSubType
        
        if deviceSubType == 0 {
            
            var canUseStandardMethod: [String] = ["10,3", "10,4", "10,6", "11,2", "11,4", "11,6", "11,8", "12,1", "12,3", "12,5", "13,1", "13,2", "13,3", "13,4", "14,4", "14,5", "14,2", "14,3", "14,7", "14,8", "15,2"]
            for (i, v) in canUseStandardMethod.enumerated() {
                canUseStandardMethod[i] = "iPhone" + v
            }
            
            let deviceModel: String = UIDevice().machineName
            
            if canUseStandardMethod.contains(deviceModel) {
                // can use device bounds
                deviceSubType = Int(UIScreen.main.nativeBounds.height)
            }
            
            if deviceSubType == 0, let fromJSON = subtypeFromBundledJSON(for: deviceModel) {
                deviceSubType = fromJSON
            }
            
            // set the subtype
            if deviceSubType == 0 {
                // get the current subtype (safe parsing — no force unwrap, no crash)
                do {
                    let url = URL(fileURLWithPath: dynamicPath)
                    let data = try Data(contentsOf: url)
                    guard let plist = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
                          let cacheExtra = plist["CacheExtra"] as? [String: Any],
                          let gestaltEntry = cacheExtra["oPeik/9e8lQWMszEjbPzng"] as? [String: Any],
                          let currentType = gestaltEntry["ArtworkDeviceSubType"] as? Int else {
                        print("DynamicCow: ArtworkDeviceSubType not found in MobileGestalt.plist")
                        deviceSubType = 0
                        originalDeviceSubType = 0
                        withAnimation{
                            shouldAlertDeviceSubTypeError = true
                        }
                        return 0
                    }
                    
                    deviceSubType = currentType
                    
                    let origDeviceTypeURL = URL(fileURLWithPath: "/var/mobile/.DO-NOT-DELETE-TrollTools/.DO-NOT-DELETE-ArtworkDeviceSubTypeBackup")
                    if !FileManager.default.fileExists(atPath: origDeviceTypeURL.path) {
                        let backupData = String(currentType).data(using: .utf8)!
                        try backupData.write(to: origDeviceTypeURL)
                    }
                } catch {
                    print(error.localizedDescription)
                }
            }
             
            if deviceSubType == 0 {
                withAnimation{
                    shouldAlertDeviceSubTypeError = true
                }
            }
            
            if deviceSubType != 0 {
                originalDeviceSubType = deviceSubType
            }
        }
        return deviceSubType
    }
    
    func subtypeFromBundledJSON(for deviceModel: String) -> Int? {
        guard let url = Bundle.main.url(forResource: "DefaultSubTypes", withExtension: "json"),
              let data = try? Data(contentsOf: url),
              let object = try? JSONSerialization.jsonObject(with: data, options: []) as? [String: Any],
              let subtypes = object["Default_SubTypes"] as? [String: Int] else {
            return nil
        }
        return subtypes[deviceModel]
    }
    
    
    
    // Overwrite the system font with the given font using CVE-2022-46689.
    // The font must be specially prepared so that it skips past the last byte in every 16KB page.
    // See BrotliPadding.swift for an implementation that adds this padding to WOFF2 fonts.
    // credit: FontOverwrite
    func overwriteFile(originPath: String, replacementData: Data) -> Bool {
    #if false
        let documentDirectory = FileManager.default.urls(
            for: .documentDirectory,
            in: .userDomainMask
        )[0].path
        
        let pathToRealTarget = originPath
        let originPath = documentDirectory + originPath
        let origData = try! Data(contentsOf: URL(fileURLWithPath: pathToRealTarget))
        try! origData.write(to: URL(fileURLWithPath: originPath))
    #endif
        
        // open and map original font
        let fd = open(originPath, O_RDONLY | O_CLOEXEC)
        if fd == -1 {
            print("Could not open target file")
            return false
        }
        defer { close(fd) }
        // check size of font
        let originalFileSize = lseek(fd, 0, SEEK_END)
        guard originalFileSize >= replacementData.count else {
            print("Original file: \(originalFileSize)")
            print("Replacement file: \(replacementData.count)")
            print("File too big")
            return false
        }
        lseek(fd, 0, SEEK_SET)
        
        // Map the font we want to overwrite so we can mlock it
        let fileMap = mmap(nil, replacementData.count, PROT_READ, MAP_SHARED, fd, 0)
        if fileMap == MAP_FAILED {
            print("Failed to map")
            return false
        }
        // mlock so the file gets cached in memory
        guard mlock(fileMap, replacementData.count) == 0 else {
            print("Failed to mlock")
            munmap(fileMap, replacementData.count)
            // FIX 1: was `return true` — reported success while nothing was written
            return false
        }
        defer { munmap(fileMap, replacementData.count) } // FIX 2: was leaked
        
        // for every 16k chunk, rewrite
        print(Date())
        for chunkOff in stride(from: 0, to: replacementData.count, by: 0x4000) {
            print(String(format: "%lx", chunkOff))
            let dataChunk = replacementData[chunkOff..<min(replacementData.count, chunkOff + 0x4000)]
            var overwroteOne = false
            for _ in 0..<2 {
                let overwriteSucceeded = dataChunk.withUnsafeBytes { dataChunkBytes in
                    return unaligned_copy_switch_race(
                        fd, Int64(chunkOff), dataChunkBytes.baseAddress, dataChunkBytes.count, 10)
                }
                if overwriteSucceeded {
                    overwroteOne = true
                    break
                }
                print("try again?!")
            }
            guard overwroteOne else {
                print("Failed to overwrite")
                return false
            }
        }
        print(Date())
        return true
    }
    
    func respring(){
        UIImpactFeedbackGenerator(style: .soft).impactOccurred()

        // FIX 12: no more force unwraps — fall back to the raw backboard crash
        guard let windowScene = UIApplication.shared.connectedScenes
            .compactMap({ $0 as? UIWindowScene }).first,
              let window = windowScene.windows.first else {
            respringBackboard()
            return
        }

        let view = UIView(frame: UIScreen.main.bounds)
        view.backgroundColor = .black
        view.alpha = 0

        window.addSubview(view)
        UIView.animate(withDuration: 0.2, delay: 0, animations: {
            view.alpha = 1
        })

        DispatchQueue.main.asyncAfter(deadline: .now() + 0.2, execute: {
            respringBackboard()
        })
    }

    
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
