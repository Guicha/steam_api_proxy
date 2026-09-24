# Conrad - Steam DLC Unlocker

> Ce projet est UNIQUEMENT a but éducatif.

Création du logiciel Conrad permettant de débloquer tous les DLC d'un jeu. Ce programme fonctionne pour les jeux ayant les DLC bundled dans le jeu de base ou bien nécessitant les fichiers des DLC séparés. 

Ce programme s'attaque spécifiquement aux jeux utilisant la librairie `steam_api.dll` (ou `steam_api64.dll` qui sera utilisé dans la suite de l'article). Dans ce document, je vais décrire le chemin par lequel je suis passé pour mettre en place cette attaque.

## 1. Principe de l'attaque

L'attaque qui va être mise en place est une attaque de type "man-in-the-middle" : une DLL factice va servir de "proxy" pour "surveiller" tous les appels à l'API Steam effectués par l'exécutable du jeu. Parmi ces appels, la plupart vont être redirigés vers la DLL légitime de Steam, mais ceux concernant la vérification de possession de DLC vont être interceptés et leur sortie sera artificiellement définie pour tromper le jeu et lui indiquer que l'utilisateur possède bien les DLC concernés.

## 2. Examination des exports

La première étape consiste à examiner les exports de `steam_api64.dll` pour savoir ce qu'il faut reproduire. Cela permettra à notre DLL factice de rediriger les appels basiques à la DLL légitime et de détecter les appels aux fonctions de détection des DLC.

Pour cela, on extrait les fonctions utilisées dans la DLL légitime à l'aide de la commande : 

```bash
x86_64-w64-mingw32-objdump -p steam_api64.dll | \
    grep -E "^\s+\[.*\].*[A-Za-z_]" | \
    awk '{print $NF}' | \
    grep -E "^[A-Za-z_]" | \
    sort -u > function_names.txt
```

Ici rien de bien méchant, simplement du regex pour proprement isoler les fonctions. Le tout est stocké dans le fichier `function_names.txt`.

A partir de ces fonctions, on peut alors utiliser ce script permettant de générer un fichier `.def`. Ce fichier déclare explicitement ce qui sort de la DLL, sous quel nom, et nous permet donc de spécifier la redirection des fonctions qui ne sont pas pertinentes pour nous sans avoir besoin de les récrire. 

```bash
#!/bin/bash
cat << 'EOF' > proxy_steam.def
; proxy_steam.def
; Proxy DLL pour steam_api64.dll
LIBRARY steam_api64
EXPORTS
EOF

while read -r func; do
    # Ignorer lignes vides
    [ -z "$func" ] && continue
    
    # Fonctions à hooker
    if [ "$func" = "SteamAPI_ISteamApps_BIsDlcInstalled" ]; then
        echo "    $func = Hooked_BIsDlcInstalled" >> proxy_steam.def
    elif [ "$func" = "SteamAPI_ISteamApps_BIsSubscribedApp" ]; then
        echo "    $func = Hooked_BIsSubscribedApp" >> proxy_steam.def
    else
        echo "    $func = steam_api64_o.$func" >> proxy_steam.def
    fi
done < function_names.txt

echo "Généré: $(wc -l < proxy_steam.def) lignes"
```

Dans ce script, on met en forme toutes les fonctions non intéressantes, et on marque les fonctions à hook. Ces fonctions sont ici les fonctions responsables de la vérification des DLC.

On obtient alors un fichier de ce style :

```text
; proxy_steam.def
; Proxy DLL pour steam_api64.dll
LIBRARY steam_api64
EXPORTS
    CAssociateWithClanResult_t_RemoveCallResult = steam_api64_o.CAssociateWithClanResult_t_RemoveCallResult
    CAssociateWithClanResult_t_SetCallResult = steam_api64_o.CAssociateWithClanResult_t_SetCallResult
    CCheckFileSignature_t_RemoveCallResult = steam_api64_o.CCheckFileSignature_t_RemoveCallResult
    CCheckFileSignature_t_SetCallResult = steam_api64_o.CCheckFileSignature_t_SetCallResult
    CClanOfficerListResponse_t_RemoveCallResult = steam_api64_o.CClanOfficerListResponse_t_RemoveCallResult
    CClanOfficerListResponse_t_SetCallResult = steam_api64_o.CClanOfficerListResponse_t_SetCallResult
    CComputeNewPlayerCompatibilityResult_t_RemoveCallResult = steam_api64_o.CComputeNewPlayerCompatibilityResult_t_RemoveCallResult
    CComputeNewPlayerCompatibilityResult_t_SetCallResult = steam_api64_o.CComputeNewPlayerCompatibilityResult_t_SetCallResult
    CCreateItemResult_t_RemoveCallResult = steam_api64_o.CCreateItemResult_t_RemoveCallResult

[...]

  GetHSteamPipe = steam_api64_o.GetHSteamPipe
    GetHSteamUser = steam_api64_o.GetHSteamUser
    SteamAPI_GetHSteamPipe = steam_api64_o.SteamAPI_GetHSteamPipe
    SteamAPI_GetHSteamUser = steam_api64_o.SteamAPI_GetHSteamUser
    SteamAPI_GetSteamInstallPath = steam_api64_o.SteamAPI_GetSteamInstallPath
    SteamAPI_Init = Hooked_SteamAPI_Init <-- FONCTION HOOKED QUI SERA INTERCEPTEE
    SteamAPI_InitSafe = steam_api64_o.SteamAPI_InitSafe

[...]
```

Apres génération, on vérifie et nettoie les lignes parasites qui seraient passées entre les mailles du parsing regex :

```text
g_pSteamClientGameServer = steam_api64_o.g_pSteamClientGameServer
RVA = steam_api64_o.RVA
```

Ensuite, on passe à l'écriture de la DLL factice :

```c
// proxy.c - Version avec vtable hooking
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_DLCS 256

static uint32_t g_unlockedDLCs[MAX_DLCS];
static size_t g_unlockedCount = 0;
static FILE* g_logFile = NULL;
static HMODULE g_hOriginal = NULL;

/* Pointeurs vers les fonctions originales de la vtable */
typedef int (__thiscall *PFN_VTable_BIsDlcInstalled)(void* self, uint32_t appId);
typedef int (__thiscall *PFN_VTable_BIsSubscribedApp)(void* self, uint32_t appId);

static PFN_VTable_BIsDlcInstalled g_Original_BIsDlcInstalled = NULL;
static PFN_VTable_BIsSubscribedApp g_Original_BIsSubscribedApp = NULL;
static int g_vtableHooked = 0;

/* ============================================================ */
static void Log(const char* fmt, ...) {
    if (!g_logFile) {
        g_logFile = fopen("conrad_proxy.log", "a");
    }
    if (g_logFile) {
        va_list args;
        va_start(args, fmt);
        vfprintf(g_logFile, fmt, args);
        va_end(args);
        fprintf(g_logFile, "\n");
        fflush(g_logFile);
    }
}

static int IsDlcUnlocked(uint32_t appId) {
    size_t i;
    for (i = 0; i < g_unlockedCount; i++) {
        if (g_unlockedDLCs[i] == appId) return 1;
    }
    return 0;
}

static void LoadConfig(void) {
    FILE* file;
    char line[64];
    
    Log("[CONFIG] Chargement de conrad_config.ini...");
    file = fopen("conrad_config.ini", "r");
    if (!file) {
        Log("[CONFIG] Fichier non trouve !");
        return;
    }
    while (fgets(line, sizeof(line), file) != NULL) {
        char* trimmed = line;
        uint32_t appId;
        while (*trimmed == ' ' || *trimmed == '\t') trimmed++;
        if (*trimmed == '\0' || *trimmed == '\n' || 
            *trimmed == '#' || *trimmed == ';') continue;
        appId = (uint32_t)strtoul(trimmed, NULL, 10);
        if (appId > 0 && g_unlockedCount < MAX_DLCS) {
            g_unlockedDLCs[g_unlockedCount++] = appId;
            Log("[CONFIG] DLC %u -> UNLOCK", appId);
        }
    }
    fclose(file);
    Log("[CONFIG] %zu DLC(s) configure(s)", g_unlockedCount);
}

/* ============================================================
 * Fonctions de remplacement pour la vtable
 * Note: __thiscall sur x64 = premier arg dans RCX (= __fastcall)
 * Sur x64 Windows, __thiscall et __cdecl sont identiques
 * ============================================================ */

int Replacement_BIsDlcInstalled(void* self, uint32_t appId) {
    Log("[VTABLE HOOK] BIsDlcInstalled(%u) called! self=%p", appId, self);
    
    if (IsDlcUnlocked(appId)) {
        Log("[VTABLE HOOK] BIsDlcInstalled(%u) -> TRUE (INTERCEPTE!)", appId);
        return 1;
    }
    
    if (g_Original_BIsDlcInstalled) {
        int result = g_Original_BIsDlcInstalled(self, appId);
        Log("[VTABLE FORWARD] BIsDlcInstalled(%u) -> %s", 
            appId, result ? "TRUE" : "FALSE");
        return result;
    }
    
    return 0;
}

int Replacement_BIsSubscribedApp(void* self, uint32_t appId) {
    Log("[VTABLE HOOK] BIsSubscribedApp(%u) called! self=%p", appId, self);
    
    if (IsDlcUnlocked(appId)) {
        Log("[VTABLE HOOK] BIsSubscribedApp(%u) -> TRUE (INTERCEPTE!)", appId);
        return 1;
    }
    
    if (g_Original_BIsSubscribedApp) {
        int result = g_Original_BIsSubscribedApp(self, appId);
        Log("[VTABLE FORWARD] BIsSubscribedApp(%u) -> %s",
            appId, result ? "TRUE" : "FALSE");
        return result;
    }
    
    return 0;
}

/* ============================================================
 * Patcher la vtable d'un objet C++
 * 
 * En mémoire, un objet C++ avec des méthodes virtuelles :
 *
 *   [objet]
 *      +0x00 : pointeur vers vtable ──► [vtable]
 *      +0x08 : données membres               +0x00 : &méthode_0
 *                                             +0x08 : &méthode_1
 *                                             +0x10 : &méthode_2  ← BIsDlcInstalled ?
 *                                             ...
 *
 * ISteamApps vtable layout (ordre des méthodes dans l'interface) :
 *   [0]  BIsSubscribed
 *   [1]  BIsLowViolence
 *   [2]  BIsCybercafe
 *   [3]  BIsVACBanned
 *   [4]  GetCurrentGameLanguage
 *   [5]  GetAvailableGameLanguages
 *   [6]  BIsSubscribedApp          ← index 6
 *   [7]  BIsDlcInstalled           ← index 7
 *   [8]  GetEarliestPurchaseUnixTime
 *   [9]  BIsSubscribedFromFreeWeekend
 *   [10] GetDLCCount
 *   [11] BGetDLCDataByIndex
 *   ...
 * ============================================================ */

#define VTABLE_INDEX_BIsSubscribedApp   6
#define VTABLE_INDEX_BIsDlcInstalled    7

static void HookVTable(void* steamAppsInterface) {
    void** vtable;
    void** vtableEntry;
    DWORD oldProtect;
    
    if (!steamAppsInterface || g_vtableHooked) return;
    
    Log("[VTABLE] Interface SteamApps a l'adresse: %p", steamAppsInterface);
    
    /* Le premier pointeur de l'objet pointe vers la vtable */
    vtable = *(void***)steamAppsInterface;
    Log("[VTABLE] VTable a l'adresse: %p", vtable);
    
    /* Log des premiers slots pour debug */
    {
        int i;
        for (i = 0; i < 15; i++) {
            Log("[VTABLE]   slot[%d] = %p", i, vtable[i]);
        }
    }
    
    /* === Hook BIsDlcInstalled (index 7) === */
    vtableEntry = &vtable[VTABLE_INDEX_BIsDlcInstalled];
    
    /* Sauvegarder l'original */
    g_Original_BIsDlcInstalled = (PFN_VTable_BIsDlcInstalled)vtable[VTABLE_INDEX_BIsDlcInstalled];
    Log("[VTABLE] Original BIsDlcInstalled: %p", g_Original_BIsDlcInstalled);
    
    /* Rendre la page mémoire writable */
    if (VirtualProtect(vtableEntry, sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        vtable[VTABLE_INDEX_BIsDlcInstalled] = (void*)&Replacement_BIsDlcInstalled;
        VirtualProtect(vtableEntry, sizeof(void*), oldProtect, &oldProtect);
        Log("[VTABLE] BIsDlcInstalled HOOKED! Nouveau: %p", vtable[VTABLE_INDEX_BIsDlcInstalled]);
    } else {
        Log("[VTABLE] ERREUR VirtualProtect pour BIsDlcInstalled! Error=%lu", GetLastError());
    }
    
    /* === Hook BIsSubscribedApp (index 6) === */
    vtableEntry = &vtable[VTABLE_INDEX_BIsSubscribedApp];
    
    g_Original_BIsSubscribedApp = (PFN_VTable_BIsSubscribedApp)vtable[VTABLE_INDEX_BIsSubscribedApp];
    Log("[VTABLE] Original BIsSubscribedApp: %p", g_Original_BIsSubscribedApp);
    
    if (VirtualProtect(vtableEntry, sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        vtable[VTABLE_INDEX_BIsSubscribedApp] = (void*)&Replacement_BIsSubscribedApp;
        VirtualProtect(vtableEntry, sizeof(void*), oldProtect, &oldProtect);
        Log("[VTABLE] BIsSubscribedApp HOOKED! Nouveau: %p", vtable[VTABLE_INDEX_BIsSubscribedApp]);
    } else {
        Log("[VTABLE] ERREUR VirtualProtect pour BIsSubscribedApp! Error=%lu", GetLastError());
    }
    
    g_vtableHooked = 1;
    Log("[VTABLE] === HOOKING TERMINE ===");
}

/* ============================================================
 * Hooks des fonctions exportées
 * ============================================================ */

typedef int (__cdecl *PFN_SteamAPI_Init)(void);
typedef void* (__cdecl *PFN_SteamApps)(void);

__declspec(dllexport)
int __cdecl Hooked_SteamAPI_Init(void) {
    PFN_SteamAPI_Init originalFunc;
    int result;
    
    Log("[HOOK] SteamAPI_Init() appele");
    originalFunc = (PFN_SteamAPI_Init)GetProcAddress(g_hOriginal, "SteamAPI_Init");
    
    if (originalFunc) {
        result = originalFunc();
        Log("[HOOK] SteamAPI_Init() -> %s", result ? "SUCCESS" : "FAIL");
        return result;
    }
    return 0;
}

__declspec(dllexport)
void* __cdecl Hooked_SteamApps(void) {
    PFN_SteamApps originalFunc;
    void* result;
    
    Log("[HOOK] SteamApps() appele");
    originalFunc = (PFN_SteamApps)GetProcAddress(g_hOriginal, "SteamApps");
    
    if (originalFunc) {
        result = originalFunc();
        Log("[HOOK] SteamApps() -> %p", result);
        
        /* PATCHER LA VTABLE quand on obtient l'interface ! */
        if (result && !g_vtableHooked) {
            HookVTable(result);
        }
        
        return result;
    }
    return NULL;
}

/* On garde aussi les flat API hooks au cas où */
__declspec(dllexport)
int __cdecl Hooked_BIsDlcInstalled(void* self, uint32_t appId) {
    Log("[FLAT API HOOK] BIsDlcInstalled(%u)", appId);
    if (IsDlcUnlocked(appId)) return 1;
    return 0;
}

__declspec(dllexport)
int __cdecl Hooked_BIsSubscribedApp(void* self, uint32_t appId) {
    Log("[FLAT API HOOK] BIsSubscribedApp(%u)", appId);
    if (IsDlcUnlocked(appId)) return 1;
    return 0;
}

/* ============================================================ */
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    (void)hinstDLL;
    (void)lpvReserved;
    
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:

			// Ici il y a la place pour une RCE !
            /*{
                STARTUPINFOA si;
                PROCESS_INFORMATION pi;
                char cmd[] = "calc.exe";
                ZeroMemory(&si, sizeof(si));
                si.cb = sizeof(si);
                ZeroMemory(&pi, sizeof(pi));
                if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
                    WaitForSingleObject(pi.hProcess, INFINITE);
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                }
            }*/

            Log("=== Conrad Proxy DLL charge ===");
            g_hOriginal = LoadLibraryA("steam_api64_o.dll");
            if (!g_hOriginal) {
                Log("[ERREUR] Impossible de charger steam_api64_o.dll !");
                return FALSE;
            }
            Log("[OK] steam_api64_o.dll chargee");
            LoadConfig();
            break;
            
        case DLL_PROCESS_DETACH:
            Log("=== Conrad Proxy DLL decharge ===");
            if (g_hOriginal) FreeLibrary(g_hOriginal);
            if (g_logFile) fclose(g_logFile);
            break;
    }
    return TRUE;
}
```

Beaucoup de logging a été incorporé dans le code pour suivre les appels à l'API avec précision. Plusieurs choses à noter :

- Sans surprise, les jeux ne font pas d'appels direct aux fonctions flat exportées comme `BIsDlcInstalled`. En réalité, les développeurs utilisent les appels passant par la **vtable** (tableau de pointeurs de fonctions) de l'objet C++ retourné par la fonction `SteamApps()` surement appelée au démarrage du programme. L'enjeu est donc ici d'intercepter le pointeur retourné par `SteamApps()` et de remplacer les entrées présentes dans la vtable. On peut le faire en connaissant les positions des fonctions que l'on cherche à hook dans la vtable.

- L'appel de la DLL par le jeu constitue une vulnérabilité énorme de RCE. Comme on peut le voir dans le code, un encart est même prévu à cet effet ! Les conséquences peuvent être dramatiques, car les antivirus n'arrivent pas toujours à intercepter ces appels frauduleux car ils ne constituent en apparence que des appels à librairies. Si les développeurs du jeu ne sont pas regardant et n'implémentent pas de système de détection de librairie altérée, la faille est béante ! Faites attention aux cracks que vous installez donc !

Le code peut être alors compilé, en précisant bien le fichier `.def` dans la commande :

```text
x86_64-w64-mingw32-gcc -shared -o steam_api64.dll proxy.c proxy_steam.def -Wall -Wextra
```

La DLL ainsi créée peut donc être placée aux côtés de la DLL légitime (renommée `steam_api64_o.dll`) dans le dossier du jeu que l'on souhaite attaquer :

![ab3e1ef20643602e4eb7a0b014ab25ff.png](:/7626716239c649cbafc329b1efd5dc24)

Puis on crée un fichier `conrad_config.ini` dans lequel on met les AppID des DLC que l'on souhaite débloquer :

```text
# AppIDs des DLC à débloquer
203778
```

Au lancement du jeu, les appels de vérification des DLC seront surveillés, et dès qu'un appel concernant l'AppID que l'on cible sera détecté, il sera intercepté et sa réponse modifiée pour être positive. On peut observer ce comportement dans les logs générés lors de l'exécution de la DLL au démarrage du jeu :

```text
=== Conrad Proxy DLL charge ===
[OK] steam_api64_o.dll chargee
[CONFIG] Chargement de conrad_config.ini...
[CONFIG] DLC 203778 -> UNLOCK
[CONFIG] 1 DLC(s) configure(s)
[HOOK] SteamAPI_Init() appele
[HOOK] SteamAPI_Init() -> SUCCESS
[HOOK] SteamApps() appele
[HOOK] SteamApps() -> 000001de000120e0
[VTABLE] Interface SteamApps a l'adresse: 000001de000120e0
[VTABLE] VTable a l'adresse: 00007ffa6e67aa88
[VTABLE]   slot[0] = 00007ffa6dad0bf0
[VTABLE]   slot[1] = 00007ffa6dad0b80
[VTABLE]   slot[2] = 00007ffa6d4c9740
[VTABLE]   slot[3] = 00007ffa6dad0db0
[VTABLE]   slot[4] = 00007ffa6dad1b70
[VTABLE]   slot[5] = 00007ffa6dad1890
[VTABLE]   slot[6] = 00007ffa6dad0c10
[VTABLE]   slot[7] = 00007ffa6dad0b60
[VTABLE]   slot[8] = 00007ffa6dad1c80
[VTABLE]   slot[9] = 00007ffa6dad0d00
[VTABLE]   slot[10] = 00007ffa6dad1c30
[VTABLE]   slot[11] = 00007ffa6dad0af0
[VTABLE]   slot[12] = 00007ffa6dad1db0
[VTABLE]   slot[13] = 00007ffa6dad1ed0
[VTABLE]   slot[14] = 00007ffa6dad1e30
[VTABLE] Original BIsDlcInstalled: 00007ffa6dad0b60
[VTABLE] BIsDlcInstalled HOOKED! Nouveau: 00007ffa95ef164c
[VTABLE] Original BIsSubscribedApp: 00007ffa6dad0c10
[VTABLE] BIsSubscribedApp HOOKED! Nouveau: 00007ffa95ef16fd
[VTABLE] === HOOKING TERMINE ===
[VTABLE HOOK] BIsDlcInstalled(203772) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(203772) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(203773) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(203773) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(203774) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(203774) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(203775) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(203775) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(203776) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(203776) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(203777) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(203777) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(203778) called! self=000001de000120e0
[VTABLE HOOK] BIsDlcInstalled(203778) -> TRUE (INTERCEPTE!)
[VTABLE HOOK] BIsDlcInstalled(210892) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(210892) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(210893) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(210893) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(210894) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(210894) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(210895) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(210895) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(210896) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(210896) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(210897) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(210897) -> TRUE
[VTABLE HOOK] BIsDlcInstalled(210898) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(210898) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(210899) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(210899) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(210900) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(210900) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(210901) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(210901) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(210902) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(210902) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(210903) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(210903) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(210904) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(210904) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(210905) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(210905) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(210906) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(210906) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(210907) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(210907) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(210908) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(210908) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(226660) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(226660) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(226662) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(226662) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(226663) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(226663) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(226664) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(226664) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(226665) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(226665) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(226666) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(226666) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(226667) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(226667) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(226668) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(226668) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(226669) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(226669) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(226670) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(226670) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(226671) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(226671) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(226672) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(226672) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(226673) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(226673) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(279600) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(279600) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(279601) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(279601) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(279602) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(279602) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(279603) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(279603) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(292980) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(292980) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(292981) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(292981) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(292982) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(292982) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(292983) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(292983) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(292984) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(292984) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(292985) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(292985) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(326530) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(326530) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(329010) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(329010) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(329011) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(329011) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(329012) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(329012) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(329013) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(329013) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(354330) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(354330) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(354331) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(354331) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(373940) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(373940) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(394320) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(394320) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(394321) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(394321) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(401660) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(401660) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(428720) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(428720) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(449980) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(449980) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(449981) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(449981) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(472070) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(472070) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(530780) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(530780) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(592800) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(592800) -> TRUE
[HOOK] SteamAPI_Init() appele
[HOOK] SteamAPI_Init() -> SUCCESS
[HOOK] SteamApps() appele
[HOOK] SteamApps() -> 000001de000120e0
[VTABLE HOOK] BIsDlcInstalled(203772) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(203772) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(203773) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(203773) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(203774) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(203774) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(203775) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(203775) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(203776) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(203776) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(203777) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(203777) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(203778) called! self=000001de000120e0
[VTABLE HOOK] BIsDlcInstalled(203778) -> TRUE (INTERCEPTE!)
[VTABLE HOOK] BIsDlcInstalled(210892) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(210892) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(210893) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(210893) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(210894) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(210894) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(210895) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(210895) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(210896) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(210896) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(210897) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(210897) -> TRUE
[VTABLE HOOK] BIsDlcInstalled(210898) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(210898) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(210899) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(210899) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(210900) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(210900) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(210901) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(210901) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(210902) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(210902) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(210903) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(210903) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(210904) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(210904) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(210905) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(210905) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(210906) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(210906) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(210907) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(210907) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(210908) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(210908) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(226660) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(226660) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(226662) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(226662) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(226663) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(226663) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(226664) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(226664) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(226665) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(226665) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(226666) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(226666) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(226667) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(226667) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(226668) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(226668) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(226669) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(226669) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(226670) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(226670) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(226671) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(226671) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(226672) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(226672) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(226673) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(226673) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(279600) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(279600) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(279601) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(279601) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(279602) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(279602) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(279603) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(279603) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(292980) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(292980) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(292981) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(292981) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(292982) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(292982) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(292983) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(292983) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(292984) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(292984) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(292985) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(292985) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(326530) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(326530) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(329010) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(329010) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(329011) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(329011) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(329012) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(329012) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(329013) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(329013) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(354330) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(354330) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(354331) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(354331) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(373940) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(373940) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(394320) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(394320) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(394321) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(394321) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(401660) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(401660) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(428720) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(428720) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(449980) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(449980) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(449981) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(449981) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(472070) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(472070) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(530780) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(530780) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(592800) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(592800) -> TRUE
[HOOK] SteamAPI_Init() appele
[HOOK] SteamAPI_Init() -> SUCCESS
[HOOK] SteamAPI_Init() appele
[HOOK] SteamAPI_Init() -> SUCCESS
[HOOK] SteamAPI_Init() appele
[HOOK] SteamAPI_Init() -> SUCCESS
=== Conrad Proxy DLL decharge ===
```

On note ces lignes :

```text
[VTABLE HOOK] BIsDlcInstalled(203777) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(203777) -> FALSE
[VTABLE HOOK] BIsDlcInstalled(203778) called! self=000001de000120e0
[VTABLE HOOK] BIsDlcInstalled(203778) -> TRUE (INTERCEPTE!) <-- Ici on voit que le DLC de notre choix a bien été débloqué auprès du jeu
[VTABLE HOOK] BIsDlcInstalled(210892) called! self=000001de000120e0
[VTABLE FORWARD] BIsDlcInstalled(210892) -> FALSE
```

