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