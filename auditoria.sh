#!/usr/bin/env bash

# ============================================================
#   Auditoria de Fuerza Bruta - v2.1
#   Uso: ./auditoria.sh <IP o RANGO CIDR>
#   Ejemplo: ./auditoria.sh 192.168.1.1
#            ./auditoria.sh 192.168.1.0/24
# ============================================================

ROJO='\033[0;31m'
VERDE='\033[0;32m'
AZUL='\033[0;36m'
AMARILLO='\033[1;33m'
CYAN='\033[0;35m'
RESET='\033[0m'

THREADS=4
DELAY=1
TIMEOUT_HYDRA=120
INFORME="informe_auditoria_$(date +%Y%m%d_%H%M%S).txt"

# ── Utilidades ───────────────────────────────────────────────

banner() {
    echo -e "${AZUL}"
    echo "  ╔══════════════════════════════════════════╗"
    echo "  ║     Auditoria de Fuerza Bruta  v2.1      ║"
    echo "  ║   Solo para entornos autorizados         ║"
    echo "  ╚══════════════════════════════════════════╝"
    echo -e "${RESET}"
}

mostrar_error() {
    echo -e "${ROJO}[ERROR] $1${RESET}" >&2
    exit 1
}

verificar_dependencias() {
    for paquete in nmap hydra; do
        if ! command -v "$paquete" &>/dev/null; then
            echo -e "${AMARILLO}[!] $paquete no encontrado. Instalando...${RESET}"
            if command -v apt-get &>/dev/null; then
                sudo apt-get install -y "$paquete" &>/dev/null \
                    || mostrar_error "No se pudo instalar $paquete."
            else
                mostrar_error "Instala $paquete manualmente."
            fi
        fi
    done
}

verificar_root() {
    if [ "$(id -u)" != 0 ]; then
        echo -e "${AMARILLO}[!] Sin root: el escaneo -sV puede ser menos preciso.${RESET}"
    fi
}

# ── Mapeo nmap -> modulo hydra ────────────────────────────────

mapear_servicio() {
    case "${1,,}" in
        ssh|ssh2)                     echo "ssh" ;;
        ftp)                          echo "ftp" ;;
        http|http-alt)                echo "http-get" ;;
        https|ssl/http)               echo "https-get" ;;
        rdp|ms-wbt-server)            echo "rdp" ;;
        smb|microsoft-ds|netbios-ssn) echo "smb" ;;
        mysql)                        echo "mysql" ;;
        postgres|postgresql)          echo "postgres" ;;
        telnet)                       echo "telnet" ;;
        vnc)                          echo "vnc" ;;
        smtp)                         echo "smtp" ;;
        imap)                         echo "imap" ;;
        pop3)                         echo "pop3" ;;
        mssql|ms-sql-s)               echo "mssql" ;;
        *)                            echo "$1" ;;
    esac
}

# ── Escaneo de puertos ───────────────────────────────────────

escanear_puertos() {
    local objetivo=$1
    echo -e "\n${AZUL}[*] Escaneando $objetivo ...${RESET}"

    local xml_tmp
    xml_tmp=$(mktemp /tmp/nmap_XXXXXX.xml)

    nmap -Pn -sV --top-ports 1000 --open -oX "$xml_tmp" "$objetivo" &>/dev/null

    if [ ! -s "$xml_tmp" ]; then
        echo -e "${ROJO}[-] El escaneo no produjo resultados.${RESET}"
        rm -f "$xml_tmp"
        return 1
    fi

    HOSTS_PUERTOS=()
    while IFS= read -r linea; do
        HOSTS_PUERTOS+=("$linea")
    done < <(python3 - "$xml_tmp" <<'PYEOF'
import sys, xml.etree.ElementTree as ET
tree = ET.parse(sys.argv[1])
for host in tree.findall('host'):
    addr = host.find('address')
    if addr is None: continue
    ip = addr.get('addr','')
    ports = host.find('ports')
    if ports is None: continue
    for port in ports.findall('port'):
        state = port.find('state')
        if state is None or state.get('state') != 'open': continue
        portid = port.get('portid','')
        svc = port.find('service')
        svcname = svc.get('name','unknown') if svc is not None else 'unknown'
        product = svc.get('product','') if svc is not None else ''
        version = svc.get('version','') if svc is not None else ''
        extra = f" ({product} {version})".strip(" ()")
        extra = f" [{extra}]" if extra else ""
        print(f"{ip}:{portid}:{svcname}{extra}")
PYEOF
    )

    rm -f "$xml_tmp"

    if [ ${#HOSTS_PUERTOS[@]} -eq 0 ]; then
        echo -e "${ROJO}[-] No se encontraron puertos abiertos en $objetivo.${RESET}"
        return 1
    fi

    return 0
}

# ── Menu de seleccion ────────────────────────────────────────

mostrar_menu() {
    echo -e "\n${AZUL}╔══════════════════════════════════════════════╗${RESET}"
    echo -e "${AZUL}║         PUERTOS ABIERTOS DETECTADOS          ║${RESET}"
    echo -e "${AZUL}╚══════════════════════════════════════════════╝${RESET}"
    printf "${VERDE}%-4s %-18s %-8s %-30s %-15s${RESET}\n" \
           "No" "IP" "Puerto" "Servicio Nmap" "Modulo Hydra"
    echo -e "${AZUL}────────────────────────────────────────────────────────${RESET}"

    local i=1
    MENU_OPCIONES=()

    for entry in "${HOSTS_PUERTOS[@]}"; do
        local ip puerto svc_raw svc_name svc_hydra
        ip=$(echo "$entry"      | cut -d: -f1)
        puerto=$(echo "$entry"  | cut -d: -f2)
        svc_raw=$(echo "$entry" | cut -d: -f3-)
        svc_name=$(echo "$svc_raw" | awk '{print $1}')
        svc_hydra=$(mapear_servicio "$svc_name")

        printf "%-4s %-18s %-8s %-30s ${CYAN}%-15s${RESET}\n" \
               "[$i]" "$ip" "$puerto" "$svc_raw" "$svc_hydra"
        MENU_OPCIONES+=("$ip:$puerto:$svc_hydra")
        ((i++))
    done

    echo -e "${AZUL}────────────────────────────────────────────────────────${RESET}"
    echo -e "${AMARILLO}[0] Salir${RESET}"
}

pedir_seleccion() {
    local max=${#MENU_OPCIONES[@]}
    local sel

    while true; do
        read -rp $'\n'"Selecciona un objetivo [1-$max] o 0 para salir: " sel
        if [[ "$sel" == "0" ]]; then
            echo -e "${AMARILLO}Saliendo.${RESET}"
            exit 0
        fi
        if [[ "$sel" =~ ^[0-9]+$ ]] && [ "$sel" -ge 1 ] && [ "$sel" -le "$max" ]; then
            SELECCION="${MENU_OPCIONES[$((sel-1))]}"
            return 0
        fi
        echo -e "${ROJO}Opcion invalida. Introduce un numero entre 0 y $max.${RESET}"
    done
}

pedir_ficheros() {
    local ip=$1
    local puerto=$2
    local modulo=$3

    echo -e "\n${AZUL}[*] Objetivo: $ip:$puerto ($modulo)${RESET}"
    echo -e "${AZUL}────────────────────────────────────────────────${RESET}"

    while true; do
        read -rp "$(echo -e "${VERDE}Ruta fichero USUARIOS:${RESET} ")" f_usuarios
        f_usuarios="${f_usuarios/#\~/$HOME}"
        if [ ! -f "$f_usuarios" ]; then
            echo -e "${ROJO}  x No existe: '$f_usuarios'${RESET}"
        elif [ ! -s "$f_usuarios" ]; then
            echo -e "${ROJO}  x Fichero vacio: '$f_usuarios'${RESET}"
        else
            echo -e "${VERDE}  + $(wc -l < "$f_usuarios") usuarios cargados.${RESET}"
            break
        fi
    done

    while true; do
        read -rp "$(echo -e "${VERDE}Ruta fichero CONTRASENAS:${RESET} ")" f_passwords
        f_passwords="${f_passwords/#\~/$HOME}"
        if [ ! -f "$f_passwords" ]; then
            echo -e "${ROJO}  x No existe: '$f_passwords'${RESET}"
        elif [ ! -s "$f_passwords" ]; then
            echo -e "${ROJO}  x Fichero vacio: '$f_passwords'${RESET}"
        else
            echo -e "${VERDE}  + $(wc -l < "$f_passwords") contrasenas cargadas.${RESET}"
            break
        fi
    done

    F_USUARIOS="$f_usuarios"
    F_PASSWORDS="$f_passwords"
}

# ── Ataque ───────────────────────────────────────────────────

ejecutar_ataque() {
    local ip=$1
    local puerto=$2
    local modulo=$3
    local f_usuarios=$4
    local f_passwords=$5
    local fecha
    fecha=$(date "+%Y-%m-%d %H:%M:%S")

    echo -e "\n${AZUL}[*] Lanzando hydra -> $modulo en $ip:$puerto${RESET}"
    echo -e "${AMARILLO}    Usuarios:    $f_usuarios${RESET}"
    echo -e "${AMARILLO}    Contrasenas: $f_passwords${RESET}"
    echo -e "${AMARILLO}    Threads: $THREADS | Delay: ${DELAY}s | Timeout: ${TIMEOUT_HYDRA}s${RESET}\n"

    local salida_hydra
    salida_hydra=$(timeout "$TIMEOUT_HYDRA" \
        hydra -L "$f_usuarios" -P "$f_passwords" \
              "$ip" "$modulo" -s "$puerto" \
              -I -t "$THREADS" -W "$DELAY" -vV 2>&1)

    local intentos
    intentos=$(echo "$salida_hydra" | grep -ic "trying")

    # Extraer credenciales: hydra las imprime como "[puerto][modulo] host: X   login: Y   password: Z"
    local creds_raw
    creds_raw=$(echo "$salida_hydra" | grep -iE "^\[.+\].+login:.+password:")

    local resultado color_res
    if [ -n "$creds_raw" ]; then
        resultado="CRITICO: Credenciales validas encontradas."
        color_res="$ROJO"

        echo -e "${ROJO}╔══════════════════════════════════════════════╗${RESET}"
        echo -e "${ROJO}║       *** ACCESO CONSEGUIDO ***              ║${RESET}"
        echo -e "${ROJO}╚══════════════════════════════════════════════╝${RESET}"
        echo -e "${ROJO}  Servicio : $modulo  |  Host: $ip:$puerto${RESET}"
        echo -e "${ROJO}  Intentos : $intentos${RESET}"
        echo -e "${ROJO}────────────────────────────────────────────────${RESET}"
        echo -e "${ROJO}  CREDENCIALES VALIDAS:${RESET}\n"

        local n=1
        while IFS= read -r linea; do
            local usr pass
            usr=$(echo "$linea" | grep -oP '(?<=login: )\S+')
            pass=$(echo "$linea" | grep -oP '(?<=password: )\S+')
            if [ -n "$usr" ] && [ -n "$pass" ]; then
                echo -e "${AMARILLO}  [$n] Usuario   : $usr${RESET}"
                echo -e "${AMARILLO}      Contrasena: $pass${RESET}"
                echo -e "${ROJO}  ──────────────────────────────────────────${RESET}"
                ((n++))
            fi
        done <<< "$creds_raw"

    elif echo "$salida_hydra" | grep -Eqi "too many connections|blocked|rate limit|connection reset"; then
        resultado="PROTEGIDO: Sistema bloqueo el ataque."
        color_res="$VERDE"
        echo -e "${VERDE}╔══════════════════════════════════════════════╗${RESET}"
        echo -e "${VERDE}║   [OK] SISTEMA PROTEGIDO                     ║${RESET}"
        echo -e "${VERDE}╚══════════════════════════════════════════════╝${RESET}"
        echo -e "${VERDE}  El sistema bloqueo el ataque activamente.${RESET}"
        echo -e "${VERDE}  Intentos realizados: $intentos${RESET}"

    elif [ "$intentos" -eq 0 ]; then
        resultado="INDETERMINADO: Hydra no realizo intentos."
        color_res="$AMARILLO"
        echo -e "${AMARILLO}╔══════════════════════════════════════════════╗${RESET}"
        echo -e "${AMARILLO}║   [?] SIN INTENTOS REGISTRADOS               ║${RESET}"
        echo -e "${AMARILLO}╚══════════════════════════════════════════════╝${RESET}"
        echo -e "${AMARILLO}  Posibles causas:${RESET}"
        echo -e "${AMARILLO}    - El servicio no respondio al modulo '$modulo'${RESET}"
        echo -e "${AMARILLO}    - Puerto incorrecto o servicio incompatible${RESET}"
        echo -e "${AMARILLO}    - Conexion rechazada antes de autenticar${RESET}"

    else
        resultado="VULNERABLE: $intentos intentos sin bloqueo detectado."
        color_res="$AMARILLO"
        echo -e "${AMARILLO}╔══════════════════════════════════════════════╗${RESET}"
        echo -e "${AMARILLO}║   [!] SIN BLOQUEO DETECTADO                  ║${RESET}"
        echo -e "${AMARILLO}╚══════════════════════════════════════════════╝${RESET}"
        echo -e "${AMARILLO}  $intentos intentos sin rate limiting detectado.${RESET}"
        echo -e "${AMARILLO}  No se encontraron credenciales en el diccionario.${RESET}"
    fi

    # Escribir informe
    {
        echo "==================================================="
        echo "Fecha:        $fecha"
        echo "IP objetivo:  $ip"
        echo "Puerto:       $puerto"
        echo "Modulo hydra: $modulo"
        echo "Usuarios:     $f_usuarios"
        echo "Contrasenas:  $f_passwords"
        echo "Intentos:     $intentos"
        echo "Resultado:    $resultado"
        if [ -n "$creds_raw" ]; then
            echo ""
            echo "--- CREDENCIALES ENCONTRADAS ---"
            local n=1
            while IFS= read -r linea; do
                local usr pass
                usr=$(echo "$linea" | grep -oP '(?<=login: )\S+')
                pass=$(echo "$linea" | grep -oP '(?<=password: )\S+')
                if [ -n "$usr" ] && [ -n "$pass" ]; then
                    echo "  [$n] Usuario: $usr  |  Contrasena: $pass"
                    ((n++))
                fi
            done <<< "$creds_raw"
        fi
        echo ""
        echo "--- Evidencia hydra (ultimas 20 lineas) ---"
        echo "$salida_hydra" | tail -n 20
        echo ""
    } >> "$INFORME"

    echo -e "\n${color_res}[+] Resultado guardado en: $INFORME${RESET}"
}

# ── Bucle principal ──────────────────────────────────────────

main() {
    banner

    if [ $# -ne 1 ]; then
        echo -e "${AMARILLO}Uso: $0 <IP | RANGO CIDR>${RESET}"
        echo -e "  Ejemplo: $0 192.168.1.10"
        echo -e "  Ejemplo: $0 192.168.1.0/24"
        exit 1
    fi

    local objetivo=$1

    verificar_root
    verificar_dependencias

    {
        echo "==================================================="
        echo "  INFORME DE AUDITORIA"
        echo "  Objetivo: $objetivo"
        echo "  Inicio:   $(date '+%Y-%m-%d %H:%M:%S')"
        echo "==================================================="
        echo ""
    } > "$INFORME"

    escanear_puertos "$objetivo" || exit 1

    while true; do
        mostrar_menu
        pedir_seleccion

        local ip puerto modulo
        ip=$(echo "$SELECCION"     | cut -d: -f1)
        puerto=$(echo "$SELECCION" | cut -d: -f2)
        modulo=$(echo "$SELECCION" | cut -d: -f3)

        pedir_ficheros "$ip" "$puerto" "$modulo"
        ejecutar_ataque "$ip" "$puerto" "$modulo" "$F_USUARIOS" "$F_PASSWORDS"

        echo ""
        read -rp "$(echo -e "${AZUL}Atacar otro objetivo del escaneo? [s/N]:${RESET} ")" continuar
        [[ "${continuar,,}" == "s" ]] || break
    done

    echo -e "\n${VERDE}[+] Auditoria finalizada. Informe guardado en: ${INFORME}${RESET}\n"
}

main "$@"
