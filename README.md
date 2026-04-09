# Auto-Auditoria de Fuerza Bruta (Brute-Force Auditor)

![Bash](https://img.shields.io/badge/Language-Bash-4EAA25?style=for-the-badge&logo=gnu-bash&logoColor=white)
![Linux](https://img.shields.io/badge/OS-Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![Pentesting](https://img.shields.io/badge/Type-Pentesting_Tool-D32121?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-2.1-blue?style=for-the-badge)

Script interactivo y automatizado escrito en **Bash** para la auditoría de seguridad y pruebas de penetración (*pentesting*). Unifica el poder de **Nmap** (reconocimiento y fingerprinting) e **Hydra** (explotación) en una única herramienta con interfaz de consola amigable.

Diseñado originalmente como proyecto de ampliación para el módulo de **Hacking Ético**.

---

## Características Principales

- **Escaneo Inteligente (Fingerprinting):** Utiliza Nmap (`-sV`) para escanear puertos y detectar versiones exactas de servicios.
- **Mapeo Automático de Módulos:** Traduce automáticamente el servicio detectado por Nmap al módulo correspondiente que necesita Hydra (ej: `http-alt` -> `http-get`, `microsoft-ds` -> `smb`).
- **Interfaz Interactiva:** Muestra una tabla visual con los puertos abiertos y permite al auditor seleccionar exactamente qué servicio atacar.
- **Control de Impacto:** Permite controlar los hilos (*threads*), los retrasos (*delay*) y el tiempo de espera (*timeout*) para evitar causar denegaciones de servicio (DoS) involuntarias o ser baneado por IPS/IDS.
- **Generación de Informes:** Genera automáticamente un reporte final (`informe_auditoria_FECHA.txt`) documentando la fecha, IP, servicio, número de intentos, vulnerabilidad detectada y credenciales expuestas.
- **Parseo Robusto:** Usa un micro-script integrado en Python3 para parsear la salida XML de Nmap de forma segura y fiable, evitando los falsos positivos del comando `grep`.

## Requisitos Previos

El script verificará e intentará instalar las dependencias automáticamente (si se ejecuta con privilegios), pero se recomienda tener instalados:

- Sistema operativo Linux (Probado en Ubuntu y Kali Linux).
- `nmap`
- `hydra`
- `python3` (Preinstalado en la mayoría de distribuciones modernas).

## Instalación

Clona el repositorio y asigna permisos de ejecución al script:

```bash
git clone https://github.com/TU_USUARIO/TU_REPOSITORIO.git
cd TU_REPOSITORIO
chmod +x auditoria.sh
```

## Modo de Uso

El script requiere que se proporcione como argumento una dirección IP objetivo o un rango de red (CIDR).

**Ejemplo contra una sola IP:**
```bash
sudo ./auditoria.sh 192.168.1.50
```

**Ejemplo contra un segmento de red:**
```bash
sudo ./auditoria.sh 192.168.1.0/24
```

### Flujo de Trabajo:
1. El script escaneará de forma silenciosa el objetivo.
2. Desplegará un menú interactivo con los servicios atacables encontrados.
3. Solicitará las rutas absolutas o relativas hacia los diccionarios de usuarios y contraseñas (ej: `usuarios.txt`, `rockyou.txt`).
4. Lanzará el ataque y mostrará por pantalla si logró acceso o si el sistema bloqueó la intrusión.
5. Guardará todas las evidencias en el archivo de informe local de manera automática.


## ⚠️ Aviso Legal (Disclaimer)

Esta herramienta ha sido desarrollada **estrictamente con fines educativos y académicos** para la asignatura de Hacking Ético. 

El uso de esta herramienta para atacar objetivos sin el consentimiento mutuo previo es ilegal. Es responsabilidad exclusiva del usuario final obedecer todas las leyes locales, estatales y federales aplicables. El desarrollador asume **cero responsabilidad** y no se hace cargo de ningún mal uso o daño causado por este programa.

---
**Desarrollado por [Tu Nombre / Nickname]**  
*Inspirado en estructuras de scripting de @K1K04.*
