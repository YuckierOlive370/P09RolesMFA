#!/bin/bash

# ============================================================
# VARIABLES GLOBALES
# ============================================================
DC_IP="192.168.32.3"
DOMINIO="dominio.local"
REALM="DOMINIO.LOCAL"
ADMIN_PASS="Admin@12345!"
SERVIDOR_NOMBRE="SRV-DC"                        # Nombre NetBIOS del servidor Windows
PERFILES_SHARE="Perfiles\$"                     # Share de perfiles moviles (oculto con $)
MOUNT_BASE="/mnt/perfiles"                      # Punto de montaje local en el cliente Linux

# ---------------------------------------- Funciones ----------------------------------------
VerificarRoot() {
    if [ "$EUID" -ne 0 ]; then
        echo "Este script debe ejecutarse como root"
        exit 1
    fi
}

configurar_dns() {
    echo "[+] Configurando DNS hacia el DC ($DC_IP)..."
    cat > /etc/resolv.conf << EOF
nameserver $DC_IP
search $DOMINIO
domain $DOMINIO
EOF
    chattr +i /etc/resolv.conf
    if host "$DOMINIO" &>/dev/null; then
        echo "    DNS OK: $DOMINIO resuelto correctamente"
    else
        echo "    ERROR: No se puede resolver $DOMINIO"; return 1
    fi
}

instalar_paquetes() {
    echo "[+] Instalando paquetes..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y \
        realmd sssd sssd-tools adcli \
        samba-common samba-common-bin \
        krb5-user libpam-sss libnss-sss libsss-sudo \
        oddjob oddjob-mkhomedir packagekit \
        cifs-utils keyutils                         # <-- necesario para montar SMB
    echo "    Paquetes instalados"
}

configurar_kerberos() {
    echo "[+] Configurando Kerberos..."
    cat > /etc/krb5.conf << EOF
[libdefaults]
    default_realm = $REALM
    dns_lookup_realm = false
    dns_lookup_kdc = true

[realms]
    $REALM = {
        kdc = $DC_IP
        admin_server = $DC_IP
        default_domain = $DOMINIO
    }

[domain_realm]
    .$DOMINIO = $REALM
    $DOMINIO  = $REALM
EOF
    echo "    Kerberos configurado (realm: $REALM)"
}

unir_dominio() {
    echo "[+] Uniendo al dominio $DOMINIO..."
    echo "$ADMIN_PASS" | /usr/sbin/realm join --user=Administrator "$DOMINIO" -v
    if /usr/sbin/realm list | grep -q "$DOMINIO"; then
        echo "    Union completada"
    else
        echo "    ERROR: No se pudo unir al dominio"; return 1
    fi
}

configurar_sssd() {
    echo "[+] Configurando SSSD..."
    # fallback_homedir apunta a la carpeta local donde se montara el perfil movil.
    # El directorio real en el servidor es \\SERVIDOR\Perfiles$\<usuario>
    # En Linux se monta en /mnt/perfiles/<usuario> mediante pam_mount (ver configurar_pam_mount).
    # fallback_homedir = /mnt/perfiles/%u  coincide con el punto de montaje.
    cat > /etc/sssd/sssd.conf << EOF
[sssd]
domains = $DOMINIO
config_file_version = 2
services = nss, pam, sudo

[domain/$DOMINIO]
id_provider = ad
auth_provider = ad
access_provider = ad
ad_domain = $DOMINIO
krb5_realm = $REALM
fallback_homedir = /mnt/perfiles/%u
default_shell = /bin/bash
cache_credentials = true
ldap_id_mapping = true
ldap_referrals = false
use_fully_qualified_names = false
EOF
    chmod 600 /etc/sssd/sssd.conf
    echo "    sssd.conf configurado (home -> /mnt/perfiles/%u)"
}

configurar_sudoers() {
    echo "[+] Configurando sudoers..."
    cat > /etc/sudoers.d/ad-admins << EOF
%domain\ admins@$DOMINIO ALL=(ALL:ALL) ALL
EOF
    chmod 440 /etc/sudoers.d/ad-admins
    echo "    /etc/sudoers.d/ad-admins listo"
}

configurar_pam_mkhomedir() {
    echo "[+] Configurando PAM mkhomedir (crea /mnt/perfiles/<usuario> localmente si no existe)..."
    # mkhomedir crea el directorio local de montaje; pam_mount sincronizara el contenido
    if ! grep -q "pam_mkhomedir" /etc/pam.d/common-session; then
        echo "session required pam_mkhomedir.so skel=/etc/skel/ umask=0077" \
            >> /etc/pam.d/common-session
        echo "    PAM mkhomedir agregado"
    else
        echo "    PAM mkhomedir ya estaba configurado"
    fi
}

configurar_pam_mount() {
    echo "[+] Configurando pam_mount para montar perfil movil SMB al iniciar sesion..."

    apt-get install -y libpam-mount -qq

    mkdir -p "$MOUNT_BASE"
    chmod 755 "$MOUNT_BASE"

    # NOTA: se usa sec=ntlmssp en lugar de sec=krb5i porque pam_mount
    # se ejecuta en la fase "session" de PAM, ANTES de que sssd exporte
    # el ticket Kerberos al ccache del usuario.
    # Con sec=krb5i el kernel no encuentra el ticket -> error 126
    # "Required key not available".
    # Con sec=ntlmssp pam_mount usa %(PASSWORD) capturado en la fase auth.
    cat > /etc/security/pam_mount.conf.xml << EOF
<?xml version="1.0" encoding="utf-8" ?>
<!DOCTYPE pam_mount SYSTEM "pam_mount.conf.xml.dtd">
<pam_mount>

  <debug enable="0" />

  <volume
    user="*"
    fstype="cifs"
    server="$DC_IP"
    path="Perfiles\$/%(USER)"
    mountpoint="$MOUNT_BASE/%(USER)"
    options="sec=ntlmssp,username=%(USER),password=%(PASSWORD),domain=DOMINIO,uid=%(USERUID),gid=%(USERGID),forceuid,forcegid,dir_mode=0700,file_mode=0600,iocharset=utf8,vers=3.0"
  />

  <logout umount="1" />
  <mkmountpoint enable="1" remove="true" />

</pam_mount>
EOF

    # pam_mount necesita estar en common-auth para capturar la contrasena
    if ! grep -q "pam_mount" /etc/pam.d/common-auth; then
        echo "auth    optional    pam_mount.so" >> /etc/pam.d/common-auth
        echo "    pam_mount agregado a common-auth (captura de password)"
    else
        echo "    pam_mount ya estaba en common-auth"
    fi

    # pam_mount en common-session ejecuta el montaje real
    if ! grep -q "pam_mount" /etc/pam.d/common-session; then
        sed -i '1s/^/session optional    pam_mount.so\n/' /etc/pam.d/common-session
        echo "    pam_mount agregado a common-session (montaje)"
    else
        echo "    pam_mount ya estaba en common-session"
    fi

    echo "    pam_mount listo: sec=ntlmssp, monta en login, desmonta en logout"
    echo "    Share: //$DC_IP/Perfiles\$/<usuario>  ->  $MOUNT_BASE/<usuario>"
}

configurar_montaje_manual() {
    echo "[+] Creando script de montaje manual (para pruebas sin login grafico)..."
    mkdir -p "$MOUNT_BASE"

    cat > /usr/local/bin/montar-perfil.sh << 'SCRIPT'
#!/bin/bash
# Uso: montar-perfil.sh <usuario_ad>
# Monta el perfil movil del usuario desde el servidor Windows
USUARIO="$1"
DC_IP="192.168.32.3"
MOUNT_BASE="/mnt/perfiles"

if [ -z "$USUARIO" ]; then
    echo "Uso: $0 <usuario>"
    exit 1
fi

MOUNT_POINT="$MOUNT_BASE/$USUARIO"
mkdir -p "$MOUNT_POINT"

echo "Montando perfil movil de $USUARIO..."
mount -t cifs "//$DC_IP/Perfiles\$$USUARIO" "$MOUNT_POINT" \
    -o "sec=krb5i,uid=$(id -u $USUARIO),gid=$(id -g $USUARIO),dir_mode=0700,file_mode=0600" \
    && echo "  OK: Montado en $MOUNT_POINT" \
    || echo "  ERROR: Fallo el montaje. Verifica que tienes ticket Kerberos (kinit $USUARIO)"
SCRIPT

    chmod +x /usr/local/bin/montar-perfil.sh
    echo "    Script creado: /usr/local/bin/montar-perfil.sh <usuario>"
}


reparar_pam_mount() {
    echo "[+] Reparando pam_mount existente (krb5i -> ntlmssp)..."

    # 1. Reescribir el XML con sec=ntlmssp
    configurar_pam_mount

    # 2. Eliminar entradas viejas de pam_mount que puedan estar duplicadas
    #    (la instalacion anterior pudo haber dejado "pam_mount" en common-session
    #     pero sin la entrada en common-auth que necesita para capturar el password)
    echo "[+] Limpiando entradas PAM duplicadas..."
    # Contar cuantas veces aparece pam_mount en common-session
    COUNT=$(grep -c "pam_mount" /etc/pam.d/common-session 2>/dev/null || echo 0)
    if [ "$COUNT" -gt 1 ]; then
        echo "    Detectadas $COUNT entradas de pam_mount en common-session, limpiando..."
        # Eliminar todas y volver a agregar solo una
        sed -i '/pam_mount/d' /etc/pam.d/common-session
        sed -i '1s/^/session optional    pam_mount.so\n/' /etc/pam.d/common-session
        echo "    common-session: entrada unica restaurada"
    fi

    COUNT_AUTH=$(grep -c "pam_mount" /etc/pam.d/common-auth 2>/dev/null || echo 0)
    if [ "$COUNT_AUTH" -gt 1 ]; then
        sed -i '/pam_mount/d' /etc/pam.d/common-auth
        echo "auth    optional    pam_mount.so" >> /etc/pam.d/common-auth
        echo "    common-auth: entrada unica restaurada"
    fi

    # 3. Reiniciar sssd para que el cambio tome efecto
    reiniciar_sssd

    echo ""
    echo "    Reparacion completada. Prueba: su - cramirez"
    echo "    Si aun falla, revisa: dmesg | tail -20"
}

reiniciar_sssd() {
    echo "[+] Reiniciando sssd..."
    systemctl enable sssd
    systemctl restart sssd
    sleep 2
    if systemctl is-active --quiet sssd; then
        echo "    sssd: ACTIVO"
    else
        echo "    ERROR: sssd no activo"; systemctl status sssd --no-pager; return 1
    fi
}

mostrar_evidencia() {
    echo ""
    echo "========================================"
    echo "EVIDENCIA TAREA 08 - Cliente Debian"
    echo "Fecha: $(date)"
    echo "========================================"
    echo ""
    echo "--- 1. UNION AL DOMINIO ---"
    /usr/sbin/realm list
    echo ""
    echo "--- 2. USUARIOS AD RESUELTOS ---"
    id cramirez
    id smendez
    echo ""
    echo "--- 3. GRUPOS AD ---"
    getent group grupocuates
    getent group gruponocuates
    echo ""
    echo "--- 4. SSSD ACTIVO ---"
    systemctl is-active sssd
    echo ""
    echo "--- 5. SUDOERS AD ---"
    cat /etc/sudoers.d/ad-admins
    echo ""
    echo "--- 6. fallback_homedir (perfil movil) ---"
    grep fallback_homedir /etc/sssd/sssd.conf
    echo ""
    echo "--- 7. PAM MOUNT ---"
    grep -A3 "volume" /etc/security/pam_mount.conf.xml 2>/dev/null || echo "pam_mount no configurado"
    echo ""
    echo "--- 8. PUNTO DE MONTAJE BASE ---"
    ls -la "$MOUNT_BASE" 2>/dev/null || echo "$MOUNT_BASE no existe aun (se crea al primer login)"
    echo ""
    echo "--- 9. PROBAR LOGIN CON PERFIL MOVIL ---"
    echo "Ejecuta: su - cramirez"
    echo "El perfil se monta automaticamente desde \\\\$DC_IP\\Perfiles\$\\cramirez"
    echo "========================================"
}

instalar_todo() {
    configurar_dns          || exit 1
    instalar_paquetes       || exit 1
    configurar_kerberos
    unir_dominio            || exit 1
    configurar_sssd
    configurar_sudoers
    configurar_pam_mkhomedir
    configurar_pam_mount
    configurar_montaje_manual
    reiniciar_sssd          || exit 1
    mostrar_evidencia
}
