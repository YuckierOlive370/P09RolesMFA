#!/bin/bash
source ./FunCliente.sh
VerificarRoot
# ============================================================
# MENU INTERACTIVO
# ============================================================
mostrar_menu() {
    clear
    echo "============================================="
    echo "  TAREA 08 - CLIENTE DEBIAN - MENU PRINCIPAL"
    echo "============================================="
    echo ""
    echo "  [1]  FLUJO COMPLETO (configuracion de inicio a fin)"
    echo "  ---------------------------------------------"
    echo "  [2]  Solo: Configurar DNS"
    echo "  [3]  Solo: Instalar paquetes"
    echo "  [4]  Solo: Configurar Kerberos"
    echo "  [5]  Solo: Unirse al dominio"
    echo "  [6]  Solo: Configurar SSSD"
    echo "  [7]  Solo: Configurar sudoers"
    echo "  [8]  Solo: Configurar PAM mkhomedir"
    echo "  [9]  Solo: Configurar PAM Mount (perfil movil SMB)"
    echo "  [9r] REPARAR PAM Mount (error 126 / krb5i -> ntlmssp)"
    echo "  [10] Solo: Script montaje manual de perfil"
    echo "  [11] Solo: Reiniciar SSSD"
    echo "  ---------------------------------------------"
    echo "  [12] Mostrar evidencia para la rubrica"
    echo "  [0]  Salir"
    echo ""
}

while true; do
    mostrar_menu
    read -rp "  Selecciona una opcion: " opcion

    case "$opcion" in
        1)
            echo ""
            echo ">> Ejecutando flujo completo..."
            instalar_todo
            ;;
        2)
            echo ""
            echo ">> Configurando DNS..."
            configurar_dns
            ;;
        3)
            echo ""
            echo ">> Instalando paquetes..."
            instalar_paquetes
            ;;
        4)
            echo ""
            echo ">> Configurando Kerberos..."
            configurar_kerberos
            ;;
        5)
            echo ""
            echo ">> Uniendo al dominio..."
            unir_dominio
            ;;
        6)
            echo ""
            echo ">> Configurando SSSD..."
            configurar_sssd
            ;;
        7)
            echo ""
            echo ">> Configurando sudoers..."
            configurar_sudoers
            ;;
        8)
            echo ""
            echo ">> Configurando PAM mkhomedir..."
            configurar_pam_mkhomedir
            ;;
        9)
            echo ""
            echo ">> Configurando PAM Mount para perfil movil SMB..."
            configurar_pam_mount
            ;;
        9r)
            echo ""
            echo ">> Reparando PAM Mount (sec=krb5i -> sec=ntlmssp)..."
            reparar_pam_mount
            ;;
        10)
            echo ""
            echo ">> Creando script de montaje manual..."
            configurar_montaje_manual
            echo ""
            echo "Uso: montar-perfil.sh <usuario>"
            ;;
        11)
            echo ""
            echo ">> Reiniciando SSSD..."
            reiniciar_sssd
            ;;
        12)
            echo ""
            echo ">> Mostrando evidencia..."
            mostrar_evidencia
            ;;
        0)
            echo ""
            echo "Saliendo..."
            exit 0
            ;;
        *)
            echo ""
            echo "Opcion no valida."
            ;;
    esac

    echo ""
    read -rp "Presiona ENTER para volver al menu..." _
done
