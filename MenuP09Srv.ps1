. .\FunSrv.ps1
. .\FunP09Srv.ps1
#Requires -RunAsAdministrator
# ============================================================
# MENU INTERACTIVO - PRACTICA 09
# ============================================================
function Show-MenuP09 {
    Clear-Host
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "   PRACTICA 09 - MENU PRINCIPAL" -ForegroundColor Cyan
    Write-Host "   Seguridad, Delegacion y MFA" -ForegroundColor Cyan
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1]  FLUJO COMPLETO P09 (RBAC + FGPP + Auditoria)" -ForegroundColor White
    Write-Host "  -----------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  --- RBAC y DELEGACION ---" -ForegroundColor Gray
    Write-Host "  [2]  Crear usuarios admin delegados" -ForegroundColor Gray
    Write-Host "  [3]  Aplicar delegacion RBAC (dsacls)" -ForegroundColor Gray
    Write-Host "  [4]  Verificar ACLs y delegacion" -ForegroundColor Gray
    Write-Host "  -----------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  --- FGPP y CONTRASENAS ---" -ForegroundColor Gray
    Write-Host "  [5]  Configurar FGPP (politicas de contrasena)" -ForegroundColor Gray
    Write-Host "  [6]  Verificar FGPP aplicadas" -ForegroundColor Gray
    Write-Host "  -----------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  --- AUDITORIA ---" -ForegroundColor Gray
    Write-Host "  [7]  Habilitar auditoria de eventos" -ForegroundColor Gray
    Write-Host "  [8]  Generar reporte accesos denegados (Script)" -ForegroundColor Gray
    Write-Host "  -----------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  --- MFA (multiOTP + Google Authenticator) ---" -ForegroundColor Gray
    Write-Host "  Nota:    Instalar multiOTP Credential Provider con el .msi" -ForegroundColor Gray
    Write-Host "  [MFA-1]  Registrar usuario en multiOTP (generar QR)" -ForegroundColor Gray
    Write-Host "  [MFA-2]  Verificar codigo TOTP de un usuario" -ForegroundColor Gray
    Write-Host "  [MFA-3]  Configurar lockout MFA (3 intentos / 30 min)" -ForegroundColor Gray
    Write-Host "  [MFA-4]  Ver estado de multiOTP" -ForegroundColor Gray
    Write-Host "  -----------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  [9]  Verificacion final completa P09" -ForegroundColor Green
    Write-Host "  [0]  Salir" -ForegroundColor Red
    Write-Host ""
}

do {
    Show-MenuP09
    $opcion = Read-Host "  Selecciona una opcion"

    switch ($opcion) {
        "1" {
            Write-Host "`n>> Ejecutando flujo completo P09..." -ForegroundColor Cyan
            Import-Module ActiveDirectory, GroupPolicy
            Invoke-ConfigurarP09
        }
        "2" {
            Write-Host "`n>> Creando usuarios admin delegados..." -ForegroundColor Cyan
            Import-Module ActiveDirectory
            New-UsuariosAdmin
        }
        "3" {
            Write-Host "`n>> Aplicando delegacion RBAC con dsacls..." -ForegroundColor Cyan
            Import-Module ActiveDirectory
            Set-DelegacionRBAC
        }
        "4" {
            Write-Host "`n>> Verificando ACLs y delegacion..." -ForegroundColor Cyan
            Import-Module ActiveDirectory
            Show-VerificacionRBAC
        }
        "5" {
            Write-Host "`n>> Configurando FGPP..." -ForegroundColor Cyan
            Import-Module ActiveDirectory
            New-PoliticasContrasena
        }
        "6" {
            Write-Host "`n>> Verificando FGPP..." -ForegroundColor Cyan
            Import-Module ActiveDirectory
            Show-VerificacionFGPP
        }
        "7" {
            Write-Host "`n>> Habilitando auditoria de eventos..." -ForegroundColor Cyan
            Set-AuditoriaEventos
        }
        "8" {
            Write-Host "`n>> Generando reporte de accesos denegados..." -ForegroundColor Cyan
            Get-ReporteAccesosDenegados
        }
        "MFA-1" {
            Write-Host "`n>> Instalando multiOTP Credential Provider..." -ForegroundColor Cyan
            Install-MultiOTP
        }
        "MFA-1" {
            $usr = Read-Host "  Nombre de usuario a registrar (ej: Administrator)"
            Write-Host "`n>> Registrando $usr en multiOTP..." -ForegroundColor Cyan
            Set-MultiOTPUsuario -Usuario $usr
        }
        "MFA-2" {
            $usr  = Read-Host "  Nombre de usuario"
            $code = Read-Host "  Codigo TOTP de Google Authenticator (6 digitos)"
            Write-Host "`n>> Verificando codigo..." -ForegroundColor Cyan
            Test-MultiOTPCodigo -Usuario $usr -CodigoTOTP $code
        }
        "MFA-3" {
            Write-Host "`n>> Configurando lockout MFA (3 intentos / 30 min)..." -ForegroundColor Cyan
            Set-MultiOTPLockout
        }
        "MFA-4" {
            Write-Host "`n>> Estado de multiOTP..." -ForegroundColor Green
            Show-EstadoMFA
        }
        "9" {
            Write-Host "`n>> Ejecutando verificacion final P09..." -ForegroundColor Green
            Import-Module ActiveDirectory
            Invoke-VerificacionFinalP09
        }
        "0" {
            Write-Host "`nSaliendo..." -ForegroundColor Red
            break
        }
        default {
            Write-Host "`nOpcion no valida." -ForegroundColor Red
        }
    }

    if ($opcion -ne "0") {
        Write-Host "`nPresiona ENTER para volver al menu..." -ForegroundColor DarkGray
        Read-Host | Out-Null
    }

} while ($opcion -ne "0")
