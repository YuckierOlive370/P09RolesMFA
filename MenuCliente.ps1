. .\FunCliente.ps1
#Requires -RunAsAdministrator
# ============================================================
# MENU INTERACTIVO
# ============================================================
function Show-Menu {
    Clear-Host
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "  TAREA 08 - CLIENTE WINDOWS - MENU PRINCIPAL" -ForegroundColor Cyan
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1]  FASE 1 - Unirse al dominio  ** REINICIA EL EQUIPO **" -ForegroundColor Yellow
    Write-Host "  [2]  FASE 2 - Configurar AppLocker (post-reinicio)" -ForegroundColor White
    Write-Host "  -----------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  [3]  Solo: Detectar interfaz de red" -ForegroundColor Gray
    Write-Host "  [4]  Solo: Configurar DNS hacia el DC" -ForegroundColor Gray
    Write-Host "  [5]  Solo: Verificar resolucion DNS" -ForegroundColor Gray
    Write-Host "  [6]  Solo: Obtener hashes de notepad" -ForegroundColor Gray
    Write-Host "  [7]  Solo: Generar XML de AppLocker" -ForegroundColor Gray
    Write-Host "  [8]  Solo: Aplicar politica AppLocker" -ForegroundColor Gray
    Write-Host "  [9]  Solo: Habilitar AppIDSvc" -ForegroundColor Gray
    Write-Host "  -----------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  [10] Ver resumen y politica efectiva" -ForegroundColor Green
    Write-Host "  [0]  Salir" -ForegroundColor Red
    Write-Host ""
}

do {
    Show-Menu
    $opcion = Read-Host "  Selecciona una opcion"

    switch ($opcion) {
        "1"  {
            Write-Host "`n>> El equipo se REINICIARA al unirse al dominio." -ForegroundColor Yellow
            $confirmar = Read-Host "   Confirmar? (S/N)"
            if ($confirmar -eq "S") { Invoke-UnirDominio }
        }
        "2"  {
            Write-Host "`n>> Configurando AppLocker (post-reinicio)..." -ForegroundColor Cyan
            Invoke-ConfigAppLocker
        }
        "3"  {
            Write-Host "`n>> Detectando interfaz de red..." -ForegroundColor Cyan
            Get-InterfazRed | Out-Null
        }
        "4"  {
            Write-Host "`n>> Configurando DNS hacia el DC..." -ForegroundColor Cyan
            $iface = Get-InterfazRed
            Set-DnsHaciasDC -Interfaz $iface
        }
        "5"  {
            Write-Host "`n>> Verificando resolucion DNS..." -ForegroundColor Cyan
            Test-ResolucionDominio | Out-Null
        }
        "6"  {
            Write-Host "`n>> Obteniendo hashes de notepad..." -ForegroundColor Cyan
            Get-HashesNotepad | Out-Null
        }
        "7"  {
            Write-Host "`n>> Generando XML de AppLocker..." -ForegroundColor Cyan
            $hashes = Get-HashesNotepad
            New-AppLockerXml -Hashes $hashes
        }
        "8"  {
            Write-Host "`n>> Aplicando politica AppLocker..." -ForegroundColor Cyan
            if (-not (Test-Path $Global:AppLockerXml)) {
                Write-Host "ERROR: XML no encontrado. Ejecuta opcion [7] primero." -ForegroundColor Red
            } else {
                Set-AppLockerPolicyLocal
            }
        }
        "9"  {
            Write-Host "`n>> Habilitando AppIDSvc..." -ForegroundColor Cyan
            Enable-AppIDSvc
        }
        "10" {
            Write-Host "`n>> Mostrando resumen y politica efectiva..." -ForegroundColor Green
            Show-ResumenAppLocker
        }
        "0"  {
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
