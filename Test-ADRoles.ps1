#Requires -Modules ActiveDirectory, GroupPolicy
<#
.SYNOPSIS
    Script de pruebas automatizadas para los 4 roles delegados en Active Directory.

.DESCRIPTION
    Ejecuta y valida los permisos de los roles:
      - admin_identidad  (IAM Operator)
      - admin_storage    (Storage Operator)
      - admin_politicas  (GPO Compliance)
      - admin_auditoria  (Security Auditor)

    Genera un reporte en C:\Logs\TestReport_<fecha>.txt con el resultado
    de cada prueba (PASS / FAIL / EXPECTED-FAIL).

.NOTES
    Ejecutar como Administrador del dominio en el Controlador de Dominio.
    Requiere RSAT: ActiveDirectory y GroupPolicy modules.
#>

# ============================================================
#  CONFIGURACION GLOBAL
# ============================================================
$Domain       = "dominio.local"
$DomainDN     = "DC=dominio,DC=local"
$OUCuates     = "OU=Cuates,$DomainDN"
$OUNoCuates   = "OU=NoCuates,$DomainDN"
$LogDir       = "C:\Logs"
$Timestamp    = Get-Date -Format "yyyyMMdd_HHmm"
$ReportFile   = "$LogDir\TestReport_$Timestamp.txt"
$TempUser     = "test_temp_$PID)"           # usuario temporal para pruebas

# Credenciales de cada rol (ajustar si el dominio usa otro nombre)
$Roles = @{
    IAM     = "admin_identidad"
    Storage = "admin_storage"
    GPO     = "admin_politicas"
    Audit   = "admin_auditoria"
}

# Usuarios de muestra existentes en el dominio
$UsersCuates   = @("cramirez","mlopez","jperez","atorres","lgomez")
$UsersNoCuates = @("smendez","dvargas","ecastro","pruiz","lsoto")

# ============================================================
#  INICIALIZACION
# ============================================================
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir | Out-Null }

$Results   = [System.Collections.Generic.List[PSCustomObject]]::new()
$PassCount = 0
$FailCount = 0
$WarnCount = 0

# ============================================================
#  FUNCIONES AUXILIARES
# ============================================================

function Write-Banner {
    param([string]$Title, [string]$Color = "Cyan")
    $line = "=" * 62
    Write-Host ""
    Write-Host $line -ForegroundColor $Color
    Write-Host ("  " + $Title) -ForegroundColor $Color
    Write-Host $line -ForegroundColor $Color
}

function Write-SectionHeader {
    param([string]$Text)
    Write-Host ""
    Write-Host "  -- $Text" -ForegroundColor Yellow
}

function Add-Result {
    param(
        [string]$Role,
        [string]$Test,
        [string]$Status,    # PASS | FAIL | EXPECTED-FAIL
        [string]$Detail = ""
    )

    $icon  = switch ($Status) {
        "PASS"          { "[+]" }
        "FAIL"          { "[X]" }
        "EXPECTED-FAIL" { "[~]" }
    }
    $color = switch ($Status) {
        "PASS"          { "Green"  }
        "FAIL"          { "Red"    }
        "EXPECTED-FAIL" { "DarkYellow" }
    }

    $line = "  $icon [$Role] $Test"
    if ($Detail) { $line += " — $Detail" }
    Write-Host $line -ForegroundColor $color

    $script:Results.Add([PSCustomObject]@{
        Rol    = $Role
        Prueba = $Test
        Estado = $Status
        Detalle= $Detail
    })

    switch ($Status) {
        "PASS"          { $script:PassCount++ }
        "FAIL"          { $script:FailCount++ }
        "EXPECTED-FAIL" { $script:WarnCount++ }
    }
}

# Ejecuta un bloque esperando exito
function Test-ShouldSucceed {
    param([string]$Role, [string]$Name, [scriptblock]$Action)
    try {
        & $Action | Out-Null
        Add-Result -Role $Role -Test $Name -Status "PASS"
    } catch {
        Add-Result -Role $Role -Test $Name -Status "FAIL" -Detail $_.Exception.Message
    }
}

# Ejecuta un bloque esperando fallo (Access Denied / Unauthorized)
function Test-ShouldFail {
    param([string]$Role, [string]$Name, [scriptblock]$Action)
    try {
        & $Action | Out-Null
        # Si NO lanza excepcion => la restriccion NO esta configurada => FAIL real
        Add-Result -Role $Role -Test $Name -Status "FAIL" `
            -Detail "ATENCION: operacion ejecutada sin error — revisar ACLs"
    } catch {
        Add-Result -Role $Role -Test $Name -Status "EXPECTED-FAIL" `
            -Detail "Acceso denegado correctamente"
    }
}

# Impersona un usuario del dominio para ejecutar el bloque
function Invoke-AsUser {
    param(
        [string]$UserName,
        [scriptblock]$Action
    )
    $script:cred = Get-Credential -UserName "$($UserName)@$Domain" `
        -Message "Ingresa la contrasena para $UserName"
    $job = Start-Job -ScriptBlock $Action -Credential $cred
    Wait-Job $job | Out-Null
    Receive-Job $job
    Remove-Job $job
}

# ============================================================
#  PRELUDIO: crear usuario temporal para pruebas de eliminacion
# ============================================================
function Initialize-TempUser {
    try {
        if (-not (Get-ADUser -Filter {SamAccountName -eq $TempUser} -ErrorAction SilentlyContinue)) {
            New-ADUser -Name "Temp Prueba" `
                -SamAccountName $TempUser `
                -UserPrincipalName "$TempUser@$Domain" `
                -Path $OUCuates `
                -AccountPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) `
                -Enabled $true
            Write-Host "  [i] Usuario temporal '$TempUser' creado." -ForegroundColor DarkGray
        }
    } catch {
        Write-Host "  [!] No se pudo crear el usuario temporal: $($_.Exception.Message)" -ForegroundColor DarkYellow
    }
}

function Remove-TempUser {
    try {
        if (Get-ADUser -Filter {SamAccountName -eq $TempUser} -ErrorAction SilentlyContinue) {
            Remove-ADUser -Identity $TempUser -Confirm:$false
            Write-Host "  [i] Usuario temporal '$TempUser' eliminado." -ForegroundColor DarkGray
        }
    } catch {}
}

# ============================================================
#  ROL 1 — IAM OPERATOR (admin_identidad)
# ============================================================
function Test-IAMOperator {
    $role = "IAM"
    Write-Banner "ROL 1: IAM Operator  [admin_identidad]"
    $script:cred  = Get-Credential -UserName "admin_identidad@$Domain" `
                -Message "Contrasena para admin_identidad"

    # --- DEBE FUNCIONAR ---
    Write-SectionHeader "Pruebas que DEBEN funcionar"

    # 1.1 Crear usuario en OU Cuates
    Test-ShouldSucceed -Role $role -Name "Crear usuario en OU Cuates" {
        $params = @{
            Name               = "Nuevo Cuate"
            SamAccountName     = "nuevo_cuate_test"
            UserPrincipalName  = "nuevo_cuate_test@Domain"
            Path               = $OUCuates
            AccountPassword    = (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force)
            Enabled            = $true
            Credential         = $script:cred
        }
        New-ADUser @params
    }

    # 1.2 Crear usuario en OU NoCuates
    Test-ShouldSucceed -Role $role -Name "Crear usuario en OU NoCuates" {
        $params = @{
            Name              = "Nuevo NoCuate"
            SamAccountName    = "nuevo_nocuate_test"
            UserPrincipalName = "nuevo_nocuate_test@Domain"
            Path              = $OUNoCuates
            AccountPassword   = (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force)
            Enabled           = $true
            Credential        = $script:cred
        }
        New-ADUser @params
    }

    # 1.3 Modificar atributos basicos — cramirez (Cuates)
    Test-ShouldSucceed -Role $role -Name "Modificar atributos basicos de cramirez (Cuates)" {
        Set-ADUser -Identity "cramirez" `
            -OfficePhone "555-1001" `
            -Office "Sala Cuates A" `
            -EmailAddress "yuji@Domain" `
            -Credential $script:cred
    }

    # 1.4 Modificar atributos basicos — smendez (NoCuates)
    Test-ShouldSucceed -Role $role -Name "Modificar atributos basicos de smendez (NoCuates)" {
        Set-ADUser -Identity "smendez" `
            -OfficePhone "555-2001" `
            -Office "Sala NoCuates B" `
            -Credential $script:cred
    }

    # 1.5 Resetear contrasena — mlopez
    Test-ShouldSucceed -Role $role -Name "Reset password de mlopez (Cuates)" {
        Set-ADAccountPassword -Identity "mlopez" `
            -NewPassword (ConvertTo-SecureString "NuevoP@ss123!" -AsPlainText -Force) `
            -Reset `
            -Credential $script:cred
    }

    # 1.6 Resetear contrasena — ecastro (NoCuates)
    Test-ShouldSucceed -Role $role -Name "Reset password de ecastro (NoCuates)" {
        Set-ADAccountPassword -Identity "ecastro" `
            -NewPassword (ConvertTo-SecureString "NuevoP@ss123!" -AsPlainText -Force) `
            -Reset `
            -Credential $script:cred
    }

    # 1.7 Desbloquear cuenta — jperez
    Test-ShouldSucceed -Role $role -Name "Desbloquear cuenta de nobara" {
        Unlock-ADAccount -Identity "jperez" -Credential $script:cred
    }

    # 1.8 Eliminar el usuario temporal creado al inicio
    Test-ShouldSucceed -Role $role -Name "Eliminar usuario temporal en OU Cuates" {
        Remove-ADUser -Identity $TempUser -Confirm:$false -Credential $script:cred
    }

    # Limpiar usuarios de prueba creados en 1.1 y 1.2
    try { Remove-ADUser -Identity "nuevo_cuate_test"   -Confirm:$false } catch {}
    try { Remove-ADUser -Identity "nuevo_nocuate_test" -Confirm:$false } catch {}

    # --- DEBE FALLAR ---
    Write-SectionHeader "Restricciones criticas (DEBEN fallar)"

    # 1.9 Agregar usuario a Domain Admins
    Test-ShouldFail -Role $role -Name "Agregar cramirez a Domain Admins [RESTRICCION]" {
        Add-ADGroupMember -Identity "Domain Admins" `
            -Members "cramirez" `
            -Credential $script:cred
    }

    # 1.10 Modificar configuracion de GPO
    Test-ShouldFail -Role $role -Name "Editar GPO Default Domain Policy [RESTRICCION]" {
        # Set-GPRegistryValue no acepta -Credential directamente.
        # Start-Job con -Credential lanza el bloque en un proceso aparte
        # con el contexto del rol, sin necesitar PSRemoting/WinRM.
        $job = Start-Job -Credential $script:cred -ScriptBlock {
            Import-Module GroupPolicy -ErrorAction Stop
            Set-GPRegistryValue -Name "Default Domain Policy" `
                -Key "HKLM\Software\TestRestriction" `
                -ValueName "IAMTest" `
                -Type String -Value "no-debe-escribir"
        }
        Wait-Job $job | Out-Null
        $jobResult = Receive-Job $job -ErrorVariable jobErr 2>&1
        Remove-Job $job
        # Si el job reporto error de acceso, propagarlo para que
        # Test-ShouldFail lo capture como EXPECTED-FAIL
        if ($jobErr) { throw $jobErr[0] }
    }
}

# ============================================================
#  ROL 2 — STORAGE OPERATOR (admin_storage)
# ============================================================
function Test-StorageOperator {
    $role = "STORAGE"
    Write-Banner "ROL 2: Storage Operator  [admin_storage]"
    $script:cred  = Get-Credential -UserName "admin_storage@$Domain" `
                -Message "Contrasena para admin_storage"

    # --- DEBE FUNCIONAR ---
    Write-SectionHeader "Pruebas que DEBEN funcionar"

    # Helper interno: ejecuta un bloque FSRM con las creds del rol.
    #
    # POR QUE Invoke-Command y no Start-Job:
    #   Start-Job -Credential crea un proceso local pero NO establece un token
    #   COM/WMI delegado: el proceso hereda la sesion del padre (Domain Admin)
    #   para llamadas COM, por eso FSRM siempre ve el token del Administrador
    #   y no el de admin_storage, devolviendo 0x80070005.
    #
    #   Invoke-Command -ComputerName localhost -Credential abre una sesion WinRM
    #   completa con el token de admin_storage, de modo que TODAS las llamadas
    #   COM/WMI (incluido FSRM) se realizan bajo ese usuario.
    #
    # PREREQUISITO (una sola vez como Admin si WinRM no esta activo):
    #   Enable-PSRemoting -Force
    #   Set-Item WSMan:\localhost\Client\TrustedHosts -Value "localhost" -Force
    function Invoke-FsrmAsStorage {
        param([string]$TestName, [scriptblock]$Block)
        try {
            Invoke-Command -ComputerName localhost `
                           -Credential $script:cred `
                           -ScriptBlock $Block `
                           -ErrorAction Stop | Out-Null
        } catch {
            throw $_
        }
    }



    # 2.1 Crear cuota en carpeta de usuario
    Test-ShouldSucceed -Role $role -Name "Crear cuota FSRM en C:\Perfiles\cramirez" {
        Invoke-FsrmAsStorage -TestName "Crear cuota" {
            $path = "C:\Perfiles\cramirez"
            if (-not (Test-Path $path)) { New-Item -ItemType Directory -Path $path -Force | Out-Null }
            if (Get-FsrmQuota -Path $path -ErrorAction SilentlyContinue) {
                Remove-FsrmQuota -Path $path -Confirm:$false
            }
            New-FsrmQuota -Path $path -Size 1GB -SoftLimit
        }
    }

    # 2.2 Modificar limite de cuota existente
    Test-ShouldSucceed -Role $role -Name "Modificar cuota FSRM de C:\Perfiles\cramirez a 2 GB" {
        Invoke-FsrmAsStorage -TestName "Modificar cuota" {
            Set-FsrmQuota -Path "C:\Perfiles\cramirez" -Size 2GB
        }
    }

    # 2.3 Listar cuotas configuradas
    Test-ShouldSucceed -Role $role -Name "Listar cuotas FSRM (Get-FsrmQuota)" {
        Invoke-FsrmAsStorage -TestName "Listar cuotas" {
            Get-FsrmQuota | Select-Object Path, Size | Out-Null
        }
    }

    # 2.4 Crear grupo de archivos prohibidos
    Test-ShouldSucceed -Role $role -Name "Crear FsrmFileGroup de archivos prohibidos" {
        Invoke-FsrmAsStorage -TestName "Crear FileGroup" {
            $nombre = "Archivos-Prohibidos-Test"
            if (-not (Get-FsrmFileGroup -Name $nombre -ErrorAction SilentlyContinue)) {
                New-FsrmFileGroup -Name $nombre `
                    -IncludePattern @("*.mp3","*.mp4","*.exe","*.iso","*.torrent")
            }
        }
    }

    # 2.5 Crear plantilla de file screening activa
    Test-ShouldSucceed -Role $role -Name "Crear FsrmFileScreenTemplate activa" {
        Invoke-FsrmAsStorage -TestName "Crear FileScreenTemplate" {
            $nombre = "Bloquear-Multimedia-Test"
            if (-not (Get-FsrmFileScreenTemplate -Name $nombre -ErrorAction SilentlyContinue)) {
                New-FsrmFileScreenTemplate -Name $nombre `
                    -Active -IncludeGroup @("Archivos-Prohibidos-Test")
            }
        }
    }

    # 2.6 Aplicar file screen a carpeta compartida
    Test-ShouldSucceed -Role $role -Name "Aplicar FileScreen a C:\Shares\Cuates" {
        Invoke-FsrmAsStorage -TestName "Aplicar FileScreen" {
            $path = "C:\Shares\Cuates"
            if (-not (Test-Path $path)) { New-Item -ItemType Directory -Path $path -Force | Out-Null }
            if (Get-FsrmFileScreen -Path $path -ErrorAction SilentlyContinue) {
                Remove-FsrmFileScreen -Path $path -Confirm:$false
            }
            New-FsrmFileScreen -Path $path -Template "Bloquear-Multimedia-Test"
        }
    }

    # 2.7 Generar reporte de uso de cuotas
    Test-ShouldSucceed -Role $role -Name "Generar reporte FSRM de uso de cuotas" {
        Invoke-FsrmAsStorage -TestName "Generar reporte" {
            $nombreReporte = "Reporte-Cuotas-Test"

            $reporteExistente = Get-FsrmStorageReport -Name $nombreReporte -ErrorAction SilentlyContinue
            if ($reporteExistente) {
                Write-Host "El reporte ya existía. Limpiando configuración anterior..." -ForegroundColor Yellow
                Remove-FsrmStorageReport -Name $nombreReporte -Confirm:$false
            }

            New-FsrmStorageReport -Name $nombreReporte `
                      -Namespace "C:\Perfiles" `
                      -ReportType QuotaUsage `
                      -ReportFormat Text `
                      -Interactive
        }
    }

    # --- DEBE FALLAR ---
    Write-SectionHeader "Restricciones criticas (DEBEN fallar)"

    # 2.8 Reset password sobre atorres (OU Cuates)
    Test-ShouldFail -Role $role -Name "Reset password de atorres — Deny ACL [RESTRICCION]" {
        Set-ADAccountPassword -Identity "atorres" `
            -NewPassword (ConvertTo-SecureString "Test123!" -AsPlainText -Force) `
            -Reset `
            -Credential $script:cred
    }

    # 2.9 Reset password sobre lsoto (OU NoCuates)
    Test-ShouldFail -Role $role -Name "Reset password de lsoto (NoCuates) — Deny ACL [RESTRICCION]" {
        Set-ADAccountPassword -Identity "lsoto" `
            -NewPassword (ConvertTo-SecureString "Test123!" -AsPlainText -Force) `
            -Reset `
            -Credential $script:cred
    }

    # 2.10 Crear usuario en AD (no es su rol)
    Test-ShouldFail -Role $role -Name "Crear usuario en AD — fuera de rol [RESTRICCION]" {
        New-ADUser -Name "Storage Usurpador" `
            -SamAccountName "storage_usurp" `
            -Path $OUCuates `
            -Credential $script:cred
    }
}

# ============================================================
#  ROL 3 — GPO COMPLIANCE (admin_politicas)
# ============================================================
function Test-GPOCompliance {
    $role = "GPO"
    Write-Banner "ROL 3: GPO Compliance  [admin_politicas]"
    $script:cred = Get-Credential -UserName "admin_politicas@$Domain" `
                -Message "Contrasena para admin_politicas"

    # Helper interno: ejecuta cmdlets GPO con creds del rol via Start-Job
    # (los cmdlets GroupPolicy no aceptan -Credential de forma nativa)
    function Invoke-GPOAsGPOAdmin {
        param([scriptblock]$Block)
        $job = Start-Job -Credential $script:cred -ScriptBlock $Block
        Wait-Job $job | Out-Null
        $jobErr = $null
        Receive-Job $job -ErrorVariable jobErr 2>&1 | Out-Null
        Remove-Job $job
        if ($jobErr) { throw $jobErr[0] }
    }

    Remove-GPLink -Name "Default Domain Policy" -Target $ouCuates -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    Remove-GPLink -Name "Default Domain Policy" -Target $OUNoCuates -Confirm:$false -ErrorAction SilentlyContinue | Out-Null

    # --- DEBE FUNCIONAR ---
    Write-SectionHeader "Pruebas que DEBEN funcionar"

    # 3.1 Lectura de usuarios en todo el dominio
    Test-ShouldSucceed -Role $role -Name "Listar usuarios del dominio (solo lectura)" {
        Get-ADUser -Filter * -Credential $script:cred | Select-Object Name | Out-Null
    }

    # 3.2 Lectura de GPOs existentes
    Test-ShouldSucceed -Role $role -Name "Listar GPOs del dominio (Get-GPO)" {
        Invoke-GPOAsGPOAdmin {
            Import-Module GroupPolicy
            Get-GPO -All | Select-Object DisplayName, Id | Out-Null
        }
    }

    # 3.3 Vincular GPO a OU Cuates
    Test-ShouldSucceed -Role $role -Name "Vincular Default Domain Policy a OU Cuates" {
        Invoke-GPOAsGPOAdmin {
            Import-Module GroupPolicy
            New-GPLink -Name "Default Domain Policy" `
                -Target "OU=Cuates,DC=dominio,DC=local" `
                -LinkEnabled Yes -ErrorAction Stop
        }
    }

    # 3.4 Vincular GPO a OU NoCuates
    Test-ShouldSucceed -Role $role -Name "Vincular Default Domain Policy a OU NoCuates" {
        Invoke-GPOAsGPOAdmin {
            Import-Module GroupPolicy
            New-GPLink -Name "Default Domain Policy" `
                -Target "OU=NoCuates,DC=dominio,DC=local" `
                -LinkEnabled Yes -ErrorAction Stop
        }
    }

    # 3.5 Desvincular GPO de OU Cuates
    Test-ShouldSucceed -Role $role -Name "Desvincular GPO de OU Cuates" {
        Invoke-GPOAsGPOAdmin {
            Import-Module GroupPolicy
            Remove-GPLink -Name "Default Domain Policy" `
                -Target "OU=Cuates,DC=dominio,DC=local" -ErrorAction Stop
        }
    }

    # 3.6 Modificar Logon Hours de lgomez
    Test-ShouldSucceed -Role $role -Name "Configurar Logon Hours de lgomez" {
        $horas = [byte[]]([byte]0) * 21
        Set-ADUser -Identity "lgomez" `
            -Replace @{logonHours=$horas} `
            -Credential $script:cred
    }

    # 3.7 Consultar FGPPs existentes
    Test-ShouldSucceed -Role $role -Name "Consultar Fine-Grained Password Policies" {
        Get-ADFineGrainedPasswordPolicy -Filter * -Credential $script:cred 
    }

    Remove-ADFineGrainedPasswordPolicySubject `
        -Identity "FGPP-Estandar" `
        -Subjects "atorres" `
        -Credential $script:cred `
        -Confirm:$false

    # 3.8 Aplicar FGPP a satoru
    Test-ShouldSucceed -Role $role -Name "Aplicar FGPP-Estandar a atorres" {
        Add-ADFineGrainedPasswordPolicySubject `
            -Identity "FGPP-Estandar" `
            -Subjects "atorres" `
            -Credential $script:cred
    }

    # 3.9 Verificar politica resultante
    Test-ShouldSucceed -Role $role -Name "Verificar politica resultante de cramirez (FGPP)" {
        Get-ADUserResultantPasswordPolicy -Identity "cramirez" `
            -Credential $script:cred | Out-Null
    }

    # --- DEBE FALLAR ---
    Write-SectionHeader "Restricciones criticas (DEBEN fallar)"

    # 3.10 Modificar atributo de usuario
    Test-ShouldFail -Role $role -Name "Modificar telefono de jperez (Write user) [RESTRICCION]" {
        Set-ADUser -Identity "jperez" `
            -OfficePhone "999-0000" `
            -Credential $script:cred
    }

    # 3.11 Crear nuevo usuario
    Test-ShouldFail -Role $role -Name "Crear usuario en OU Cuates [RESTRICCION]" {
        New-ADUser -Name "GPO Usurpador" `
            -SamAccountName "gpo_usurp" `
            -Path $OUCuates `
            -Credential $script:cred
    }

    # 3.12 Reset password de zenitsu
    Test-ShouldFail -Role $role -Name "Reset password de dvargas [RESTRICCION]" {
        Set-ADAccountPassword -Identity "dvargas" `
            -NewPassword (ConvertTo-SecureString "Test123!" -AsPlainText -Force) `
            -Reset `
            -Credential $script:cred
    }
}

# ============================================================
#  ROL 4 — SECURITY AUDITOR (admin_auditoria)
# ============================================================
function Test-SecurityAuditor {
    $role = "AUDIT"
    Write-Banner "ROL 4: Security Auditor  [admin_auditoria]"
    $script:cred = Get-Credential -UserName "admin_auditoria@$Domain" `
                -Message "Contrasena para admin_auditoria"

    # Helper interno: ejecuta cmdlets/binarios sin -Credential via Start-Job
    # (Get-WinEvent local, auditpol y Clear-EventLog no aceptan -Credential)
    function Invoke-AsAuditor {
        param([scriptblock]$Block)
        $job = Start-Job -Credential $script:cred -ScriptBlock $Block
        Wait-Job $job | Out-Null
        $jobErr = $null
        Receive-Job $job -ErrorVariable jobErr 2>&1 | Out-Null
        Remove-Job $job
        if ($jobErr) { throw $jobErr[0] }
    }

    # --- DEBE FUNCIONAR ---
    Write-SectionHeader "Pruebas que DEBEN funcionar"

    # 4.1 Leer Security Event Log
    Test-ShouldSucceed -Role $role -Name "Leer Security Event Log (ultimos 20 eventos)" {
        Invoke-AsAuditor {
            Get-WinEvent -LogName Security -MaxEvents 20 | Out-Null
        }
    }

    # 4.2 Filtrar eventos ID 4625 (logon fallido)
    Test-ShouldSucceed -Role $role -Name "Filtrar eventos 4625 (Logon Failed)" {
        Invoke-AsAuditor {
            Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} `
                -MaxEvents 10 -ErrorAction SilentlyContinue | Out-Null
        }
    }

    # 4.3 Filtrar eventos ID 4656 (acceso denegado a objeto)
    Test-ShouldSucceed -Role $role -Name "Filtrar eventos 4656 (Object Access Denied)" {
        Invoke-AsAuditor {
            Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4656} `
                -MaxEvents 10 -ErrorAction SilentlyContinue | Out-Null
        }
    }

    # 4.4 Consultar politica de auditoria actual
    Test-ShouldSucceed -Role $role -Name "Consultar auditpol (estado de auditoria)" {
        Invoke-AsAuditor {
            auditpol /get /category:"*" | Out-Null
        }
    }

    # 4.5 Verificar auditoria de acceso a objetos
    Test-ShouldSucceed -Role $role -Name "Verificar subcategoria Object Access en auditpol" {
        Invoke-AsAuditor {
            auditpol /get /category:"Object Access" | Out-Null
        }
    }

    # 4.6 Leer atributos de usuario en AD (solo lectura)
    Test-ShouldSucceed -Role $role -Name "Leer atributos de satoru en AD (lectura)" {
        Get-ADUser -Identity "atorres" `
            -Properties LastLogonDate, PasswordLastSet, LockedOut `
            -Credential $script:cred | Out-Null
    }

    # 4.7 Ejecutar script de extraccion de accesos denegados
    Test-ShouldSucceed -Role $role -Name "Ejecutar script Get-DeniedAccess.ps1" {
        Invoke-AsAuditor {
            $scriptPath = "C:\Scripts\Get-DeniedAccess.ps1"
            if (Test-Path $scriptPath) {
                & $scriptPath
            } else {

                Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 10 -ErrorAction SilentlyContinue |
                Select-Object TimeCreated, 
                            Id, 
                            @{Name='Usuario'; Expression={$_.Properties[5].Value}}, 
                            @{Name='Dominio'; Expression={$_.Properties[6].Value}},
                            @{Name='IP_Origen'; Expression={$_.Properties[19].Value}} | ft | 
                Out-File "C:\Logs\AccesosDenegados_$(Get-Date -Format 'yyyyMMdd_HHmm').txt" -Encoding UTF8
                # Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} `
                #     -MaxEvents 10 -ErrorAction SilentlyContinue |
                #     Select-Object TimeCreated, Id, Message |
                #     Out-File "C:\Logs\AccesosDenegados_$(Get-Date -Format 'yyyyMMdd_HHmm').txt" -Encoding UTF8
            }
        }
    }

    # --- DEBE FALLAR ---
    Write-SectionHeader "Restricciones criticas (DEBEN fallar)"

    # 4.8 Modificar cualquier usuario
    Test-ShouldFail -Role $role -Name "Set-ADUser sobre cramirez — Read-Only [RESTRICCION]" {
        Set-ADUser -Identity "cramirez" `
            -OfficePhone "000-0000" `
            -Credential $script:cred
    }

    # 4.9 Deshabilitar una categoria de auditoria
    Test-ShouldFail -Role $role -Name "Deshabilitar auditoria Logon [RESTRICCION]" {
        Invoke-AsAuditor {
            auditpol /set /subcategory:"Logon" /success:disable
        }
    }

    # 4.10 Limpiar el Security Log
    Test-ShouldFail -Role $role -Name "Clear-EventLog Security — Read-Only [RESTRICCION]" {
        Invoke-AsAuditor {
            Clear-EventLog -LogName Security
        }
    }

    # 4.11 Crear usuario en AD
    Test-ShouldFail -Role $role -Name "Crear usuario en AD [RESTRICCION]" {
        New-ADUser -Name "Auditor Usurpador" `
            -SamAccountName "audit_usurp" `
            -Path $OUCuates `
            -Credential $script:cred
    }

    # 4.12 Vincular GPO
    Test-ShouldFail -Role $role -Name "Vincular GPO — Read-Only [RESTRICCION]" {
        Invoke-AsAuditor {
            Import-Module GroupPolicy
            New-GPLink -Name "Default Domain Policy" `
                -Target "OU=Cuates,DC=dominio,DC=local" `
                -LinkEnabled Yes
        }
    }
}

# ============================================================
#  REPORTE FINAL
# ============================================================
function Write-FinalReport {
    Write-Banner "REPORTE FINAL DE PRUEBAS" "White"

    $total = $Results.Count
    Write-Host ""
    Write-Host ("  Total de pruebas : " + $total)         -ForegroundColor White
    Write-Host ("  PASS             : " + $PassCount)     -ForegroundColor Green
    Write-Host ("  EXPECTED-FAIL    : " + $WarnCount)     -ForegroundColor DarkYellow
    Write-Host ("  FAIL (errores)   : " + $FailCount)     -ForegroundColor Red
    Write-Host ""

    # Tabla por rol
    $Results | Group-Object Rol | ForEach-Object {
        Write-Host ("  Rol: " + $_.Name) -ForegroundColor Cyan
        $_.Group | ForEach-Object {
            $color = switch ($_.Estado) {
                "PASS"          { "Green"       }
                "EXPECTED-FAIL" { "DarkYellow"  }
                "FAIL"          { "Red"         }
            }
            $ico = switch ($_.Estado) {
                "PASS"          { "[+]" }
                "EXPECTED-FAIL" { "[~]" }
                "FAIL"          { "[X]" }
            }
            Write-Host ("    $ico " + $_.Prueba) -ForegroundColor $color
            if ($_.Detalle) {
                Write-Host ("        -> " + $_.Detalle) -ForegroundColor DarkGray
            }
        }
        Write-Host ""
    }

    # Advertencias de seguridad si alguna restriccion no funciono
    $fallosRestriccion = $Results | Where-Object {
        $_.Estado -eq "FAIL" -and $_.Prueba -like "*RESTRICCION*"
    }
    if ($fallosRestriccion) {
        Write-Host ""
        Write-Host "  [!] ADVERTENCIAS DE SEGURIDAD — Restricciones no aplicadas:" -ForegroundColor Red
        $fallosRestriccion | ForEach-Object {
            Write-Host ("      -> [" + $_.Rol + "] " + $_.Prueba) -ForegroundColor Red
        }
    }

    # Exportar a archivo TXT
    $reportContent = @"
========================================================
  REPORTE DE PRUEBAS DE ROLES AD
  Dominio  : $Domain
  Generado : $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')
  Servidor : $env:COMPUTERNAME
========================================================

RESUMEN
  Total pruebas    : $total
  PASS             : $PassCount
  EXPECTED-FAIL    : $WarnCount
  FAIL (errores)   : $FailCount

DETALLE POR PRUEBA
$(
    $Results | ForEach-Object {
        $ico = switch ($_.Estado) {
            "PASS"          { "[+]" }
            "EXPECTED-FAIL" { "[~]" }
            "FAIL"          { "[X]" }
        }
        "  $ico [{0}] {1}" -f $_.Rol, $_.Prueba
        if ($_.Detalle) { "       -> {0}" -f $_.Detalle }
    } | Out-String
)

LEYENDA
  [+] PASS          — Permiso funciono correctamente
  [~] EXPECTED-FAIL — Restriccion activa (comportamiento esperado)
  [X] FAIL          — Resultado inesperado (revisar configuracion)
========================================================
"@

    $reportContent | Out-File -FilePath $ReportFile -Encoding UTF8
    Write-Host ""
    Write-Host "  Reporte guardado en: $ReportFile" -ForegroundColor Cyan
}

# ============================================================
#  PUNTO DE ENTRADA PRINCIPAL
# ============================================================
Clear-Host
Write-Banner "SUITE DE PRUEBAS — ROLES DELEGADOS AD" "Magenta"
Write-Host "  Dominio  : $Domain"
Write-Host "  Servidor : $env:COMPUTERNAME"
Write-Host "  Fecha    : $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')"
Write-Host ""
Write-Host "  Se le pedira la contrasena de cada rol antes de sus pruebas." -ForegroundColor DarkGray
Write-Host ""

# Crear usuario temporal para prueba de eliminacion
Initialize-TempUser

# Ejecutar pruebas de cada rol
Test-IAMOperator
Test-StorageOperator
Test-GPOCompliance
Test-SecurityAuditor

    Write-Banner "VALIDACION FGPP — Politicas de contrasena ajustada"
 
    Write-SectionHeader "Pruebas que DEBEN fallar (restriccion de longitud minima)"
 
    # 5.1 Contrasena de 8 chars en cuenta admin_identidad (PSO-AdminPolicy exige 12)
    # Usamos complejidad correcta (mayus + minus + numero + simbolo = Cort@123)
    # para demostrar que el rechazo es por LONGITUD (8 < 12) y no por complejidad.
    Test-ShouldFail -Role $role -Name "Contrasena 8 chars en admin_identidad — PSO exige 12 [RESTRICCION]" {
        Write-Host "  [i] Intentando asignar contrasena de 8 caracteres a admin_identidad..." `
            -ForegroundColor Yellow
        $contrasenaCorta = ConvertTo-SecureString "Cort@123" -AsPlainText -Force
        Set-ADAccountPassword -Identity "admin_identidad" `
            -NewPassword $contrasenaCorta `
            -Reset:$true
    }

# Limpiar si quedaron usuarios temporales
Remove-TempUser

# Mostrar y exportar reporte final
Write-FinalReport