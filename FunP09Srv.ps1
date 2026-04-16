# ============================================================
# FunP09Srv.ps1 - PRACTICA 09
# Seguridad de Identidad, Delegacion y MFA
# Requiere que FunSrv.ps1 ya haya configurado el dominio (P08)
# ============================================================

# ============================================================
# VARIABLES GLOBALES P09
# ============================================================
$Global:DominioDN   = "DC=dominio,DC=local"
$Global:Dominio     = "dominio.local"
$Global:MultiOTPDir = "C:\Program Files\multiOTP"
$Global:AuditLog    = "C:\Scripts\auditoria_accesos.txt"

# ============================================================
# BLOQUE 0 - INSTALAR CARBON
# ============================================================

function Ensure-CarbonModule {
    $moduleName = "Carbon"
    
    # 1. Verificar si el módulo ya está cargado o instalado en el sistema
    if (Get-Module -ListAvailable -Name $moduleName) {
        Write-Host "El módulo '$moduleName' ya está instalado." -ForegroundColor Cyan
    } 
    else {
        Write-Host "El módulo '$moduleName' no se encontró. Iniciando instalación..." -ForegroundColor Yellow
        
        try {
            # 2. Asegurar que TLS 1.2 esté habilitado para descargar de PowerShell Gallery
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            
            # 3. Instalar el proveedor de paquetes NuGet si no existe (necesario para Install-Module)
            if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
                Write-Host "Instalando proveedor NuGet..." -ForegroundColor Gray
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
            }
            
            # 4. Instalar el módulo Carbon
            Write-Host "Descargando e instalando Carbon..." -ForegroundColor White
            Install-Module -Name $moduleName -AllowClobber -Force -Scope CurrentUser
            
            Write-Host "Módulo '$moduleName' instalado con éxito." -ForegroundColor Green
        } 
        catch {
            Write-Error "Error al intentar instalar el módulo: $($_.Exception.Message)"
            # return $false
        }
    }

    # 5. Importar el módulo para asegurar que los comandos estén disponibles
    Import-Module -Name $moduleName
    # return $true
}

# ============================================================
# BLOQUE 1 - RBAC: Usuarios administrativos delegados
# ============================================================

function New-UsuariosAdmin {
    Ensure-CarbonModule
    Import-Module ActiveDirectory
    Import-Module Carbon

    $admins = @(
        @{ Sam = "admin_identidad"; Nombre = "Admin Identidad";  Desc = "Rol 1 - IAM Operator" },
        @{ Sam = "admin_storage";   Nombre = "Admin Storage";    Desc = "Rol 2 - Storage Operator" },
        @{ Sam = "admin_politicas"; Nombre = "Admin Politicas";  Desc = "Rol 3 - GPO Compliance" },
        @{ Sam = "admin_auditoria"; Nombre = "Admin Auditoria";  Desc = "Rol 4 - Security Auditor" }
    )

    $pass = ConvertTo-SecureString "Admin.P09!Secure" -AsPlainText -Force
    $privilegio = "SeInteractiveLogonRight"

    foreach ($a in $admins) {
        if (-not (Get-ADUser -Filter "SamAccountName -eq '$($a.Sam)'" -ErrorAction SilentlyContinue)) {
            New-ADUser `
                -SamAccountName $a.Sam `
                -Name $a.Nombre `
                -UserPrincipalName "$($a.Sam)@$Global:Dominio" `
                -AccountPassword $pass `
                -Enabled $true `
                -Description $a.Desc `
                -Path "CN=Users,$Global:DominioDN"
            Write-Host "Creado: $($a.Sam)" -ForegroundColor Green
        } else {
            Write-Host "Ya existe: $($a.Sam)" -ForegroundColor Yellow
        }
    
        try {
            # Otorgar el privilegio
            Grant-CPrivilege -Identity $a.Sam -Privilege $privilegio
            Write-Host "Exito: Permiso de inicio de sesión local otorgado a $($a.Sam)" -ForegroundColor Green
            
            # Forzar actualización de políticas
            # gpupdate /force
        }
        catch {
            Write-Error "Hubo un problema al asignar el permiso: $_"
        }   
    }

    Write-Host "Actualizando politicas..." -ForegroundColor Cyan
    gpupdate /force

    # Grupo de seguridad para los 4 admins (lo usara la FGPP)
    if (-not (Get-ADGroup -Filter "Name -eq 'GrupoAdmins'" -ErrorAction SilentlyContinue)) {
        New-ADGroup -Name "GrupoAdmins" -GroupScope Global -GroupCategory Security `
            -Path "CN=Users,$Global:DominioDN" -Description "Administradores delegados P09"
        Write-Host "Grupo GrupoAdmins creado" -ForegroundColor Green
    }
    foreach ($a in $admins) {
        Add-ADGroupMember -Identity "GrupoAdmins" -Members $a.Sam -ErrorAction SilentlyContinue
    }
    Write-Host "Usuarios admin listos y en GrupoAdmins" -ForegroundColor Green
}


function Set-DelegacionRBAC {
    Import-Module ActiveDirectory

    $ouCuates   = "OU=Cuates,$Global:DominioDN"
    $ouNoCuates = "OU=NoCuates,$Global:DominioDN"

    Remove-ADGroupMember -Identity "Group Policy Creator Owners" -Members "admin_identidad" -Confirm:$false
    # Importamos el módulo por si acaso
    Import-Module GroupPolicy

    # Obtenemos todas las GPOs del dominio y les aplicamos el permiso
    Get-GPO -All | ForEach-Object {
        Set-GPPermission -Guid $_.Id -TargetName "admin_identidad" -TargetType User -PermissionLevel GpoRead | Out-Null
        
        # Esta línea es solo para que veas el progreso en pantalla
        Write-Host "Bloqueada la GPO: $($_.DisplayName)" -ForegroundColor Green
    }

    Write-Host "`n[ROL 1] Delegando admin_identidad en OUs..." -ForegroundColor Cyan

    foreach ($ou in @($ouCuates, $ouNoCuates)) {
        # Crear, modificar y eliminar usuarios
        & dsacls $ou /G "DOMINIO\admin_identidad:CCDC;user" | Out-Null
        # Permisos en todos los atributos
        & dsacls $ou /I:S /G "DOMINIO\admin_identidad:RPWP;;user"  | Out-Null
        # Reset de contrasena
        & dsacls $ou /I:S /G "DOMINIO\admin_identidad:CA;Reset Password;user" | Out-Null 

        # Desbloqueo de cuenta
        & dsacls $ou /I:S /G "DOMINIO\admin_identidad:RPWP;lockoutTime;user" | Out-Null  
        # Atributos basicos: telefono, oficina, correo
        & dsacls $ou /I:S /G "DOMINIO\admin_identidad:RPWP;telephoneNumber;user" | Out-Null       
        & dsacls $ou /I:S /G "DOMINIO\admin_identidad:RPWP;physicalDeliveryOfficeName;user" | Out-Null 
        & dsacls $ou /I:S /G "DOMINIO\admin_identidad:RPWP;mail;user" | Out-Null              
        Write-Host "  Permisos ROL 1 aplicados en: $ou" -ForegroundColor Green
    }

    Write-Host "`n[ROL 2] Aplicando DENY Reset Password a admin_storage..." -ForegroundColor Cyan
    foreach ($ou in @($ouCuates, $ouNoCuates)) {
        # DENY explicito - esto es lo que hace que el Test 1 falle con Acceso Denegado
        & dsacls $ou /I:S /D "DOMINIO\admin_storage:CA;Reset Password;user" | Out-Null

        # Denegar la escritura del atributo de última contraseña
        & dsacls $ou /I:S /D "DOMINIO\admin_storage:WP;pwdLastSet;user" | Out-Null
        # Denegar la escritura de contraseñas en general
        & dsacls $ou /I:S /D "DOMINIO\admin_storage:WP;userPassword;user" | Out-Null

        & dsacls $ou /D "DOMINIO\admin_storage:CCDC;user" | Out-Null    

        Write-Host "  DENY Reset Password aplicado en: $ou" -ForegroundColor Green
    }

    Add-ADGroupMember -Identity "Administrators" -Members "admin_storage"
    $acl = Get-Acl "C:\Users"
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("DOMINIO\admin_storage","FullControl","ContainerInherit,ObjectInherit","None","Allow")
    $acl.AddAccessRule($rule)
    Set-Acl "C:\Users" $acl

    Write-Host "`n[ROL 3] Configurando admin_politicas (GPO Compliance)..." -ForegroundColor Cyan
    # Permiso de lectura en todo el dominio
    & dsacls $Global:DominioDN /G "DOMINIO\admin_politicas:GR" | Out-Null
    # Se agrega a Group Policy Creator Owners para poder editar GPOs

    # Permisos para gestionar enlaces (Links) en la OU Cuates
    & dsacls $ouCuates /I:T /G "DOMINIO\admin_politicas:RPWP;gPLink" "DOMINIO\admin_politicas:RPWP;gPOptions" | Out-Null

    # Permisos para gestionar enlaces (Links) en la OU NoCuates
    & dsacls $ouNoCuates /I:T /G "DOMINIO\admin_politicas:RPWP;gPLink" "DOMINIO\admin_politicas:RPWP;gPOptions" | Out-Null

    & dsacls $ouCuates /I:S /G "DOMINIO\admin_politicas:RPWP;logonHours;user" | Out-Null
    & dsacls $ouNoCuates /I:S /G "DOMINIO\admin_politicas:RPWP;logonHours;user" | Out-Null

    # 1. Variables
    $usuarioPol = "DOMINIO\admin_politicas"
    $dominioDN = (Get-ADDomain).DistinguishedName
    $pscPath = "CN=Password Settings Container,CN=System,$dominioDN"

    Write-Host "Dando permisos en el contenedor de FGPP..." -ForegroundColor Yellow

    # 2. Permiso para VER (Leer) las políticas de contraseñas existentes
    # (RP = Read Property, msDS-PasswordSettings = Clase de objeto de las FGPP)
    & dsacls $pscPath /I:S /G "${usuarioPol}:RP;;msDS-PasswordSettings" | Out-Null

    # 3. Permiso para ASIGNAR/REMOVER usuarios a las políticas
    # (Permite leer y escribir específicamente en el atributo msDS-PSOAppliedTo)
    & dsacls $pscPath /I:S /G "${usuarioPol}:RPWP;msDS-PSOAppliedTo;msDS-PasswordSettings" | Out-Null

    # Otorgar Lectura y Escritura completa sobre todas las propiedades de las FGPP
    & dsacls $pscPath /I:S /G "${usuarioPol}:RPWP;;msDS-PasswordSettings" | Out-Null

    Add-ADGroupMember -Identity "Group Policy Creator Owners" -Members "admin_politicas" -ErrorAction SilentlyContinue
    Write-Host "  admin_politicas: lectura en dominio + Group Policy Creator Owners" -ForegroundColor Green

    Write-Host "`n[ROL 4] Configurando admin_auditoria (solo lectura)..." -ForegroundColor Cyan
    # Solo lectura en el dominio
    & dsacls $Global:DominioDN /G "DOMINIO\admin_auditoria:GR"  | Out-Null
    # Acceso al Security Event Log (via wevtutil sd)
    # Obtener el descriptor actual del canal Security
    $sddl = & wevtutil gl Security | Select-String "channelAccess" | ForEach-Object { $_ -replace "channelAccess: ","" }
    $sidAuditoria = (Get-ADUser "admin_auditoria").SID.Value
    # Agregar lectura (0x1) al SID del auditor
    $newAce = "(A;;0x1;;;$sidAuditoria)"
    if ($sddl -and -not ($sddl -match $sidAuditoria)) {
        $newSddl = $sddl + $newAce
        & wevtutil sl Security /ca:$newSddl 2>&1 | Out-Null
        Write-Host "  admin_auditoria: acceso lectura al Security Event Log" -ForegroundColor Green
    } else {
        Write-Host "  admin_auditoria: acceso al log ya configurado o SDDL no recuperado" -ForegroundColor Yellow
    }

    $usuarioAud = "admin_auditoria"
    $sid = (Get-ADUser -Identity $usuarioAud).SID.Value

    Write-Host "Aislando el SDDL puro e inyectando permisos..." -ForegroundColor Cyan

    # 1. Obtenemos el output crudo
    $sddlOutput = auditpol /get /sd

    # 2. Buscamos la línea que tiene el código (la que contiene "D:(")
    $sddlLine = ($sddlOutput | Where-Object { $_ -match "D:\(" }) -join ""

    # 3. LA CORRECCIÓN: Cortamos todo el texto basura que esté antes de la "D:"
    $sddl = $sddlLine.Substring($sddlLine.IndexOf("D:"))
    $sddl = $sddl.Trim()

    # 4. Si quedó algún rastro de nuestro SID de intentos fallidos, lo limpiamos
    if ($sddl -match $sid) {
        $sddl = $sddl -replace "\([^\)]*$sid\)", ""
    }

    # 5. Agregamos el permiso de lectura (GR) al final
    $nuevoSddl = $sddl + "(A;;GR;;;$sid)"

    Write-Host "SDDL limpio a inyectar: $nuevoSddl" -ForegroundColor DarkGray

    # 6. Guardamos los cambios en Windows
    auditpol /set /sd:$nuevoSddl | Out-Null

    Write-Host "¡Permiso inyectado con éxito sin errores de sintaxis!" -ForegroundColor Green

    Write-Host "`nDelegacion RBAC completada." -ForegroundColor Green
}


function Show-VerificacionRBAC {
    Write-Host "`n===== VERIFICACION RBAC =====" -ForegroundColor Magenta
    $ouCuates = "OU=Cuates,$Global:DominioDN"
    Write-Host "`nACL OU Cuates (filtrado por admins):" -ForegroundColor Yellow
    & dsacls $ouCuates | Where-Object { $_ -match "admin_" }
    Write-Host "`nMiembros de GrupoAdmins:" -ForegroundColor Yellow
    Get-ADGroupMember "GrupoAdmins" | Select-Object SamAccountName, Name | Format-Table -AutoSize
    Write-Host "`nGroup Policy Creator Owners:" -ForegroundColor Yellow
    Get-ADGroupMember "Group Policy Creator Owners" | Select-Object SamAccountName | Format-Table -AutoSize
}


# ============================================================
# BLOQUE 2 - FGPP: Directivas de contrasena ajustadas
# ============================================================

function New-PoliticasContrasena {
    Import-Module ActiveDirectory

    # --- Politica para administradores (12 caracteres) ---
    if (-not (Get-ADFineGrainedPasswordPolicy -Filter "Name -eq 'FGPP-Admins'" -ErrorAction SilentlyContinue)) {
        New-ADFineGrainedPasswordPolicy `
            -Name "FGPP-Admins" `
            -Precedence 10 `
            -MinPasswordLength 12 `
            -PasswordHistoryCount 10 `
            -ComplexityEnabled $true `
            -ReversibleEncryptionEnabled $false `
            -MaxPasswordAge "60.00:00:00" `
            -MinPasswordAge "1.00:00:00" `
            -LockoutThreshold 3 `
            -LockoutDuration "00:30:00" `
            -LockoutObservationWindow "00:30:00"
        Write-Host "FGPP-Admins creada (12 chars, lockout 3 intentos / 30 min)" -ForegroundColor Green
    } else {
        Write-Host "FGPP-Admins ya existe" -ForegroundColor Yellow
    }

    # Aplicar al grupo de administradores
    Add-ADFineGrainedPasswordPolicySubject -Identity "FGPP-Admins" -Subjects "GrupoAdmins" -ErrorAction SilentlyContinue
    Write-Host "FGPP-Admins -> GrupoAdmins" -ForegroundColor Green

    # --- Politica para usuarios estandar (8 caracteres) ---
    if (-not (Get-ADFineGrainedPasswordPolicy -Filter "Name -eq 'FGPP-Estandar'" -ErrorAction SilentlyContinue)) {
        New-ADFineGrainedPasswordPolicy `
            -Name "FGPP-Estandar" `
            -Precedence 20 `
            -MinPasswordLength 8 `
            -PasswordHistoryCount 5 `
            -ComplexityEnabled $true `
            -ReversibleEncryptionEnabled $false `
            -MaxPasswordAge "90.00:00:00" `
            -MinPasswordAge "0.00:00:00" `
            -LockoutThreshold 5 `
            -LockoutDuration "00:15:00" `
            -LockoutObservationWindow "00:15:00"
        Write-Host "FGPP-Estandar creada (8 chars, lockout 5 intentos / 15 min)" -ForegroundColor Green
    } else {
        Write-Host "FGPP-Estandar ya existe" -ForegroundColor Yellow
    }

    # Aplicar a Domain Users
    Add-ADFineGrainedPasswordPolicySubject -Identity "FGPP-Estandar" -Subjects "Domain Users" -ErrorAction SilentlyContinue
    Write-Host "FGPP-Estandar -> Domain Users" -ForegroundColor Green

    Write-Host "`nFGPP configuradas." -ForegroundColor Green
}


function Show-VerificacionFGPP {
    Write-Host "`n===== VERIFICACION FGPP =====" -ForegroundColor Magenta

    Write-Host "`nPoliticas existentes:" -ForegroundColor Yellow
    Get-ADFineGrainedPasswordPolicy -Filter * |
        Select-Object Name, Precedence, MinPasswordLength, LockoutThreshold,
            @{N="LockoutDuration";E={$_.LockoutDuration}},
            @{N="Sujetos";E={(Get-ADFineGrainedPasswordPolicySubject -Identity $_.Name).SamAccountName -join ", "}} |
        Format-Table -AutoSize

    Write-Host "`nPolitica efectiva para admin_identidad:" -ForegroundColor Yellow
    Get-ADUserResultantPasswordPolicy -Identity "admin_identidad" |
        Select-Object Name, MinPasswordLength, LockoutThreshold, LockoutDuration | Format-List

    Write-Host "`nPolitica efectiva para yuji (usuario estandar):" -ForegroundColor Yellow
    Get-ADUserResultantPasswordPolicy -Identity "yuji" |
        Select-Object Name, MinPasswordLength, LockoutThreshold, LockoutDuration | Format-List
}


# ============================================================
# BLOQUE 3 - AUDITORIA: Politicas y script de monitoreo
# ============================================================

function Set-AuditoriaEventos {
    Write-Host "[+] Configurando politicas de auditoria..." -ForegroundColor Cyan

    $subcategorias = @(
        @{ Cat = "Logon";                   Sub = "Logon" },
        @{ Cat = "Logon";                   Sub = "Logoff" },
        @{ Cat = "Account Logon";           Sub = "Kerberos Authentication Service" },
        @{ Cat = "Account Logon";           Sub = "Credential Validation" },
        @{ Cat = "Account Management";      Sub = "User Account Management" },
        @{ Cat = "Account Management";      Sub = "Security Group Management" },
        @{ Cat = "Object Access";           Sub = "File System" },
        @{ Cat = "Policy Change";           Sub = "Audit Policy Change" }
    )

    foreach ($s in $subcategorias) {
        & auditpol /set /subcategory:"$($s.Sub)" /success:enable /failure:enable | Out-Null
        Write-Host "  Auditoria habilitada: $($s.Sub)" -ForegroundColor Green
    }

    # Asegurar que el log de seguridad tenga suficiente tamano (256 MB)
    & wevtutil sl Security /ms:268435456 | Out-Null
    Write-Host "  Security Log: tamano establecido en 256 MB" -ForegroundColor Green

    Write-Host "Auditoria configurada." -ForegroundColor Green
}


function Get-ReporteAccesosDenegados {
    Write-Host "[+] Extrayendo eventos de acceso denegado..." -ForegroundColor Cyan

    New-Item -ItemType Directory -Path "C:\Scripts" -Force | Out-Null

    $eventos = Get-WinEvent -LogName Security -FilterXPath `
        "*[System[(EventID=4625 or EventID=4771 or EventID=4776)]]" `
        -MaxEvents 10 -ErrorAction SilentlyContinue

    if (-not $eventos) {
        Write-Host "  No se encontraron eventos de acceso denegado aun." -ForegroundColor Yellow
        Write-Host "  Genera intentos fallidos de login para poblar el log." -ForegroundColor Yellow
        return
    }

    $lineas = @()
    $lineas += "=" * 60
    $lineas += "REPORTE DE ACCESOS DENEGADOS - DOMINIO: $Global:Dominio"
    $lineas += "Generado: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $lineas += "Script ejecutado como: $env:USERNAME"
    $lineas += "=" * 60
    $lineas += ""

    $i = 1
    foreach ($ev in $eventos) {
        $xml = [xml]$ev.ToXml()
        $datos = $xml.Event.EventData.Data

        # Extraer campos segun el EventID
        $usuario    = ($datos | Where-Object { $_.Name -eq "TargetUserName"   }).'#text'
        $dominio    = ($datos | Where-Object { $_.Name -eq "TargetDomainName" }).'#text'
        $ip         = ($datos | Where-Object { $_.Name -eq "IpAddress"        }).'#text'
        $motivo     = ($datos | Where-Object { $_.Name -eq "SubStatus"        }).'#text'
        $logonType  = ($datos | Where-Object { $_.Name -eq "LogonType"        }).'#text'

        $motivos = @{
            "0xC000006A" = "Contrasena incorrecta"
            "0xC0000064" = "Usuario no existe"
            "0xC000006D" = "Credenciales invalidas"
            "0xC000006F" = "Fuera del horario de inicio de sesion"
            "0xC0000070" = "Estacion de trabajo no autorizada"
            "0xC0000072" = "Cuenta deshabilitada"
            "0xC000015B" = "Tipo de logon no concedido"
            "0xC0000234" = "Cuenta bloqueada"
        }
        $descripcionMotivo = if ($motivo -and $motivos[$motivo]) { $motivos[$motivo] } else { $motivo }

        $lineas += "[$i] EventID: $($ev.Id)"
        $lineas += "    Fecha/Hora: $($ev.TimeCreated)"
        $lineas += "    Usuario:    $usuario@$dominio"
        $lineas += "    IP origen:  $ip"
        $lineas += "    Tipo logon: $logonType"
        $lineas += "    Motivo:     $descripcionMotivo ($motivo)"
        $lineas += ""
        $i++
    }

    $lineas += "=" * 60
    $lineas += "Total eventos extraidos: $($eventos.Count)"
    $lineas += "=" * 60

    $lineas | Out-File -FilePath $Global:AuditLog -Encoding UTF8 -Force
    Write-Host "  Reporte guardado en: $Global:AuditLog" -ForegroundColor Green
    Write-Host ""
    $lineas | ForEach-Object { Write-Host $_ }
}


# ============================================================
# BLOQUE 4 - MFA: multiOTP Credential Provider
# ============================================================

function Invoke-MultiOTP {
    param([string[]]$Argumentos)
    $multiotpExe = "$Global:MultiOTPDir\multiotp.exe"
    Push-Location $Global:MultiOTPDir
    try {
        $resultado = & $multiotpExe @Argumentos 2>&1
    } finally {
        Pop-Location
    }
    return $resultado
}

#crear usuario QR
function Set-MultiOTPUsuario {
    param(
        [Parameter(Mandatory)]
        [string]$Usuario
    )

    if (-not (Test-Path "$Global:MultiOTPDir\multiotp.exe")) {
        Write-Host "ERROR: multiOTP no encontrado en $Global:MultiOTPDir" -ForegroundColor Red
        return
    }

    Write-Host "[+] Registrando usuario '$Usuario' en multiOTP..." -ForegroundColor Cyan

    # Si el usuario ya existe eliminarlo para empezar limpio
    $existe = Test-Path "$Global:MultiOTPDir\users\$Usuario.db"
    if ($existe) {
        Write-Host "  Usuario ya existe, eliminando para recrear..." -ForegroundColor Yellow
        Invoke-MultiOTP @("-delete", $Usuario) | Out-Null
    }

    # Configurar sin PIN prefix globalmente
    Invoke-MultiOTP @("-config", "default-request-prefix-pin=0") | Out-Null

    # Crear usuario con TOTP sin PIN
    $r1 = Invoke-MultiOTP @("-fastcreatenopin", $Usuario)
    # Silencio = exito en multiotp
    if ($r1) {
        Write-Host "  Crear usuario: $r1" -ForegroundColor Gray
    } else {
        Write-Host "  Usuario '$Usuario' creado correctamente." -ForegroundColor Green
    }

    # Generar QR como imagen PNG
    $qrPath    = "C:\Scripts\qr_${Usuario}.png"
    $htmlPath  = "C:\Scripts\qr_${Usuario}.html"

    $r2 = Invoke-MultiOTP @("-qrcode", $Usuario, $qrPath)
    if ($r2) { Write-Host "  QR PNG: $r2" -ForegroundColor Gray }

    # Generar tambien como HTML
    $r3 = Invoke-MultiOTP @("-htmlinfo", $Usuario, $htmlPath)
    if ($r3) { Write-Host "  QR HTML: $r3" -ForegroundColor Gray }

    Write-Host ""
    if (Test-Path $htmlPath) {
        Write-Host "QR HTML generado: $htmlPath" -ForegroundColor Green
    } elseif (Test-Path $qrPath) {
        Write-Host "QR PNG generado: $qrPath" -ForegroundColor Green
    } else {
        Write-Host "Advertencia: archivo QR no encontrado en C:\Scripts\" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "PASOS PARA ACTIVAR EN GOOGLE AUTHENTICATOR:" -ForegroundColor Yellow
    Write-Host "  1. Abre en Edge del servidor: $htmlPath" -ForegroundColor Cyan
    Write-Host "     (alternativa: abre la imagen $qrPath)" -ForegroundColor Cyan
    Write-Host "  2. En Google Authenticator: (+) -> Escanear codigo QR" -ForegroundColor White
    Write-Host "  3. Escanea el QR" -ForegroundColor White
    Write-Host "  4. Verifica el codigo con [MFA-3] ANTES de cerrar sesion" -ForegroundColor Red
}


function Test-MultiOTPCodigo {
    param(
        [Parameter(Mandatory)][string]$Usuario,
        [Parameter(Mandatory)][string]$CodigoTOTP
    )

    if (-not (Test-Path "$Global:MultiOTPDir\multiotp.exe")) {
        Write-Host "ERROR: multiOTP no instalado." -ForegroundColor Red
        return
    }

    Write-Host "[+] Verificando codigo TOTP para '$Usuario'..." -ForegroundColor Cyan

    # Sintaxis correcta: multiotp.exe usuario codigo (sin flags adicionales)
    $resultado = Invoke-MultiOTP @($Usuario, $CodigoTOTP)

    # Silencio ($resultado vacio o nulo) = autenticacion exitosa
    if (-not $resultado -or $resultado -eq "") {
        Write-Host "CODIGO VALIDO - MFA funcionando correctamente para $Usuario" -ForegroundColor Green
        Write-Host "Ahora puedes cerrar sesion con seguridad." -ForegroundColor Green
    } elseif ($resultado -match "OK") {
        Write-Host "CODIGO VALIDO: $resultado" -ForegroundColor Green
    } else {
        Write-Host "CODIGO INVALIDO o ERROR: $resultado" -ForegroundColor Red
        Write-Host "NO cierres sesion hasta que el codigo sea valido." -ForegroundColor Red
        Write-Host "Verifica que el reloj del servidor este sincronizado:" -ForegroundColor Yellow
        Write-Host "  w32tm /resync /force" -ForegroundColor Yellow
    }
}


function Set-MultiOTPLockout {
    if (-not (Test-Path "$Global:MultiOTPDir\multiotp.exe")) {
        Write-Host "ERROR: multiOTP no instalado." -ForegroundColor Red
        return
    }

    Write-Host "[+] Configurando lockout MFA: 3 intentos / 30 minutos..." -ForegroundColor Cyan

    # --- 1. Backend: bloquear tras 3 fallos ---
    Invoke-MultiOTP @("-config", "max-block-failures=3") | Out-Null
    Write-Host "  max-block-failures = 3" -ForegroundColor Green

    # --- 2. Registro del Credential Provider ---
    foreach ($rp in @("HKLM:\SOFTWARE\multiOTP","HKLM:\SOFTWARE\Policies\multiOTP")) {
        if (-not (Test-Path $rp)) { New-Item -Path $rp -Force | Out-Null }
        Set-ItemProperty -Path $rp -Name "login_failures_before_user_locked" -Value 3  -Type DWord -Force
        Set-ItemProperty -Path $rp -Name "totp_offline_ui_login_failures"    -Value 3  -Type DWord -Force
        Set-ItemProperty -Path $rp -Name "totp_offline_ui_lockout_minutes"   -Value 30 -Type DWord -Force
        Write-Host "  Registro: $rp actualizado" -ForegroundColor Green
    }

    #Ahora se maneja con una tarea que desbloquea al usaurio si se cumple el periodo
}

function Show-EstadoMFA {
    Write-Host "`n===== ESTADO MFA (multiOTP) =====" -ForegroundColor Magenta

    if (-not (Test-Path "$Global:MultiOTPDir\multiotp.exe")) {
        Write-Host "multiOTP NO instalado en $Global:MultiOTPDir" -ForegroundColor Red
        return
    }

    Write-Host "`nmultiotp.exe encontrado en: $Global:MultiOTPDir" -ForegroundColor Green

    Write-Host "`nUsuarios registrados (archivos .db en users\):" -ForegroundColor Yellow
    $dbs = Get-ChildItem "$Global:MultiOTPDir\users\*.db" -ErrorAction SilentlyContinue
    if ($dbs) {
        $dbs | Select-Object @{N="Usuario";E={$_.BaseName}}, @{N="Tamano";E={$_.Length}}, LastWriteTime | Format-Table -AutoSize
    } else {
        Write-Host "  No hay usuarios registrados todavia." -ForegroundColor Yellow
    }

    Write-Host "`nCredential Provider en registro:" -ForegroundColor Yellow
    $cpKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers"
    $found = Get-ChildItem $cpKey -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match "multiotp" -or $_.Name -match "multiOTP" }
    if ($found) {
        $found | ForEach-Object { Write-Host "  $($_.Name)" -ForegroundColor Cyan }
    } else {
        Write-Host "  Credential Provider multiOTP no encontrado en registro." -ForegroundColor Yellow
        Write-Host "  Verifica que el MSI se instalo correctamente." -ForegroundColor Yellow
    }

    Write-Host "`nConfiguracion de lockout:" -ForegroundColor Yellow
    $regPath = "HKLM:\SOFTWARE\multiOTP"
    if (Test-Path $regPath) {
        Get-ItemProperty $regPath -ErrorAction SilentlyContinue |
            Select-Object totp_offline_ui_login_failures, totp_offline_ui_lockout_minutes | Format-List
    } else {
        Write-Host "  Clave HKLM:\SOFTWARE\multiOTP no encontrada." -ForegroundColor Yellow
    }
}


# ============================================================
# FLUJO COMPLETO P09
# ============================================================

function Invoke-ConfigurarP09 {
    Import-Module ActiveDirectory, GroupPolicy

    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "   PRACTICA 09 - CONFIGURACION COMPLETA" -ForegroundColor Cyan
    Write-Host "=============================================" -ForegroundColor Cyan

    Write-Host "`n[1/4] Creando usuarios admin..." -ForegroundColor White
    New-UsuariosAdmin

    Write-Host "`n[2/4] Aplicando delegacion RBAC..." -ForegroundColor White
    Set-DelegacionRBAC

    Write-Host "`n[3/4] Configurando FGPP..." -ForegroundColor White
    New-PoliticasContrasena

    Write-Host "`n[4/4] Habilitando auditoria de eventos..." -ForegroundColor White
    Set-AuditoriaEventos

    Write-Host "`n=============================================" -ForegroundColor Green
    Write-Host "   CONFIGURACION P09 COMPLETADA" -ForegroundColor Green
    Write-Host "   Siguiente paso: Menu [MFA-1] para instalar multiOTP" -ForegroundColor Green
    Write-Host "=============================================" -ForegroundColor Green
}


function Invoke-VerificacionFinalP09 {
    Import-Module ActiveDirectory
    Write-Host "`n===== VERIFICACION FINAL P09 =====" -ForegroundColor Magenta

    Write-Host "`nUsuarios admin:" -ForegroundColor Yellow
    foreach ($u in @("admin_identidad","admin_storage","admin_politicas","admin_auditoria")) {
        $adU = Get-ADUser $u -Properties Description -ErrorAction SilentlyContinue
        if ($adU) {
            Write-Host "  OK: $u - $($adU.Description)" -ForegroundColor Green
        } else {
            Write-Host "  FALTA: $u" -ForegroundColor Red
        }
    }

    Show-VerificacionFGPP
    Show-EstadoMFA

    Write-Host "`nAuditoria (auditpol):" -ForegroundColor Yellow
    & auditpol /get /category:"Logon/Logoff","Account Logon","Account Management" | Where-Object { $_ -match "Success|Failure" }
}
