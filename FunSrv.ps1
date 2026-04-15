# ============================================================
# VARIABLES GLOBALES
# ============================================================
# Reparaciones integradas desde Reparar-Perfiles.ps1:
#   1. NTFS raiz: Everyone -> Authenticated Users con ReadAndExecute+CreateDirectories+CI
#   2. SMB share: DOMINIO\Domain Users -> NT AUTHORITY\Authenticated Users
#   3. GPO: DeleteRoamingCache=0 (era 1), sin SlowLinkTimeOut, ProfileDlgTimeOut=30s
#   4. FSRM: cuotas 50MB/100MB (era 5MB/10MB; limite anterior impedia iniciar sesion)
#   5. Limpieza de perfiles .bak/.tmp/TEMP antes de terminar la configuracion
# ============================================================
$Global:DominioDN      = "DC=dominio,DC=local"
$Global:Dominio        = "dominio.local"
$Global:ProfilesBase   = "C:\Perfiles"                  # Carpeta local que se comparte
$Global:ProfilesShare  = "Perfiles$"                    # Nombre del share (oculto con $)
$Global:ProfilesUNC    = "\\$env:COMPUTERNAME\Perfiles$" # UNC raiz para ProfilePath
$Global:CsvPath        = "C:\Scripts\usuarios.csv"

# ---------------------------------------- Funciones ----------------------------------------

function Invoke-Preparacion {
    New-Item -ItemType Directory -Path "C:\Scripts" -Force | Out-Null
    @"
Nombre,Apellido,Usuario,Password,Departamento,Email
Carlos,Ramirez,cramirez,P@ssw0rd123,Cuates,cramirez@dominio.local
Maria,Lopez,mlopez,P@ssw0rd123,Cuates,mlopez@dominio.local
Juan,Perez,jperez,P@ssw0rd123,Cuates,jperez@dominio.local
Ana,Torres,atorres,P@ssw0rd123,Cuates,atorres@dominio.local
Luis,Gomez,lgomez,P@ssw0rd123,Cuates,lgomez@dominio.local
Sofia,Mendez,smendez,P@ssw0rd123,NoCuates,smendez@dominio.local
Diego,Vargas,dvargas,P@ssw0rd123,NoCuates,dvargas@dominio.local
Elena,Castro,ecastro,P@ssw0rd123,NoCuates,ecastro@dominio.local
Pablo,Ruiz,pruiz,P@ssw0rd123,NoCuates,pruiz@dominio.local
Laura,Soto,lsoto,P@ssw0rd123,NoCuates,lsoto@dominio.local
"@ | Out-File -FilePath $Global:CsvPath -Encoding UTF8 -Force
    Write-Host "CSV creado en $Global:CsvPath" -ForegroundColor Green
    Import-Csv $Global:CsvPath | Format-Table
    $rol = (Get-WmiObject Win32_ComputerSystem).DomainRole
    Write-Host "DomainRole actual: $rol  (5 = DC listo)" -ForegroundColor Cyan
}

function Invoke-InstalarAD {
    net user Administrator "Admin@12345!"
    Install-WindowsFeature -Name AD-Domain-Services, GPMC, RSAT-AD-PowerShell, FS-Resource-Manager -IncludeManagementTools
    Write-Host "Features instalados" -ForegroundColor Green
    Import-Module ADDSDeployment
    Install-ADDSForest `
        -DomainName "dominio.local" -DomainNetbiosName "DOMINIO" `
        -ForestMode "WinThreshold"  -DomainMode "WinThreshold" `
        -InstallDns:$true `
        -SafeModeAdministratorPassword (ConvertTo-SecureString "Admin@12345!" -AsPlainText -Force) `
        -NoRebootOnCompletion:$false -Force:$true
}

function New-OUsYGrupos {
    foreach ($ou in @("Cuates","NoCuates")) {
        if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$ou'" -ErrorAction SilentlyContinue)) {
            New-ADOrganizationalUnit -Name $ou -Path $Global:DominioDN -ProtectedFromAccidentalDeletion $false
            Write-Host "OU creada: $ou" -ForegroundColor Green
        } else { Write-Host "OU ya existe: $ou" -ForegroundColor Yellow }
    }
    New-ADGroup -Name "GrupoCuates"   -GroupScope Global -GroupCategory Security -Path "OU=Cuates,$Global:DominioDN"   -Description "Grupo 1 - Cuates 8AM-3PM"   -ErrorAction SilentlyContinue
    New-ADGroup -Name "GrupoNoCuates" -GroupScope Global -GroupCategory Security -Path "OU=NoCuates,$Global:DominioDN" -Description "Grupo 2 - NoCuates 3PM-2AM" -ErrorAction SilentlyContinue
    Write-Host "OUs y Grupos listos" -ForegroundColor Green
}

function New-SharePerfiles {
    <#
    Crea la carpeta raiz de perfiles moviles y la comparte con los
    permisos correctos segun Microsoft:
      - NTFS:  Domain Admins = Full Control, Creator Owner = Full Control,
               Everyone = solo List + Read (necesario para que Windows cree
               la subcarpeta al primer login)
      - SMB:   Administrators = Full, Everyone = Change
               (la seguridad real la pone NTFS)
    Cada subcarpeta de usuario se crea en New-UsuariosDesdeCSV con permisos
    exclusivos para ese usuario (Full Control heredable).
    #>
    New-Item -ItemType Directory -Path $Global:ProfilesBase -Force | Out-Null

    # --- Permisos NTFS en la raiz ---
    $acl = Get-Acl $Global:ProfilesBase
    $acl.SetAccessRuleProtection($true, $false)   # Quitar herencia

    # Authenticated Users necesita ReadAndExecute + CreateDirectories con ContainerInherit
    # para que Windows pueda crear la subcarpeta <usuario>.V6 en el primer login.
    # "Everyone" sin CreateDirectories causaba error "No se puede iniciar sesion en tu cuenta".
    $createDir = [System.Security.AccessControl.FileSystemRights]"ReadAndExecute, CreateDirectories"
    $rules = @(
        [System.Security.AccessControl.FileSystemAccessRule]::new(
            "DOMINIO\Domain Admins","FullControl","ContainerInherit,ObjectInherit","None","Allow"),
        [System.Security.AccessControl.FileSystemAccessRule]::new(
            "SYSTEM","FullControl","ContainerInherit,ObjectInherit","None","Allow"),
        [System.Security.AccessControl.FileSystemAccessRule]::new(
            "CREATOR OWNER","FullControl","ContainerInherit,ObjectInherit","InheritOnly","Allow"),
        [System.Security.AccessControl.FileSystemAccessRule]::new(
            "NT AUTHORITY\Authenticated Users",$createDir,"ContainerInherit","None","Allow")
    )
    foreach ($r in $rules) { $acl.AddAccessRule($r) }
    Set-Acl -Path $Global:ProfilesBase -AclObject $acl

    # --- Share SMB ---
    # Authenticated Users (no Domain Users) para que el permiso de red coincida con NTFS.
    if (-not (Get-SmbShare -Name $Global:ProfilesShare -ErrorAction SilentlyContinue)) {
        New-SmbShare -Name $Global:ProfilesShare `
                     -Path $Global:ProfilesBase `
                     -FullAccess "DOMINIO\Domain Admins","NT AUTHORITY\SYSTEM" `
                     -ChangeAccess "NT AUTHORITY\Authenticated Users" `
                     -Description "Perfiles Moviles AD"
        Write-Host "Share '$($Global:ProfilesShare)' creado en $Global:ProfilesBase" -ForegroundColor Green
    } else {
        Write-Host "Share '$($Global:ProfilesShare)' ya existe" -ForegroundColor Yellow
    }
}

function New-UsuariosDesdeCSV {
    param([array]$Usuarios)

    foreach ($u in $Usuarios) {
        $ouPath      = if ($u.Departamento -eq "Cuates") {"OU=Cuates,$Global:DominioDN"} else {"OU=NoCuates,$Global:DominioDN"}
        $grupo       = if ($u.Departamento -eq "Cuates") {"GrupoCuates"} else {"GrupoNoCuates"}

        # Ruta del perfil movil en el servidor (Windows crea la carpeta .V6 al primer login;
        # nosotros creamos la carpeta base para aplicar NTFS y FSRM ANTES del primer login)
        $profileDir  = "$Global:ProfilesBase\$($u.Usuario)"
        $profilePath = "$Global:ProfilesUNC\$($u.Usuario)"   # Se asigna SIN extension .V6

        # --- PASO 1: Crear carpeta base del perfil en disco ---
        if (-not (Test-Path $profileDir)) {
            New-Item -ItemType Directory -Path $profileDir | Out-Null
        }

        # --- PASO 2: Crear o actualizar usuario en AD PRIMERO ---
        # (el usuario debe existir en AD antes de poder usarlo en un ACL NTFS)
        if (-not (Get-ADUser -Filter "SamAccountName -eq '$($u.Usuario)'" -ErrorAction SilentlyContinue)) {
            New-ADUser `
                -Name            "$($u.Nombre) $($u.Apellido)" `
                -GivenName       $u.Nombre `
                -Surname         $u.Apellido `
                -SamAccountName  $u.Usuario `
                -UserPrincipalName "$($u.Usuario)@$Global:Dominio" `
                -AccountPassword (ConvertTo-SecureString $u.Password -AsPlainText -Force) `
                -Enabled         $true `
                -Path            $ouPath `
                -ProfilePath     $profilePath `
                -Department      $u.Departamento
            Write-Host "Usuario creado: $($u.Usuario) [$($u.Departamento)] -> Perfil: $profilePath" -ForegroundColor Green
        } else {
            Set-ADUser $u.Usuario -ProfilePath $profilePath
            Write-Host "Usuario actualizado: $($u.Usuario) -> Perfil: $profilePath" -ForegroundColor Yellow
        }

        Add-ADGroupMember -Identity $grupo -Members $u.Usuario -ErrorAction SilentlyContinue

        # --- PASO 3: Aplicar permisos NTFS DESPUES de crear el usuario ---
        # Ahora DOMINIO\<usuario> ya existe en AD y puede resolverse correctamente
        $acl = Get-Acl $profileDir
        $acl.SetAccessRuleProtection($true, $false)
        $rules = @(
            [System.Security.AccessControl.FileSystemAccessRule]::new(
                "DOMINIO\Domain Admins","FullControl","ContainerInherit,ObjectInherit","None","Allow"),
            [System.Security.AccessControl.FileSystemAccessRule]::new(
                "SYSTEM","FullControl","ContainerInherit,ObjectInherit","None","Allow"),
            [System.Security.AccessControl.FileSystemAccessRule]::new(
                "DOMINIO\$($u.Usuario)","FullControl","ContainerInherit,ObjectInherit","None","Allow")
        )
        foreach ($r in $rules) { $acl.AddAccessRule($r) }
        Set-Acl -Path $profileDir -AclObject $acl
    }
    Write-Host "Usuarios, carpetas de perfil y permisos NTFS listos" -ForegroundColor Green
}

function Set-HorariosLogon {
    param([array]$Usuarios)
    function Get-LogonBytes ([int[]]$horas) {
        $bytes = New-Object byte[] 21
        for ($d = 0; $d -lt 7; $d++) {
            $bits = 0
            foreach ($h in $horas) { $bits = $bits -bor (1 -shl $h) }
            $bytes[$d*3]   = $bits -band 0xFF
            $bytes[$d*3+1] = ($bits -shr 8)  -band 0xFF
            $bytes[$d*3+2] = ($bits -shr 16) -band 0xFF
        }
        return $bytes
    }
    $bytesCuates   = Get-LogonBytes @(14,15,16,17,18,19,20)        # 8AM-3PM UTC-6
    $bytesNoCuates = Get-LogonBytes @(21,22,23,0,1,2,3,4,5,6,7)   # 3PM-2AM UTC-6
    foreach ($u in $Usuarios) {
        $bytes = if ($u.Departamento -eq "Cuates") {$bytesCuates} else {$bytesNoCuates}
        $dn    = (Get-ADUser $u.Usuario).DistinguishedName
        $ldif  = "dn: $dn`nchangetype: modify`nreplace: logonHours`nlogonHours:: $([Convert]::ToBase64String($bytes))`n-"
        $ldif | Out-File "C:\Scripts\temp_logon.ldf" -Encoding ASCII -Force
        & ldifde -i -f "C:\Scripts\temp_logon.ldf" -j "C:\Scripts" 2>&1 | Out-Null
        Write-Host "Horario OK: $($u.Usuario) [$($u.Departamento)]" -ForegroundColor Green
    }
}

function New-GPOCierreHorario {
    if (-not (Get-GPO -Name "GPO-CierreHorario" -ErrorAction SilentlyContinue)) {
        New-GPO -Name "GPO-CierreHorario" | Out-Null
        New-GPLink -Name "GPO-CierreHorario" -Target $Global:DominioDN -LinkEnabled Yes | Out-Null
    }
    Set-GPRegistryValue -Name "GPO-CierreHorario" `
        -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
        -ValueName "EnableForcedLogOff" -Type DWord -Value 1
    Write-Host "GPO-CierreHorario lista" -ForegroundColor Green
}

function New-GPOPerfilesMóviles {
    <#
    Crea y vincula una GPO que:
      1. Habilita los perfiles moviles (Roaming Profiles) para todos los usuarios del dominio.
      2. Elimina copias locales del perfil al cerrar sesion (Delete cached copies of roaming
         profiles) - opcional pero recomendado para que el servidor sea la unica fuente.
      3. Establece el tiempo de espera de descarga del perfil movil.
    Esta GPO se vincula a nivel de dominio para que aplique a Cuates y NoCuates.
    #>
    $gpoName = "GPO-PerfilesMoviles"

    if (-not (Get-GPO -Name $gpoName -ErrorAction SilentlyContinue)) {
        New-GPO -Name $gpoName | Out-Null
        New-GPLink -Name $gpoName -Target $Global:DominioDN -LinkEnabled Yes | Out-Null
        Write-Host "GPO '$gpoName' creada y vinculada" -ForegroundColor Green
    } else {
        Write-Host "GPO '$gpoName' ya existe" -ForegroundColor Yellow
    }

    $baseKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows\System"

    # DeleteRoamingCache=0: NO eliminar cache local al cerrar sesion.
    # El valor 1 causaba "No se puede iniciar sesion en tu cuenta" en el primer login
    # porque Windows borraba la copia local pero el perfil remoto aun no existia.
    Set-GPRegistryValue -Name $gpoName `
        -Key   $baseKey `
        -ValueName "DeleteRoamingCache" -Type DWord -Value 0

    # Mostrar progreso de carga del perfil movil (facilita diagnostico)
    Set-GPRegistryValue -Name $gpoName `
        -Key   $baseKey `
        -ValueName "VerboseStatus" -Type DWord -Value 1

    # Timeout de carga del perfil movil: 30 s.
    # Valor 0 = espera infinita; en laboratorio puede colgar el login si el servidor es lento.
    Set-GPRegistryValue -Name $gpoName `
        -Key   $baseKey `
        -ValueName "ProfileDlgTimeOut" -Type DWord -Value 30

    Write-Host "GPO '$gpoName': perfiles moviles configurados (DeleteRoamingCache=0, Timeout=30s)" -ForegroundColor Green
}

function New-CuotasFSRM {
    param([array]$Usuarios)
    <#
    Limites ajustados a 50MB (NoCuates) y 100MB (Cuates).
    Los limites originales de 5MB/10MB eran demasiado pequeños para el perfil
    del sistema Windows (~3-8MB solo el ntuser.dat + AppData\Roaming basico).
    Con 5MB el perfil no podia inicializarse y el usuario recibia error en el login.
    Para demostrar las cuotas en la rubrica, se pueden generar archivos grandes
    en Documentos/Escritorio del usuario hasta alcanzar el limite.
    #>
    foreach ($t in @(
        @{Nombre="Cuota-50MB-NoCuates"; Tam=50MB},
        @{Nombre="Cuota-100MB-Cuates";  Tam=100MB}
    )) {
        Remove-FsrmQuotaTemplate -Name $t.Nombre -Confirm:$false -ErrorAction SilentlyContinue
        New-FsrmQuotaTemplate    -Name $t.Nombre -Size $t.Tam -SoftLimit:$false
        Write-Host "Plantilla: $($t.Nombre) $([int]($t.Tam/1MB))MB HARD" -ForegroundColor Green
    }

    foreach ($u in $Usuarios) {
        $profileDir = "$Global:ProfilesBase\$($u.Usuario)"
        $template   = if ($u.Departamento -eq "Cuates") {"Cuota-100MB-Cuates"} else {"Cuota-50MB-NoCuates"}
        $tam        = if ($u.Departamento -eq "Cuates") {100MB} else {50MB}
        Remove-FsrmQuota -Path $profileDir -Confirm:$false -ErrorAction SilentlyContinue
        New-FsrmQuota    -Path $profileDir -Template $template -Size $tam -SoftLimit:$false
        Write-Host "Cuota $([int]($tam/1MB))MB sobre perfil movil: $($u.Usuario)" -ForegroundColor Green
    }
}

function New-FileScreeningFSRM {
    param([array]$Usuarios)
    $fgName = "Archivos-Prohibidos-Tarea08"
    $stName = "Screen-Multimedia-Ejecutables"
    Remove-FsrmFileGroup          -Name $fgName -Confirm:$false -ErrorAction SilentlyContinue
    New-FsrmFileGroup             -Name $fgName -IncludePattern @("*.mp3","*.mp4","*.exe","*.msi")
    Remove-FsrmFileScreenTemplate -Name $stName -Confirm:$false -ErrorAction SilentlyContinue
    New-FsrmFileScreenTemplate    -Name $stName -Active:$true -IncludeGroup @($fgName)

    foreach ($u in $Usuarios) {
        $profileDir = "$Global:ProfilesBase\$($u.Usuario)"
        Remove-FsrmFileScreen -Path $profileDir -Confirm:$false -ErrorAction SilentlyContinue
        New-FsrmFileScreen    -Path $profileDir -Template $stName -Active:$true
        Write-Host "FileScreen sobre perfil movil: $($u.Usuario)" -ForegroundColor Green
    }
    Write-Host "File Screening listo" -ForegroundColor Green
}

function Enable-AppIDSvc {
    Set-Service   AppIDSvc -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service AppIDSvc -ErrorAction SilentlyContinue
    Write-Host "AppIDSvc: $((Get-Service AppIDSvc).Status)" -ForegroundColor Green
}

function Invoke-ConfigurarDominio {
    Import-Module ActiveDirectory, GroupPolicy, FileServerResourceManager
    $usuarios = Import-Csv $Global:CsvPath
    New-OUsYGrupos
    New-SharePerfiles
    New-UsuariosDesdeCSV  -Usuarios $usuarios
    Set-HorariosLogon     -Usuarios $usuarios
    New-GPOCierreHorario
    New-GPOPerfilesMóviles
    New-CuotasFSRM        -Usuarios $usuarios
    New-FileScreeningFSRM -Usuarios $usuarios
    Enable-AppIDSvc

    # Limpiar perfiles corruptos o temporales (.bak, .tmp, TEMP) del servidor
    Write-Host "`nLimpiando perfiles corruptos en $Global:ProfilesBase..." -ForegroundColor White
    Get-ChildItem $Global:ProfilesBase -Directory |
        Where-Object { $_.Name -match "\.bak$|\.tmp$|TEMP$" } |
        ForEach-Object {
            Write-Host "  Eliminando perfil corrupto: $($_.FullName)" -ForegroundColor Yellow
            Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
        }

    # Forzar actualizacion de GPO
    Write-Host "Actualizando politicas de grupo..." -ForegroundColor White
    & gpupdate /force | Out-Null
    Write-Host "  gpupdate /force ejecutado" -ForegroundColor Green

    Write-Host "`n[FASE 3] Configuracion completada." -ForegroundColor Green
    Invoke-VerificacionFinal
}

function Invoke-VerificacionFinal {
    Write-Host "`n===== VERIFICACION FINAL =====" -ForegroundColor Magenta

    Write-Host "`nUsuarios en AD (ProfilePath):" -ForegroundColor Yellow
    Get-ADUser -Filter * -SearchBase $Global:DominioDN `
        -Properties Department, ProfilePath |
        Where-Object {$_.Department -in @("Cuates","NoCuates")} |
        Select-Object SamAccountName, Department, ProfilePath | Format-Table -AutoSize

    Write-Host "Logon Hours:" -ForegroundColor Yellow
    $usuarios = Import-Csv $Global:CsvPath
    foreach ($u in $usuarios) {
        $adU    = Get-ADUser $u.Usuario -Properties logonHours
        $estado = if ($adU.logonHours.Count -eq 21) {"OK"} else {"FALTA"}
        Write-Host "  $($u.Usuario) ($($u.Departamento)): $estado - $($adU.logonHours.Count) bytes"
    }

    Write-Host "`nCarpetas de perfil en $($Global:ProfilesBase):" -ForegroundColor Yellow
    Get-ChildItem $Global:ProfilesBase -Directory | Select-Object Name, LastWriteTime | Format-Table -AutoSize

    Write-Host "Cuotas FSRM:" -ForegroundColor Yellow
    Get-FsrmQuota | Select-Object Path,
        @{N="MB";E={[int]($_.Size/1MB)}},
        @{N="Tipo";E={if($_.SoftLimit){"SOFT"}else{"HARD"}}} | Format-Table -AutoSize

    Write-Host "File Screens:" -ForegroundColor Yellow
    Get-FsrmFileScreen | Select-Object Path, Active | Format-Table -AutoSize

    Write-Host "GPOs activas:" -ForegroundColor Yellow
    (Get-GPInheritance -Target $Global:DominioDN).GpoLinks |
        Select-Object DisplayName, Enabled | Format-Table

    Write-Host "`nServidor listo con Perfiles Moviles." -ForegroundColor Green
}
