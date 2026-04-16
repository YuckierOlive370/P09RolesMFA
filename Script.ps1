do {
    $usuariosBloqueados = & "$Global:MultiOTPDir\multiotp.exe" -lockeduserslist
    
    $usuariosBloqueados | ForEach-Object {
        $usuarioActual = $_
        if ([string]::IsNullOrWhiteSpace($usuarioActual)) { return }

        $archivoUsuario = ".\users\$usuarioActual.db"
        if (-not (Test-Path $archivoUsuario)) { $archivoUsuario = ".\users\$usuarioActual.conf" }

        if (Test-Path $archivoUsuario) {
            $lineaFallos = Get-Content $archivoUsuario | Select-String "last_failed_time="
            if ($lineaFallos) {
                $ultimoFallo = [int64]($lineaFallos.ToString().Split('=')[1].Trim())
                $tiempoActual = [DateTimeOffset]::Now.ToUnixTimeSeconds()
                $diferenciaSegundos = $tiempoActual - $ultimoFallo

                if ($diferenciaSegundos -ge 300) {
                    "$(Get-Date) - Desbloqueando $usuarioActual" | Out-File "C:\Program Files\multiOTP\HistorialBloqueos.log" -Append
                    & "$Global:MultiOTPDir\multiotp.exe" -unlock $usuarioActual
                } else {
                    "$(Get-Date) - $usuarioActual bloqueado. Faltan $(300 - $diferenciaSegundos)s" | Out-File "C:\Program Files\multiOTP\HistorialBloqueos.log" -Append
                }
            }
        }
    }

    Start-Sleep -Seconds 5
} while ($true)
