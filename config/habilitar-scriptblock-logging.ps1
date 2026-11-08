# habilitar-scriptblock-logging.ps1
# Habilita o PowerShell ScriptBlock Logging (evento 4104) no Windows.
# Executar como Administrador.
#
# No lab, só EnableScriptBlockLogging gerava apenas 4105/4106 (início/fim do bloco).
# O 4104, que contém o texto do script, só apareceu com EnableScriptBlockInvocationLogging.

#Requires -RunAsAdministrator

$path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"

# -Force cria a chave (e as intermediárias) se não existirem; Out-Null esconde a saída
New-Item -Path $path -Force | Out-Null

# Registra o conteúdo dos blocos de script executados (evento 4104)
Set-ItemProperty -Path $path -Name "EnableScriptBlockLogging" -Value 1 -Type DWord

# Registra início/fim de invocação; necessário para o 4104 aparecer de forma consistente no lab
Set-ItemProperty -Path $path -Name "EnableScriptBlockInvocationLogging" -Value 1 -Type DWord

Write-Host "Configuração aplicada:" -ForegroundColor Green
Get-ItemProperty -Path $path | Select-Object EnableScriptBlockLogging, EnableScriptBlockInvocationLogging

# Teste: gera um 4104 e mostra o evento mais recente
Write-Host "`nGerando evento de teste..." -ForegroundColor Cyan
powershell.exe -NoProfile -Command 'Write-Output "teste-4104"' | Out-Null
Start-Sleep -Seconds 2
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 50 |
    Where-Object Id -eq 4104 |
    Select-Object -First 1 TimeCreated, Id, Message |
    Format-List
