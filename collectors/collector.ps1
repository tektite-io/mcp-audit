# MCP Audit Collector Script (Windows PowerShell)
# 
# This script collects MCP configurations from developer machines.
# Deploy via MDM (Intune, etc.) to gather org-wide MCP inventory.
#
# Output: JSON to stdout or file
# Usage: 
#   .\collector.ps1                    # Output to stdout
#   .\collector.ps1 -OutputDir C:\path\to\output\
#
# The output JSON can be analyzed with: mcp-audit analyze C:\path\to\collected\

param(
    [string]$OutputDir = ""
)

$ErrorActionPreference = "SilentlyContinue"

# Configuration
$MachineId = $env:COMPUTERNAME
$Timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

# Initialize results
$Mcps = @()

function Get-ClaudeDesktopConfig {
    $configPath = Join-Path $env:APPDATA "Claude\claude_desktop_config.json"
    
    if (Test-Path $configPath) {
        try {
            $config = Get-Content $configPath -Raw | ConvertFrom-Json
            
            if ($config.mcpServers) {
                $config.mcpServers.PSObject.Properties | ForEach-Object {
                    @{
                        name = $_.Name
                        found_in = "Claude Desktop"
                        config_path = $configPath
                        config = $_.Value
                    }
                }
            }
        }
        catch {
            Write-Error "Error parsing Claude Desktop config: $_"
        }
    }
}

function Get-CursorConfig {
    $configPaths = @(
        (Join-Path $env:USERPROFILE ".cursor\mcp.json"),
        (Join-Path $env:APPDATA "Cursor\mcp.json")
    )
    
    foreach ($configPath in $configPaths) {
        if (Test-Path $configPath) {
            try {
                $config = Get-Content $configPath -Raw | ConvertFrom-Json
                
                if ($config.mcpServers) {
                    $config.mcpServers.PSObject.Properties | ForEach-Object {
                        @{
                            name = $_.Name
                            found_in = "Cursor"
                            config_path = $configPath
                            config = $_.Value
                        }
                    }
                }
                break
            }
            catch {
                Write-Error "Error parsing Cursor config: $_"
            }
        }
    }
}

function Get-ContinueConfig {
    $configPath = Join-Path $env:USERPROFILE ".continue\config.json"
    
    if (Test-Path $configPath) {
        try {
            $config = Get-Content $configPath -Raw | ConvertFrom-Json
            
            if ($config.experimental.modelContextProtocolServers) {
                $config.experimental.modelContextProtocolServers | ForEach-Object {
                    @{
                        name = $_.name
                        found_in = "Continue"
                        config_path = $configPath
                        config = $_
                    }
                }
            }
        }
        catch {
            Write-Error "Error parsing Continue config: $_"
        }
    }
}

function Get-VSCodeConfig {
    $configPaths = @(
        (Join-Path $env:APPDATA "Code\User\settings.json"),
        (Join-Path $env:APPDATA "Code - Insiders\User\settings.json")
    )
    
    foreach ($configPath in $configPaths) {
        if (Test-Path $configPath) {
            try {
                $config = Get-Content $configPath -Raw | ConvertFrom-Json
                
                # Check for MCP settings (depends on extension)
                if ($config.'mcp.servers') {
                    $config.'mcp.servers'.PSObject.Properties | ForEach-Object {
                        @{
                            name = $_.Name
                            found_in = "VS Code"
                            config_path = $configPath
                            config = $_.Value
                        }
                    }
                }
            }
            catch {
                Write-Error "Error parsing VS Code config: $_"
            }
        }
    }
}

# Collect from all sources
$Mcps = @()
$Mcps += Get-ClaudeDesktopConfig
$Mcps += Get-CursorConfig
$Mcps += Get-ContinueConfig
$Mcps += Get-VSCodeConfig

# Filter out nulls
$Mcps = $Mcps | Where-Object { $_ -ne $null }

# Build output
$Output = @{
    machine_id = $MachineId
    collected_at = $Timestamp
    mcps = $Mcps
}

$JsonOutput = $Output | ConvertTo-Json -Depth 10

# Output
if ($OutputDir) {
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }
    
    $OutputFile = Join-Path $OutputDir "$MachineId.json"
    $JsonOutput | Out-File -FilePath $OutputFile -Encoding UTF8
    Write-Host "Wrote results to: $OutputFile"
}
else {
    Write-Output $JsonOutput
}
