# Cleanup-WorkdayData.ps1
# This script deletes old files in the logs/WorkdayData directory, keeping only the 5 most recent pairs of CSV and JSON files.

$DataLogDir = Join-Path $PSScriptRoot '../logs/WorkdayData'
$keepCount = 5

# Get all CSV and JSON files, sorted by LastWriteTime descending
$csvFiles = Get-ChildItem -Path $DataLogDir -Filter '*.csv' | Sort-Object LastWriteTime -Descending
$jsonFiles = Get-ChildItem -Path $DataLogDir -Filter '*.json' | Sort-Object LastWriteTime -Descending

# Keep only the most recent $keepCount files of each type
$csvToDelete = $csvFiles | Select-Object -Skip $keepCount
$jsonToDelete = $jsonFiles | Select-Object -Skip $keepCount

foreach ($file in $csvToDelete + $jsonToDelete) {
    Write-Host "Deleting $($file.FullName)"
    Remove-Item $file.FullName -Force
}

Write-Host "Cleanup complete. Kept $keepCount most recent CSV and JSON files." 