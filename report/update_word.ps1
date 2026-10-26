# Opens the generated report in Microsoft Word, updates every field (the PAGEREF page
# numbers of the Contents / List of Figures / List of Tables and the PAGE footers),
# saves it and exports a PDF. Prints the page counts per section.
#
# Usage (Windows PowerShell):
#   powershell -ExecutionPolicy Bypass -File update_word.ps1 -Docx C:\path\NetGuard_AI_Project_Report.docx
param([Parameter(Mandatory = $true)][string]$Docx)

$ErrorActionPreference = "Stop"
$word = New-Object -ComObject Word.Application
$word.Visible = $false
$word.DisplayAlerts = 0
try {
    $doc = $word.Documents.Open($Docx)
    $doc.Repaginate()
    $doc.Fields.Update() | Out-Null
    $wdActiveEndAdjustedPageNumber = 1
    $wdStatisticPages = 2
    $total = $doc.ComputeStatistics($wdStatisticPages)
    $frontEnd = $doc.Sections.Item(1).Range.Information($wdActiveEndAdjustedPageNumber)
    $mainEnd = $doc.Sections.Item(2).Range.Information($wdActiveEndAdjustedPageNumber)
    $doc.Save()
    $pdf = [System.IO.Path]::ChangeExtension($Docx, ".pdf")
    $doc.ExportAsFixedFormat($pdf, 17)  # 17 = wdExportFormatPDF
    $doc.Close()
    Write-Output "total_pages=$total"
    Write-Output "front_matter_last_page=$frontEnd"
    Write-Output "chapter1_to_references_pages=$mainEnd"
    Write-Output "pdf=$pdf"
}
finally {
    $word.Quit()
}
