$ErrorActionPreference = 'Stop'
$inputDoc = 'D:\Applications\loaderfilter_tool\thesis_section_3_1\Section_3_1_Dataset_With_WinMET.docx'
$outputPdf = 'D:\Applications\loaderfilter_tool\thesis_section_3_1\render\Section_3_1_Dataset_With_WinMET.pdf'
$wordApp = $null
$wordDoc = $null
try {
    $wordApp = New-Object -ComObject Word.Application
    $wordApp.Visible = $false
    $wordApp.DisplayAlerts = 0
    $wordDoc = $wordApp.Documents.Open($inputDoc, $false, $true, $false)
    $wordDoc.Repaginate()
    $wordDoc.ExportAsFixedFormat($outputPdf, 17)
    Write-Output $outputPdf
} finally {
    if ($null -ne $wordDoc) { $wordDoc.Close(0); [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($wordDoc) }
    if ($null -ne $wordApp) { $wordApp.Quit(); [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($wordApp) }
}
