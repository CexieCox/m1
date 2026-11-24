$ErrorActionPreference = 'Stop'
$taskRoot = 'D:\Applications\loaderfilter_tool'
$taskContent = Get-Content -Raw -LiteralPath (Join-Path $taskRoot '.work_log_collection\section_content_zenodo.json') -Encoding UTF8 | ConvertFrom-Json
$taskOutput = Join-Path $taskRoot 'Section_3_2_2_Module_1_Log_Collection.docx'

function Escape-Xml([string]$text) { return [System.Security.SecurityElement]::Escape($text) }
function New-Paragraph([string]$text, [string]$style='Normal', [bool]$pageBreak=$false) {
    $extra = if($pageBreak) { '<w:pageBreakBefore/>' } else { '' }
    return '<w:p><w:pPr><w:pStyle w:val="'+$style+'"/>'+$extra+'</w:pPr><w:r><w:t xml:space="preserve">'+(Escape-Xml $text)+'</w:t></w:r></w:p>'
}
function New-Table($block) {
    $colWidths = if($block.widths) { $block.widths } else { @(2400,6626) }
    $xml = '<w:tbl><w:tblPr><w:tblW w:w="9026" w:type="dxa"/><w:tblLayout w:type="fixed"/><w:tblBorders>'
    foreach($side in @('top','left','bottom','right','insideH','insideV')) { $xml += '<w:'+$side+' w:val="single" w:sz="4" w:color="D9D9D9"/>' }
    $xml += '</w:tblBorders><w:tblCellMar><w:top w:w="110" w:type="dxa"/><w:left w:w="140" w:type="dxa"/><w:bottom w:w="110" w:type="dxa"/><w:right w:w="140" w:type="dxa"/></w:tblCellMar></w:tblPr><w:tblGrid><w:gridCol w:w="'+$colWidths[0]+'"/><w:gridCol w:w="'+$colWidths[1]+'"/></w:tblGrid>'
    $rowItems = @(@{cells=$block.headers; header=$true})
    foreach($row in $block.rows) { $rowItems += @{cells=$row; header=$false} }
    foreach($row in $rowItems) {
        $xml += '<w:tr><w:trPr><w:cantSplit/>'
        if($row.header) { $xml += '<w:tblHeader/>' }
        $xml += '</w:trPr>'
        for($col=0;$col -lt 2;$col++) {
            $width = $colWidths[$col]
            $fill = if($row.header){'E8EDF2'}else{'FFFFFF'}
            $bold = if($row.header){'<w:b/>'}else{''}
            $xml += '<w:tc><w:tcPr><w:tcW w:w="'+$width+'" w:type="dxa"/><w:shd w:val="clear" w:fill="'+$fill+'"/><w:vAlign w:val="center"/></w:tcPr><w:p><w:pPr><w:pStyle w:val="TableText"/></w:pPr><w:r><w:rPr>'+$bold+'</w:rPr><w:t>'+(Escape-Xml ([string]$row.cells[$col]))+'</w:t></w:r></w:p></w:tc>'
        }
        $xml += '</w:tr>'
    }
    return $xml+'</w:tbl>'
}

$taskBody = New-Paragraph $taskContent.title 'Title'
foreach($block in $taskContent.blocks) {
    if($block.type -eq 'h') { $taskBody += New-Paragraph $block.text 'Heading2' }
    elseif($block.type -eq 'table') { $taskBody += New-Table $block }
    else { $taskBody += New-Paragraph $block.text }
}
$taskBody += New-Paragraph 'Reference' 'Heading2'
foreach($source in $taskContent.sources) {
    $taskBody += New-Paragraph ('['+$source.id+'] '+$source.title) 'SourceHeading'
    $taskBody += New-Paragraph $source.detail 'SourceText'
}

$taskSections = '<w:sectPr><w:footerReference w:type="default" r:id="rId2"/><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="576" w:footer="576"/><w:cols w:space="720"/></w:sectPr>'
$taskStyles = @'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman" w:cs="Times New Roman"/><w:color w:val="000000"/><w:sz w:val="24"/><w:lang w:val="en-US"/></w:rPr></w:rPrDefault><w:pPrDefault><w:pPr><w:spacing w:after="120" w:line="300" w:lineRule="auto"/><w:widowControl/></w:pPr></w:pPrDefault></w:docDefaults>
<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:qFormat/><w:pPr><w:jc w:val="both"/></w:pPr></w:style>
<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/><w:pPr><w:keepNext/><w:keepLines/><w:spacing w:before="0" w:after="220"/><w:jc w:val="left"/></w:pPr><w:rPr><w:b/><w:color w:val="000000"/><w:sz w:val="32"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/><w:pPr><w:keepNext/><w:keepLines/><w:spacing w:before="0" w:after="180"/><w:jc w:val="left"/><w:outlineLvl w:val="0"/></w:pPr><w:rPr><w:b/><w:sz w:val="28"/><w:color w:val="000000"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/><w:pPr><w:keepNext/><w:keepLines/><w:spacing w:before="180" w:after="100"/><w:jc w:val="left"/><w:outlineLvl w:val="1"/></w:pPr><w:rPr><w:b/><w:sz w:val="25"/><w:color w:val="000000"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="TableText"><w:name w:val="Table Text"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:before="0" w:after="0" w:line="264" w:lineRule="auto"/><w:jc w:val="left"/></w:pPr><w:rPr><w:sz w:val="22"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="SourceHeading"><w:name w:val="Source Heading"/><w:basedOn w:val="Normal"/><w:pPr><w:keepNext/><w:keepLines/><w:spacing w:before="140" w:after="35" w:line="240" w:lineRule="auto"/><w:jc w:val="left"/></w:pPr><w:rPr><w:b/><w:sz w:val="22"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="SourceText"><w:name w:val="Source Text"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:before="0" w:after="60" w:line="264" w:lineRule="auto"/><w:jc w:val="left"/></w:pPr><w:rPr><w:sz w:val="22"/></w:rPr></w:style>
</w:styles>
'@
$taskMembers = [ordered]@{
    '[Content_Types].xml' = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/><Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/></Types>'
    '_rels/.rels' = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/></Relationships>'
    'word/document.xml' = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><w:body>'+$taskBody+$taskSections+'</w:body></w:document>'
    'word/styles.xml' = $taskStyles
    'word/_rels/document.xml.rels' = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/></Relationships>'
    'word/footer1.xml' = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p><w:pPr><w:jc w:val="center"/></w:pPr><w:r><w:rPr><w:sz w:val="20"/></w:rPr><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText xml:space="preserve"> PAGE </w:instrText></w:r><w:r><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:t>1</w:t></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r></w:p></w:ftr>'
    'docProps/core.xml' = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>3.2.2. Module 1: Log Collection</dc:title><dc:subject>LoaderFilter methodology</dc:subject></cp:coreProperties>'
}
Add-Type -AssemblyName System.IO.Compression
$taskStream = [System.IO.File]::Open($taskOutput,[System.IO.FileMode]::Create)
$taskZip = [System.IO.Compression.ZipArchive]::new($taskStream,[System.IO.Compression.ZipArchiveMode]::Create,$false)
try {
    foreach($name in $taskMembers.Keys) {
        [xml]$taskXml = $taskMembers[$name]
        $entry=$taskZip.CreateEntry($name)
        $writer=[System.IO.StreamWriter]::new($entry.Open(),[System.Text.UTF8Encoding]::new($false))
        try { $writer.Write($taskMembers[$name]) } finally { $writer.Dispose() }
    }
} finally { $taskZip.Dispose(); $taskStream.Dispose() }
Get-Item -LiteralPath $taskOutput | Select-Object FullName,Length
