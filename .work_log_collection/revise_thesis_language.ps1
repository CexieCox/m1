$ErrorActionPreference='Stop'
$taskRoot='D:\Applications\loaderfilter_tool'
$taskPath=Join-Path $taskRoot '.work_log_collection\section_content_zenodo.json'
$taskData=Get-Content -Raw -LiteralPath $taskPath -Encoding UTF8 | ConvertFrom-Json
$taskAudit=Join-Path $taskRoot '.work_log_collection\implementation_evidence_before_thesis_revision.json'
if(-not (Test-Path -LiteralPath $taskAudit)){Copy-Item -LiteralPath $taskPath -Destination $taskAudit}
foreach($b in $taskData.blocks){
 if($b.type -eq 'p'){
  $b.text=[regex]::Replace($b.text,'\s*\[S\d+(?:, S\d+)*\]',{param($m) if($m.Value -match '\bS1\b'){' [1]'}else{''}})
  if($b.text.StartsWith('The label-loading logic')){
   $b.text='CAPE and AVClass labels are retained separately and compared with the consensus metadata. A consensus entry can supplement a missing label mapping. If it disagrees with an existing mapping, the discrepancy and its source remain recorded. The consensus metadata therefore preserves the available label assignments without requiring the two labeling sources to agree on every report.'
  }
  elseif($b.text.StartsWith('At the inventory stage')){
   $b.text='A report enters the initial candidate set when at least one relevant label matches a family in the predefined loader family list. The broader candidate set also retains reports with configured generic labels, labels requiring review, or conflicts between the label mappings and consensus metadata. Label agreement, disagreement, and missing values are recorded separately. These inclusion criteria preserve uncertain reports for subsequent analysis; candidate status alone does not establish that loader activity occurred during execution.'
  }
  elseif($b.text.StartsWith('The tool also supports evidence-mode')){
   $b.text='The filtering workflow also supports behavioral screening of CAPE reports. This step incrementally examines process records, selected API-call evidence, malware detections, and metadata describing extracted or dropped artifacts. Loader-family detections or delivery-related behavior can provide additional reasons to retain a report. Behavioral screening can cover the initial candidate set or the entire discovered collection, depending on the configured scope. The selection criterion for reports passed to the next module is described below.'
  }
  elseif($b.text.StartsWith('The collection passed to Module 2 uses')){
   $b.text='The collection passed to Module 2 includes all reports designated as candidates by the filtering workflow. This includes reports with loader-family label matches and those retained for the additional review reasons described above. Confirmed runtime loader execution is not a prerequisite for inclusion. The resulting collection is therefore a loader-related candidate subset of WinMET, preserving the distinction between family-label evidence, a reason for further inspection, and supported evidence of runtime loader execution.'
  }
  elseif($b.text.StartsWith('For report-level export')){
   $b.text='The selected original JSON reports are copied for downstream processing, and their SHA-256 digests are verified to check content integrity. Export records retain report and sample identifiers, source information, the recorded decision, and the selection criterion. This preserves the original telemetry and its provenance for the next module. The evidence extracted during filtering serves as an intermediate representation; the complete source reports remain the downstream input.'
  }
  elseif($b.text.StartsWith('The implementation preserves')){
   $b.text='The workflow preserves report inventories, processing statuses, configuration snapshots, and processing history. When behavioral screening is enabled, it also records extracted evidence and quality indicators. Input checks examine report structure and resource limits, record malformed or unsupported reports, and detect changes to source files during reading. Collection-level quality checks examine identifiers, content fingerprints, evidence integrity, consistency between records, and the prerequisites for recorded decisions. These checks support traceability and data integrity; they do not by themselves establish the accuracy or completeness of loader identification.'
  }
 }
}
$taskData.sources=@($taskData.sources | Where-Object {$_.id -eq 'S1'})
$taskData.sources[0].id='1'
[System.IO.File]::WriteAllText($taskPath,($taskData | ConvertTo-Json -Depth 12),[System.Text.UTF8Encoding]::new($false))
& (Join-Path $taskRoot '.work_log_collection\build_document.ps1')
& (Join-Path $taskRoot '.work_log_collection\build_workflow.ps1')
