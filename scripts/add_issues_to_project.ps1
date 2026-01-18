param(
  [string]$Repo = "Kareemayad/cyber-llm-engine",
  [string]$ProjectId = "PVT_kwHOBd7lUM4BKzTE",
  [string]$StatusFieldId = "PVTSSF_lAHOBd7lUM4BKzTEzg6kFPI",
  [string]$TodoOptionId = "f75ad846"
)

$ErrorActionPreference = "Stop"

function Gh-GraphQL($query, $vars) {
  $args = @("api","graphql","-f","query=$query")
  foreach ($k in $vars.Keys) { $args += @("-f","$k=$($vars[$k])") }
  return (gh @args | ConvertFrom-Json)
}

Write-Host "Repo: $Repo"
Write-Host "ProjectId: $ProjectId"
Write-Host "StatusFieldId: $StatusFieldId"
Write-Host "TodoOptionId: $TodoOptionId"

# Fetch issues and filter to [P1]..[P4]
$issues = gh issue list -R $Repo --limit 200 --json number,title,id | ConvertFrom-Json
$releaseIssues = $issues | Where-Object { $_.title -match '^\[P[1-4]\]' }

Write-Host ("Found Release issues: " + $releaseIssues.Count)

$qAddItem = @'
mutation($projectId:ID!, $contentId:ID!) {
  addProjectV2ItemById(input:{projectId:$projectId, contentId:$contentId}) {
    item { id }
  }
}
'@

$qSetStatus = @'
mutation($projectId:ID!, $itemId:ID!, $fieldId:ID!, $optionId:String!) {
  updateProjectV2ItemFieldValue(input:{
    projectId:$projectId,
    itemId:$itemId,
    fieldId:$fieldId,
    value:{ singleSelectOptionId:$optionId }
  }) { projectV2Item { id } }
}
'@

foreach ($iss in $releaseIssues) {
  try {
    $addRes = Gh-GraphQL $qAddItem @{ projectId=$ProjectId; contentId=$iss.id }
    $itemId = $addRes.data.addProjectV2ItemById.item.id

    Gh-GraphQL $qSetStatus @{ projectId=$ProjectId; itemId=$itemId; fieldId=$StatusFieldId; optionId=$TodoOptionId } | Out-Null
    Write-Host ("Added + set Todo: #" + $iss.number + " " + $iss.title)
  } catch {
    Write-Host ("Skipped (already added?): #" + $iss.number + " " + $iss.title)
  }
}

Write-Host "Done. Open the project and view as Board grouped by Status."
