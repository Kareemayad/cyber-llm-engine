param(
  [string]$Repo = "Kareemayad/cyber-llm-engine",
  [string]$ProjectTitle = "Release 1 - Execution Board"
)

$ErrorActionPreference = "Stop"

function Gh-GraphQL($query, $vars) {
  $args = @("api","graphql","-f","query=$query")
  foreach ($k in $vars.Keys) {
    $args += @("-f","$k=$($vars[$k])")
  }
  return (gh @args | ConvertFrom-Json)
}

$owner = $Repo.Split("/")[0]
$name  = $Repo.Split("/")[1]

Write-Host "Repo: $Repo"
Write-Host "Project: $ProjectTitle"

# 1) Get repo node ID + owner node ID
$qRepo = @'
query($owner:String!, $name:String!) {
  repository(owner:$owner, name:$name) {
    id
    owner { ... on User { id } ... on Organization { id } }
  }
}
'@
$repoRes = Gh-GraphQL $qRepo @{ owner=$owner; name=$name }
$repoId = $repoRes.data.repository.id
$ownerId = $repoRes.data.repository.owner.id

# 2) Create ProjectV2 under the repo owner (user/org)
$qCreateProject = @'
mutation($ownerId:ID!, $title:String!) {
  createProjectV2(input:{ownerId:$ownerId, title:$title}) {
    projectV2 { id title }
  }
}
'@
$projRes = Gh-GraphQL $qCreateProject @{ ownerId=$ownerId; title=$ProjectTitle }
$projectId = $projRes.data.createProjectV2.projectV2.id
Write-Host "Created project id: $projectId"

# 3) Find the Status field ID
$qFields = @'
query($projectId:ID!) {
  node(id:$projectId) {
    ... on ProjectV2 {
      fields(first:50) {
        nodes {
          ... on ProjectV2SingleSelectField { id name options { id name } }
        }
      }
    }
  }
}
'@
$fieldsRes = Gh-GraphQL $qFields @{ projectId=$projectId }
$statusField = $fieldsRes.data.node.fields.nodes | Where-Object { $_.name -eq "Status" } | Select-Object -First 1
if (-not $statusField) { throw "Could not find Status field on project." }
$statusFieldId = $statusField.id

# 4) Ensure Status options exist
$desired = @("Backlog","Ready","In Progress","Review / Validation","Blocked","Done")
$existing = @()
if ($statusField.options) { $existing = $statusField.options.name }

$qAddOptions = @'
mutation($projectId:ID!, $fieldId:ID!, $name:String!) {
  updateProjectV2Field(input:{
    projectId:$projectId,
    fieldId:$fieldId,
    addSingleSelectOptions:[{name:$name}]
  }) {
    projectV2Field { ... on ProjectV2SingleSelectField { id name } }
  }
}
'@

foreach ($opt in $desired) {
  if ($existing -contains $opt) {
    Write-Host "Status option exists: $opt"
  } else {
    Gh-GraphQL $qAddOptions @{ projectId=$projectId; fieldId=$statusFieldId; name=$opt } | Out-Null
    Write-Host "Added status option: $opt"
  }
}

# Re-fetch to get option IDs (needed to set status)
$fieldsRes2 = Gh-GraphQL $qFields @{ projectId=$projectId }
$statusField2 = $fieldsRes2.data.node.fields.nodes | Where-Object { $_.name -eq "Status" } | Select-Object -First 1
$backlogOpt = $statusField2.options | Where-Object { $_.name -eq "Backlog" } | Select-Object -First 1
if (-not $backlogOpt) { throw "Backlog option not found after creation." }
$backlogOptId = $backlogOpt.id

# 5) Get all issues in repo (we’ll filter by titles)
Write-Host "Fetching issues..."
$issues = gh issue list -R $Repo --limit 200 --json number,title,id | ConvertFrom-Json
$releaseIssues = $issues | Where-Object { $_.title -match '^\[P[1-4]\]' }

Write-Host ("Found Release issues: " + $releaseIssues.Count)

# 6) Add issues to project + set Status = Backlog
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
  }) {
    projectV2Item { id }
  }
}
'@

foreach ($iss in $releaseIssues) {
  try {
    $addRes = Gh-GraphQL $qAddItem @{ projectId=$projectId; contentId=$iss.id }
    $itemId = $addRes.data.addProjectV2ItemById.item.id

    Gh-GraphQL $qSetStatus @{ projectId=$projectId; itemId=$itemId; fieldId=$statusFieldId; optionId=$backlogOptId } | Out-Null
    Write-Host ("Added + set Backlog: #" + $iss.number + " " + $iss.title)
  } catch {
    Write-Host ("Skipped (maybe already added): #" + $iss.number + " " + $iss.title)
  }
}

Write-Host "Done. Open your GitHub Project and switch to Board view grouped by Status."
