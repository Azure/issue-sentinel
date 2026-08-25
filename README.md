# Azure Client Tools Agent issue intelligence

This GitHub Action exposes Azure Client Tools Agent issue-intelligence
capabilities for similar-issue discovery, security classification, and UX
classification.

The repository and action reference remain `Azure/issue-sentinel@v1` for
backward compatibility. Existing consumers do not need to change their
workflows, secrets, or OpenID Connect configuration.

## Use Azure Client Tools Agent issue intelligence

1. Contact AzPyCLI@microsoft.com to onboard the repository to Azure Client
   Tools Agent issue intelligence.

1. Add the following workflow in your repository.

    ```yaml
    # File: .github/workflows/RunIssueSentinel.yml
    name: Run Azure Client Tools Agent issue intelligence
    on:
      issues:
        types: [opened, edited, closed]

    jobs:
      Issue:
        permissions:
          issues: write
        runs-on: ubuntu-latest
        steps:
          - name: Run Azure Client Tools Agent issue intelligence
            uses: Azure/issue-sentinel@v1
            with:
              enable-similar-issues-scanning: true # Scan similar issues in your repo, default: true
              enable-security-issues-scanning: true # Scan security issues in your repo, default: false
              enable-ux-tag: false # Add UX tags to issues (currently only designed for azure-cli), default: false
    ```

## Compatibility contract

- `Azure/issue-sentinel@v1` remains the stable public action reference.
- The production service hostname and HTTP routes remain unchanged.
- The GitHub repository name remains `issue-sentinel`; this avoids changes to
  consumer workflows, workflow dispatch, repository secrets, GitHub App
  installation scope, and Azure federated credentials.
- Legacy infrastructure names are implementation details of Azure Client Tools
  Agent, not a separate product identity.

## Development

Build the checked-in action bundle after changing `src/main.ts`:

```bash
npm ci
npm run build
```

## Used by

- [Azure CLI](https://github.com/Azure/azure-cli)
- [Azure PowerShell](https://github.com/Azure/azure-powershell)
- [Office JS](https://github.com/OfficeDev/office-js)
- [Microsoft Authentication Library (MSAL) for Python](https://github.com/AzureAD/microsoft-authentication-library-for-python)
- [Microsoft Authentication Library (MSAL) for .NET](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet)
