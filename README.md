# Issue Sentinel

Easily connect to the smart Issue Sentinel with this GitHub Action. It helps you handle similar issues in your repository efficiently.

## Use the Issue Sentinel

To use the Issue Sentinel, follow these steps:

1. Contact AzPyCLI@microsoft.com to get the password for the Sentinel. We will assist you with onboarding and add your repository to the database.

1. Add the `ISSUE_SENTINEL_PASSWORD` as a secret to your repository. Go to `Settings > Secrets and variables > Actions > New repository secret`.

1. Add the following workflow in your repository.

    ```yaml
    #File: .github/workflows/RunIssueSentinel.yml
    name: Run issue sentinel
    on:
      issues:
        types: [opened, edited, closed]

    jobs:
      Issue:
        permissions:
          issues: write
        runs-on: ubuntu-latest
        steps:
          - name: Run Issue Sentinel
            uses: Azure/issue-sentinel@v1
            with:
              password: ${{secrets.ISSUE_SENTINEL_PASSWORD}}
    ```

## Notes for developers

To build the action, use the following commands:

1. `npm install`

1. `npm run build`
