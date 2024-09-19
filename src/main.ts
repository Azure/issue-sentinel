import * as core from '@actions/core';
import * as github from '@actions/github';
import axios from 'axios';

async function main() {
    try {
        const password = core.getInput('password');
        //TODO: use github token for authentication
        const token = core.getInput('github-token', { required: true });
        const enable_similar_issues_scanning = core.getInput('enable-similar-issues-scanning');
        const enable_security_issues_scanning = core.getInput('enable-security-issues-scanning');
        if (enable_similar_issues_scanning !== 'true' && enable_security_issues_scanning !== 'true') {
            throw new Error('Invalid input! Both similar issues scanning and security issues scanning are disabled. Please enable at least one of them.');
        }

        const botUrl = 'https://similar-bot-prod.calmhill-ec497646.eastus.azurecontainerapps.io';
        const context = github.context;
        if (!context.payload.issue) {
            throw new Error("No issue found in the context payload. Please check your workflow trigger is 'issues'");
        }
        const issue = context.payload.issue;
        core.debug(`Issue: ${JSON.stringify(issue)}`);
        const { owner, repo } = github.context.repo;

        if (enable_similar_issues_scanning === 'true') {
            await handleSimilarIssuesScanning(issue, owner, repo, password, token, botUrl, context);
        }

        if (enable_security_issues_scanning === 'true') {
            await handleSecurityIssuesScanning(issue, owner, repo, password, token, botUrl, context);
        }
    }
    catch (error: any) {
        core.setFailed(error.message);
    }
}

async function handleSimilarIssuesScanning(issue: any, owner: string, repo: string, password: string, token: string, botUrl: string, context: any) {
    let owner_repo = `${owner}/${repo}`;
    owner_repo = owner_repo.toLowerCase();
    core.debug(`owner/repo: ${owner_repo}`);

    const if_closed: boolean = issue.state === 'closed';
    if (if_closed) {
        await axios.post(botUrl + '/update_issue/', {
            'raw': issue,
            'password': password
        })
        core.info('This issue was closed. Update it to issue sentinel.');
        return;
    }

    const if_replied: boolean = (await axios.post(botUrl + '/check_reply/', {
        'repo': owner_repo,
        'issue': issue.number,
        'password': password
    })).data.result;
    core.info('Check if this issue was already replied by the sentinel: ' + if_replied.toString());

    if (if_replied) {
        await axios.post(botUrl + '/update_issue/', {
            'raw': issue,
            'password': password
        })
        core.info('This issue was already replied by the sentinel. Update the edited content to sentinel and skip this issue.');
        return;
    }

    const prediction: any[][] = (await axios.post(botUrl + '/search/', {
        'raw': issue,
        'password': password,
        'verify': true
    })).data.predict;
    core.info('Search by the issue sentinel successfully.');

    core.debug(`Response: ${prediction}`);
    if (!prediction || prediction.length === 0) {
        core.info('No prediction found');
        return;
    }
    let message = 'Here are some similar issues that might help you. Please check if they can solve your problem.\n'
    for (const item of prediction) {
        message += `- #${item[item.length - 1]}\n`
    }
    message = message.trimEnd();

    const octokit = github.getOctokit(token);
    const issueNumber = context.payload.issue.number;

    await octokit.rest.issues.createComment({
        owner,
        repo,
        issue_number: issueNumber,
        body: message
    });
    core.info(`Comment sended to issue #${issueNumber}`);

    const labels = ["Similar-Issue"];
    await octokit.rest.issues.addLabels({
        owner,
        repo,
        issue_number: issueNumber,
        labels
    });
    core.info(`Label added to issue #${issueNumber}`);

    await axios.post(botUrl + '/add_reply/', {
        'repo': owner_repo,
        'issue': issue.number,
        'password': password
    });
    core.info('Save replied issue to issue sentinel.');
}

async function handleSecurityIssuesScanning(issue: any, owner: string, repo: string, password: string, token: string, botUrl: string, context: any) {  
    const octokit = github.getOctokit(token);
    const issueNumber = context.payload.issue.number;
    const { data: existedLabels } = await octokit.rest.issues.listLabelsOnIssue({
        owner,
        repo,
        issue_number: issueNumber,
    });
    const labelExists = existedLabels.some((label: { name: string }) => label.name === "Security-Issue");
    
    if (labelExists) {
        core.info('This issue has already been labeled as Security-Issue. Skip this issue.');
        return;
    }
    
    const ifsecurity = (await axios.post(botUrl + '/security/', {
        'raw': issue,
        'password': password
    })).data.predict;
    core.info('Search the security issues by the issue sentinel successfully.');
    core.debug(`Response: ${ifsecurity}`);

    if (!ifsecurity) {
        core.info('Not a security issue.');
        return;
    }

    let message = 'This issue is related to security. Please pay attention.\n'
    await octokit.rest.issues.createComment({
        owner,
        repo,
        issue_number: issueNumber,
        body: message
    });
    core.info(`Comment sended to issue #${issueNumber}`);

    const labels = ["Security-Issue"];
    await octokit.rest.issues.addLabels({
        owner,
        repo,
        issue_number: issueNumber,
        labels
    });
    core.info(`Label added to issue #${issueNumber}`);
}

main();  
