import * as core from '@actions/core';
import * as github from '@actions/github';
import axios from 'axios';

const PoweredBy = "\n_Powered by [Azure Client Tools Agent](https://github.com/Azure/issue-sentinel)_";
const AgentServiceRequestAttempts = 3;
// This legacy resource hostname is a compatibility contract for existing consumers.
const AgentIssueIntelligenceUrl = 'https://similar-bot-prod-v2.wonderfulstone-4279f63d.eastus.azurecontainerapps.io';

class AgentServiceUnavailableError extends Error {
    constructor(endpoint: string, status?: number) {
        const statusMessage = status ? `HTTP ${status}` : 'a network error';
        super(`Azure Client Tools Agent endpoint ${endpoint} remained unavailable after ${AgentServiceRequestAttempts} attempts (${statusMessage}).`);
        this.name = 'AgentServiceUnavailableError';
    }
}

function isRetryableAgentServiceError(error: unknown): boolean {
    if (!axios.isAxiosError(error)) {
        return false;
    }

    const status = error.response?.status;
    return status === undefined || status === 408 || status === 429 || status >= 500;
}

async function postToAgentService<T>(endpoint: string, data: unknown): Promise<T> {
    for (let attempt = 1; attempt <= AgentServiceRequestAttempts; attempt++) {
        try {
            return (await axios.post<T>(AgentIssueIntelligenceUrl + endpoint, data)).data;
        }
        catch (error: unknown) {
            if (!isRetryableAgentServiceError(error)) {
                throw error;
            }

            const status = axios.isAxiosError(error) ? error.response?.status : undefined;
            if (attempt === AgentServiceRequestAttempts) {
                throw new AgentServiceUnavailableError(endpoint, status);
            }

            const statusMessage = status ? `HTTP ${status}` : 'network error';
            core.warning(`Azure Client Tools Agent endpoint ${endpoint} returned ${statusMessage}; retrying (${attempt}/${AgentServiceRequestAttempts}).`);
            await new Promise(resolve => setTimeout(resolve, attempt * 1000));
        }
    }

    throw new Error(`Azure Client Tools Agent endpoint ${endpoint} retry loop ended unexpectedly.`);
}

async function runAgentScan(name: string, scan: () => Promise<void>) {
    try {
        await scan();
    }
    catch (error: unknown) {
        if (error instanceof AgentServiceUnavailableError) {
            core.warning(`${name} skipped: ${error.message}`);
            return;
        }
        throw error;
    }
}

async function main() {
    try {
        const token = core.getInput('github-token', { required: true });
        const enable_similar_issues_scanning = core.getInput('enable-similar-issues-scanning');
        const enable_security_issues_scanning = core.getInput('enable-security-issues-scanning');
        const enable_ux_tag = core.getInput('enable-ux-tag');
        if (enable_similar_issues_scanning !== 'true' && enable_security_issues_scanning !== 'true' && enable_ux_tag !== 'true') {
            throw new Error('Invalid input! Similar issues scanning, security issues scanning, and UX tag are all disabled. Please enable at least one of them.');
        }

        const context = github.context;
        if (!context.payload.issue) {
            throw new Error("No issue found in the context payload. Please check your workflow trigger is 'issues'");
        }
        const issue = context.payload.issue;
        core.debug(`Issue: ${JSON.stringify(issue)}`);
        const { owner, repo } = context.repo;

        if (enable_similar_issues_scanning === 'true') {
            await runAgentScan(
                'Similar issues scanning',
                () => handleSimilarIssuesScanning(issue, owner, repo, token)
            );
        }

        if (enable_security_issues_scanning === 'true') {
            core.debug(`Issue trigger: ${context.payload.action}`);
            if (context.payload.action !== 'opened') {
                core.info('Skip security issues scanning for edited and closed issue.');
            } 
            else {
                await runAgentScan(
                    'Security issues scanning',
                    () => handleSecurityIssuesScanning(issue, owner, repo, token)
                );
            }
        }

        if (enable_ux_tag === 'true') {
            core.debug(`Issue trigger: ${context.payload.action}`);
            if (context.payload.action !== 'opened') {
                core.info('Skip adding UX tag for edited and closed issue.');
            }
            else {
                await runAgentScan(
                    'UX tagging',
                    () => handleUXTag(issue, owner, repo, token)
                );
            }
        }
    }
    catch (error: any) {
        core.setFailed(error.message);
    }
}

async function handleSimilarIssuesScanning(issue: any, owner: string, repo: string, token: string) {
    const octokit = github.getOctokit(token);
    const issueNumber = issue.number;
    let owner_repo = `${owner}/${repo}`;
    owner_repo = owner_repo.toLowerCase();
    core.debug(`owner/repo: ${owner_repo}`);

    const if_closed: boolean = issue.state === 'closed';
    if (if_closed) {
        await postToAgentService('/update_issue/', {
            'raw': issue,
            'token': token
        });
        core.info('This issue was closed. Updated it in Azure Client Tools Agent issue intelligence.');
        return;
    }

    const if_replied = (await postToAgentService<{ result: boolean }>('/check_reply/', {
        'repo': owner_repo,
        'issue': issue.number,
        'token': token
    })).result;
    core.info('Check whether Azure Client Tools Agent already replied to this issue: ' + if_replied.toString());

    if (if_replied) {
        await postToAgentService('/update_issue/', {
            'raw': issue,
            'token': token
        });
        core.info('Azure Client Tools Agent already replied. Updated the edited content and skipped this issue.');
        return;
    }

    const response = await postToAgentService<{ predict: any[][], solution: any[] }>('/search/', {
        'raw': issue,
        'verify': true,
        'token': token //used for access issue comment to get possible solution
    });
    const prediction: any[][] = response.predict;
    core.info('Azure Client Tools Agent issue-intelligence search completed successfully.');
    core.debug(`Response: ${response}`);
    if (!prediction || prediction.length === 0) {
        core.info('No prediction found');
        return;
    }


    let message = 'Here are some similar issues that might help you. Please check if they can solve your problem.\n'
    for (const item of prediction) {
        message += `- #${item[item.length - 1]}\n`
    }

    const solution: any[] = response.solution;
    let isPossibleSolutionPresent: boolean = false;
    if (!solution || solution.length === 0) {
        core.info('No solution found');
    }
    else {
        isPossibleSolutionPresent = true;
        message += '------------\n\n**Possible solution (Extracted from existing issue, might be incorrect; please verify carefully)**\n\n';
        let solutionIndex = 1;
        for (const item of solution) {
            if (solution.length > 1) {
                message += `### Solution ${solutionIndex}:\n`;
            }
            message += item.solution + '\n\n'
            solutionIndex++;
            if (item.reference.length > 0) {
                message += '**Reference**:\n';
            }
            for (const ref of item.reference) {
                message += `- ${ref}\n`;
            }
        }
    }
    message += PoweredBy;

    // Check reply status again before adding labels and comments to prevent duplicate labels and comments
    const if_replied_again = (await postToAgentService<{ result: boolean }>('/check_reply/', {
        'repo': owner_repo,
        'issue': issue.number,
        'token': token
    })).result;

    if (if_replied_again) {
        core.info('Azure Client Tools Agent replied during processing. Skipped duplicate labels and comments.');
        return;
    }

    let labels = ["Similar-Issue"];
    if (isPossibleSolutionPresent) {
        labels.push("Possible-Solution");
    }
    await octokit.rest.issues.addLabels({
        owner,
        repo,
        issue_number: issueNumber,
        labels
    });
    core.info(`Labels added to issue #${issueNumber}`);

    message = message.trimEnd();
    await octokit.rest.issues.createComment({
        owner,
        repo,
        issue_number: issueNumber,
        body: message
    });
    core.info(`Comment sent to issue #${issueNumber}`);

    await postToAgentService('/add_reply/', {
        'repo': owner_repo,
        'issue': issue.number,
        'token': token
    });
    core.info('Saved the reply state in Azure Client Tools Agent issue intelligence.');
}

async function handleSecurityIssuesScanning(issue: any, owner: string, repo: string, token: string) {
    const octokit = github.getOctokit(token);
    const issueNumber = issue.number;
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

    const if_security = (await postToAgentService<{ security: boolean }>('/security/', {
        'raw': issue,
        'token': token
    })).security;
    core.info('Azure Client Tools Agent security classification completed successfully.');
    core.debug(`Response: ${if_security}`);

    if (!if_security) {
        core.info('Not a security issue.');
        return;
    }

    let message = 'This issue is related to security. Please pay attention.\n'
    message += PoweredBy;
    await octokit.rest.issues.createComment({
        owner,
        repo,
        issue_number: issueNumber,
        body: message
    });
    core.info(`Comment sent to issue #${issueNumber}`);

    const labels = ["Security-Issue"];
    await octokit.rest.issues.addLabels({
        owner,
        repo,
        issue_number: issueNumber,
        labels
    });
    core.info(`Label added to issue #${issueNumber}`);
}

async function handleUXTag(issue: any, owner: string, repo: string, token: string) {
    const octokit = github.getOctokit(token);
    const issueNumber = issue.number;
    const tagName = (await postToAgentService<{ tag: string | null }>('/ux_tag/', {
        'raw': issue,
        'token': token
    })).tag;
    core.info('Azure Client Tools Agent UX classification completed successfully.');

    if (!tagName) {
        core.info('No UX tag found.');
        return;
    }

    const labels = [tagName];
    await octokit.rest.issues.addLabels({
        owner,
        repo,
        issue_number: issueNumber,
        labels
    });
    core.info(`UX Tag ${tagName} added to issue #${issueNumber}`);
}

main();