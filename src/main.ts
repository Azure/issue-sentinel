import * as core from '@actions/core';
import * as github from '@actions/github';
import axios from 'axios';

async function main() {
    try {
        const password = core.getInput('password');
        //TODO: use github token for authentication
        const token = core.getInput('github-token', { required: true })

        const botUrl = 'https://similar-bot-prod.calmhill-ec497646.eastus.azurecontainerapps.io';
        const context = github.context;
        if (!context.payload.issue) {
            throw new Error("No issue found in the context payload. Please check your workflow trigger is 'issues'");
        }
        const issue = context.payload.issue;
        core.debug(`Issue: ${JSON.stringify(issue)}`);
        const { owner, repo } = github.context.repo;
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
    catch (error: any) {
        core.setFailed(error.message);
    }
}

main();  
