import axios, { AxiosError } from 'axios';
import { GITHUB_USER_URL } from './config';
import { GitHubUser } from './types';

function buildHeaders(accessToken: string) {
    return {
        Accept: 'application/vnd.github+json',
        Authorization: `Bearer ${accessToken}`,
    };
}

export function isGitHubAuthFailure(error: unknown): boolean {
    const status = (error as AxiosError)?.response?.status || (error as { status?: number })?.status;
    if (status === 401 || status === 403) {
        return true;
    }

    return (error as { isGitHubAuthFailure?: boolean })?.isGitHubAuthFailure === true;
}

export class GitHubApiClient {
    async fetchCurrentUser(accessToken: string): Promise<GitHubUser> {
        const response = await axios.get(GITHUB_USER_URL, {
            headers: buildHeaders(accessToken),
            timeout: 10000,
        });

        return {
            id: response.data.id,
            login: response.data.login,
            avatarUrl: response.data.avatar_url,
            name: response.data.name || undefined,
        };
    }
}
