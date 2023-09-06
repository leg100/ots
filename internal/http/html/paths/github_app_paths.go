// Code generated by "go generate"; DO NOT EDIT.

package paths

import "fmt"

func GithubApps(organization string) string {
	return fmt.Sprintf("/app/organizations/%s/github-apps", organization)
}

func CreateGithubApp(organization string) string {
	return fmt.Sprintf("/app/organizations/%s/github-apps/create", organization)
}

func NewGithubApp(organization string) string {
	return fmt.Sprintf("/app/organizations/%s/github-apps/new", organization)
}

func GithubApp(githubApp string) string {
	return fmt.Sprintf("/app/github-apps/%s", githubApp)
}

func EditGithubApp(githubApp string) string {
	return fmt.Sprintf("/app/github-apps/%s/edit", githubApp)
}

func UpdateGithubApp(githubApp string) string {
	return fmt.Sprintf("/app/github-apps/%s/update", githubApp)
}

func DeleteGithubApp(githubApp string) string {
	return fmt.Sprintf("/app/github-apps/%s/delete", githubApp)
}

func ExchangeCodeGithubApp(organization string) string {
	return fmt.Sprintf("/app/organizations/%s/github-apps/exchange-code", organization)
}

func CompleteGithubApp(organization string) string {
	return fmt.Sprintf("/app/organizations/%s/github-apps/complete", organization)
}

func NewInstallGithubApp(githubApp string) string {
	return fmt.Sprintf("/app/github-apps/%s/new-install", githubApp)
}

func CreateInstallGithubApp(githubApp string) string {
	return fmt.Sprintf("/app/github-apps/%s/create-install", githubApp)
}