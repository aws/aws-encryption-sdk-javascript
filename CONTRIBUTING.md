# Contributing Guidelines

Thank you for your interest in contributing to our project.
Whether it's a bug report, new feature, correction, or additional documentation,
we greatly value feedback and contributions from our community.

Please read through this document before submitting any issues
or pull requests to ensure we have all the necessary information
to effectively respond to your bug report or contribution.

## Security issue notifications
If you discover a potential security issue in this project we ask that you notify AWS/Amazon Security
via our [vulnerability reporting page][vulnerability reporting].
Please do **not** create a public github issue.

## Reporting Bugs/Feature Requests

We welcome you to use the GitHub issue tracker to report bugs or suggest features.

When filing an issue, please check [existing open][issues], or [recently closed][recently closed],
issues to make sure somebody else hasn't already 
reported the issue.
Please try to include as much information as you can. Details like these are incredibly useful:

* A reproducible test case or series of steps
* The version of our code being used
* Any modifications you've made relevant to the bug
* Anything unusual about your environment or deployment


## Contributing via Pull Requests
Contributions via pull requests are much appreciated.
Before sending us a pull request, please ensure that:

1. You are working against the latest source on the *master* branch.
2. You check existing open, and recently merged,
   pull requests to make sure someone else hasn't addressed the problem already.
3. You open an issue to discuss any significant work - we would hate for your time to be wasted.

To send us a pull request, please:

1. Fork the repository.
2. Modify the source; please focus on the specific change you are contributing.
   If you also reformat all the code, it will be hard for us to focus on your change.
3. Ensure local tests pass.
4. Commit to your fork using clear commit messages.
   Your commit tile and message and pull request title and description must adhere to
   [conventional commits][conventional commits]. Title must begin with `feat(module): title`,
   `fix(module): title`, `docs(module): title`, `test(module): title`, `chore(module): title`.
   Title should be lowercase and not period at the end of it. If the commit includes
   a breaking change, the commit message must end with a single paragraph: `BREAKING CHANGE: a description of what broke`
5. Send us a pull request, answering any default questions in the pull request interface.
6. Pay attention to any automated CI failures reported in the pull request, and stay involved in the conversation.

GitHub provides additional document on [forking a repository](https://help.github.com/articles/fork-a-repo/) and 
[creating a pull request](https://help.github.com/articles/creating-a-pull-request/).


## Finding contributions to work on
Looking at the existing issues is a great way to find something to contribute on.
As our projects, by default, use the default GitHub issue labels ((enhancement/bug/duplicate/help wanted/invalid/question/wontfix),
looking at any [help wanted][help wanted] issues is a great place to start. 


## Code of Conduct
This project has adopted the [Amazon Open Source Code of Conduct][code of conduct]. 
For more information see the [Code of Conduct FAQ][code of conduct faq] or contact 
opensource-codeofconduct@amazon.com with any additional questions or comments.

## Licensing

See the [LICENSE][license] file for our project's licensing.
We will ask you to confirm the licensing of your contribution.

We may ask you to sign a [Contributor License Agreement (CLA)][cla] for larger changes.

[issues]: https://github.com/aws/aws-encryption-sdk-javascript/issues
[recently closed]: https://github.com/aws/aws-encryption-sdk-javascript/issues?utf8=%E2%9C%93&q=is%3Aissue%20is%3Aclosed%20
[help wanted]: https://github.com/aws/aws-encryption-sdk-javascript/labels/help%20wanted
[pr]: https://github.com/aws/aws-encryption-sdk-javascript/pulls
[license]: https://github.com/aws/aws-encryption-sdk-javascript/blob/master/LICENSE
[cla]: http://en.wikipedia.org/wiki/Contributor_License_Agreement
[vulnerability reporting]: http://aws.amazon.com/security/vulnerability-reporting/
[code of conduct]: https://aws.github.io/code-of-conduct
[code of conduct faq]: https://aws.github.io/code-of-conduct-faq

[conventional commits]: https://www.conventionalcommits.org/
