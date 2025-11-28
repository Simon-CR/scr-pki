### build instructions
- when building docker, always build for both arm64 and amd64
- use `docker buildx` to build multi-arch images
- tag images with both architecture and latest tags
- push images to the container registry after building

### when there's new changes:
- update the changelog in CHANGELOG.md
- update the roadmap in docs/ROADMAP.md if there are new planned features
- if there are breaking changes, update docs/UPGRADE.md with upgrade instructions
- update README.md if there are new configuration options or important changes
- push the latest changes to git repository

### testing
- in many cases, the test I'm doing are not on the machine where vscode is running, dont assume that vscode terminal is the same as the test machine

### coding
- try and always follow industry best practices for security and code quality
- use linters and formatters to maintain code consistency
- write unit tests for new features and bug fixes
- document code changes and new features thoroughly