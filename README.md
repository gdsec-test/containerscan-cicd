# containerscan-cicd

ContainerScanner codebase

Action : https://github.com/gdcorp-actions/container-scan

## How to contribute 💻

1. Install pre-commit hook.

```bash
$ python3 -m venv .venv # Create new python virtual envrionment

$ source .venv/bin/activate # Activate virtual envrionment

(.venv) $ pip install -r requirements.txt # Install required dependencies

(.venv) $ pre-commit install # Install pre-commit hook to your local env
```

2. Test your change.

```bash
$ cd docker # Change into docker folder.
export AWS_ACCESS_KEY_ID="someid"
export AWS_SECRET_ACCESS_KEY="somekey"
export AWS_SESSION_TOKEN="somesession"
export AWS_DEFAULT_REGION="someregion"
./docker $ go test ./... -coverprofile coverage.out -args -- -targeturl=some -githuburl=more -repo=test -commit=args -format=too -githubtoken=just -container=testing && go tool cover -func=coverage.out # Validate your code is passing unit test & covered.
```

3. Integration test.

```bash
$ cd test # Change into test folder.

./test $ okta # or whichever command you used to set AWS envs (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_SESSION_TOKEN)

./test $ ./integration_test.sh <ENV> # ENV - local|stabledev|stableprod|v1.1.1|...
```

4. Commit & create PR.

   - Make sure you've activated virtual environment; to get an access to pre-commit hook.
   - `pre-commit` installed from step 1 will be executed if you followed the instruction.

5. Build and versioning
   When building new version, go to `docker/Dockerfile` and set two vars:
   `CONTAINERSCAN_VERSION` as `x.x.x` - current version to be built and pushed to Golden images ECR
   `SCAN_ENV` as `dev` or `prod` - current environmet of version to be build
   `CONTAINERSCAN_VERSION` will be used to tag current build
   If you want to make current build stable and be used in Gtihub Actions or Jenkins CICD,
   you should go to `.varenv` file and make `stable<env>` be equal to current version in `CONTAINERSCAN_VERSION`
   In this case image will be taggedf as `stable<env>` in Golden images ECR

## CICD

Self-hosted VM for Github Actions

- Name: cicd-contnrscan
- Project: cloud-security
- Check [Stdandards-Best-Practice](https://github.secureserver.net/CTO/guidelines/blob/master/Standards-Best-Practices/CICD/GitHubActions.md) for more information.
