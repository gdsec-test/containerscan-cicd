# containerscan-cicd

ContainerScanner codebase

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

./docker $ go test ./... -coverprofile coverage.out && go tool cover -html=coverage.out # Validate your code is passing unit test & covered.
```

3. Integration test.

```bash
$ cd test # Change into test folder.

./test $ cat Dockerfile # Review Dockerfile that will be tested.

./test $ okta # or whichever command you used to set AWS envs (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_SESSION_TOKEN)

./test $ chmod +x ./test.sh # (Optional) Make test script executable.

./test $ ./test.sh
```

4. Commit & create PR.
   - Make sure you've activated virtual environment; to get an access to pre-commit hook.
   - `pre-commit` installed from step 1 will be executed if you followed the instruction.

## CICD

Self-hosted VM for Github Actions

- Name: cicd-contnrscan
- Project: cloud-security
- Check [Stdandards-Best-Practice](https://github.secureserver.net/CTO/guidelines/blob/master/Standards-Best-Practices/CICD/GitHubActions.md) for more information.
