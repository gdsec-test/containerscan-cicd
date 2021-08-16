# containerscan-cicd Integration Test

Integration testing framework

## Execution

### Run all tests with `stabledev` image from Golden AMI account ECR.

```bash
test/ $ okta
...

test/ $ go test -v -failfast --scannerTag=stabledev
```

### Run all tests with `local` scanner image from `docker/`.

```bash
test/ $ okta
...

test/ $ go test -v -failfast --scannerTag=local -timeout 20m
```

### Run all tests with `local` scanner image from `docker/`, specific test(s)

```bash
test/ $ okta
...

test/ $ go test -v -failfast --scannerTag=local -run <REGEX_TEST_NAME> -timeout 20m
```

### Run all tests with `local` scanner image from `docker/`, run through all tests even with failures in midway through.

```bash
test/ $ okta
...

test/ $ go test -v --scannerTag=local -run <REGEX> -timeout 20m
```
