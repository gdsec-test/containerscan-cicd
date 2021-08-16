#!/bin/bash
TEST_TARGET=$1

if [ -z "$TEST_TARGET" ]; then
    echo -e "\033[31m\n[-] Must run script with an Argument <local|stabledev|stableprod|v2.0.0|...> \n[-] ex) $0 local\033[0m"
    exit
fi

echo -e "\n[+] Setup required containers\n"

NUMBER_OF_TESTS=0

export CONTAINER_GOOD=containerscan-test:good
export CONTAINER_BAD=containerscan-test:bad

export AWS_DEFAULT_REGION=us-west-2
export TARGET_URL=https://github.com/gdcorp-infosec/containerscan-cicd
export GITHUB_URL=https://github.com/
export GITHUB_REPO=gdcorp-infosec/containerscan-cicd
export COMMIT_SHA=github-commit-sha-change-me-if-you-want
export PAT=github-PAT-token-change-me-if-you-want

echo -e "\n[+] Logging into golden AMI account\n"
aws ecr get-login-password --region us-west-2 | docker login --username AWS --password-stdin 764525110978.dkr.ecr.us-west-2.amazonaws.com
if [ $? -ne 0 ]; then
    exit
fi

DOCKER_SCAN_SUGGEST=false docker build -t ${CONTAINER_GOOD} . -f go.good.Dockerfile
if [ $? -ne 0 ]; then
    exit
fi

DOCKER_SCAN_SUGGEST=false docker build -t ${CONTAINER_BAD} . -f go.bad.Dockerfile
if [ $? -ne 0 ]; then
    exit
fi

if [ "$TEST_TARGET" = "local" ]; then
    export SCANNER_IMAGE=container-scan:local
    echo -e "\n[+] Building latest container-scan from local docker/ \n"
    DOCKER_SCAN_SUGGEST=false docker build -t ${SCANNER_IMAGE} ../docker/.
    if [ $? -ne 0 ]; then
        exit
    fi
else
    export SCANNER_IMAGE=764525110978.dkr.ecr.us-west-2.amazonaws.com/container-scan:$TEST_TARGET
    echo -e "\n[+] Pulling latest container-scan $TEST_TARGET\n\n"
    docker pull ${SCANNER_IMAGE}
    if [ $? -ne 0 ]; then
        exit
    fi
fi

echo -e "\n\n"
echo -e "[+] ####################################"
echo -e "[+] #            no status             #"
echo -e "[+] ####################################"
echo -e "\n"

(( NUMBER_OF_TESTS++ ))
echo -e "\n\n[+] ${NUMBER_OF_TESTS}. Test Happy Path\n"
docker run \
    --rm \
    -u root \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    -e AWS_ACCESS_KEY_ID \
    -e AWS_SECRET_ACCESS_KEY \
    -e AWS_SESSION_TOKEN \
    -e AWS_DEFAULT_REGION \
    -e CONTAINER=${CONTAINER_GOOD} \
    -e SCANNER_STATUS=nostatus \
    ${SCANNER_IMAGE}
echo -e "\033[36m\n[+] Result : $?\n\033[0m"


(( NUMBER_OF_TESTS++ ))
echo -e "\n\n[+] ${NUMBER_OF_TESTS}. Test with AWS_DEFAULT_REGION to unsupported region\n"
docker run \
    --rm \
    -u root \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    -e AWS_ACCESS_KEY_ID \
    -e AWS_SECRET_ACCESS_KEY \
    -e AWS_SESSION_TOKEN \
    -e AWS_DEFAULT_REGION=ap-southeast-1 \
    -e CONTAINER=${CONTAINER_GOOD} \
    -e SCANNER_STATUS=nostatus \
    ${SCANNER_IMAGE}
echo -e "\033[36m\n[+] Result : $?\n\033[0m"


(( NUMBER_OF_TESTS++ ))
echo -e "\n\n[+] ${NUMBER_OF_TESTS}. Test environment variable AWS_ACCESS_KEY_ID & AWS_SESSION_TOKEN are missing\n"
docker run \
    --rm \
    -u root \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    -e AWS_SECRET_ACCESS_KEY \
    -e AWS_DEFAULT_REGION \
    -e CONTAINER=${CONTAINER_GOOD} \
    -e SCANNER_STATUS=nostatus \
    ${SCANNER_IMAGE}
echo -e "\033[36m\n[+] Result : $?\n\033[0m"


(( NUMBER_OF_TESTS++ ))
echo -e "\n\n[+] ${NUMBER_OF_TESTS}. Test environment variable CONTAINER is missing\n"
docker run \
    --rm \
    -u root \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    -e AWS_ACCESS_KEY_ID \
    -e AWS_SECRET_ACCESS_KEY \
    -e AWS_SESSION_TOKEN \
    -e AWS_DEFAULT_REGION \
    -e SCANNER_STATUS=nostatus \
    ${SCANNER_IMAGE}
echo -e "\033[36m\n[+] Result : $?\n\033[0m"


(( NUMBER_OF_TESTS++ ))
echo -e "\n\n[+] ${NUMBER_OF_TESTS}. Test Invalid env value passed in to environment variable AWS_SECRET_ACCESS_KEY\n"
docker run \
    --rm \
    -u root \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    -e AWS_ACCESS_KEY_ID \
    -e AWS_SECRET_ACCESS_KEY=abcdefg \
    -e AWS_SESSION_TOKEN \
    -e AWS_DEFAULT_REGION \
    -e CONTAINER=${CONTAINER_GOOD} \
    -e SCANNER_STATUS=nostatus \
    ${SCANNER_IMAGE}
echo -e "\033[36m\n[+] Result : $?\n\033[0m"


(( NUMBER_OF_TESTS++ ))
echo -e "\n\n[+] ${NUMBER_OF_TESTS}. Test container vulnerability found\n"
docker run \
    --rm \
    -u root \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    -e AWS_ACCESS_KEY_ID \
    -e AWS_SECRET_ACCESS_KEY \
    -e AWS_SESSION_TOKEN \
    -e AWS_DEFAULT_REGION \
    -e CONTAINER=${CONTAINER_BAD} \
    -e SCANNER_STATUS=nostatus \
    ${SCANNER_IMAGE}
echo -e "\033[36m\n[+] Result : $?\n\033[0m"


(( NUMBER_OF_TESTS++ ))
echo -e "\n\n[+] ${NUMBER_OF_TESTS}. Test FORMAT=json Happy Path\n"
docker run \
    --rm \
    -u root \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    -e AWS_ACCESS_KEY_ID \
    -e AWS_SECRET_ACCESS_KEY \
    -e AWS_SESSION_TOKEN \
    -e AWS_DEFAULT_REGION \
    -e CONTAINER=${CONTAINER_GOOD} \
    -e SCANNER_STATUS=nostatus \
    -e FORMAT=json \
    ${SCANNER_IMAGE}
echo -e "\033[36m\n[+] Result : $?\n\033[0m"


(( NUMBER_OF_TESTS++ ))
echo -e "\n\n[+] ${NUMBER_OF_TESTS}. Test FORMAT=json with AWS_DEFAULT_REGION to unsupported region\n"
docker run \
    --rm \
    -u root \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    -e AWS_ACCESS_KEY_ID \
    -e AWS_SECRET_ACCESS_KEY \
    -e AWS_SESSION_TOKEN \
    -e AWS_DEFAULT_REGION=ap-southeast-1 \
    -e CONTAINER=${CONTAINER_GOOD} \
    -e SCANNER_STATUS=nostatus \
    -e FORMAT=json \
    ${SCANNER_IMAGE}
echo -e "\033[36m\n[+] Result : $?\n\033[0m"


(( NUMBER_OF_TESTS++ ))
echo -e "\n\n[+] ${NUMBER_OF_TESTS}. Test FORMAT=json environment variable AWS_ACCESS_KEY_ID & AWS_SESSION_TOKEN are missing\n"
docker run \
    --rm \
    -u root \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    -e AWS_SECRET_ACCESS_KEY \
    -e AWS_DEFAULT_REGION \
    -e CONTAINER=${CONTAINER_GOOD} \
    -e SCANNER_STATUS=nostatus \
    -e FORMAT=json \
    ${SCANNER_IMAGE}
echo -e "\033[36m\n[+] Result : $?\n\033[0m"


(( NUMBER_OF_TESTS++ ))
echo -e "\n\n[+] ${NUMBER_OF_TESTS}. Test FORMAT=json Invalid env value passed in to environment variable AWS_SECRET_ACCESS_KEY\n"
docker run \
    --rm \
    -u root \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    -e AWS_ACCESS_KEY_ID \
    -e AWS_SECRET_ACCESS_KEY=abcdefg \
    -e AWS_SESSION_TOKEN \
    -e AWS_DEFAULT_REGION \
    -e CONTAINER=${CONTAINER_GOOD} \
    -e SCANNER_STATUS=nostatus \
    -e FORMAT=json \
    ${SCANNER_IMAGE}
echo -e "\033[36m\n[+] Result : $?\n\033[0m"


(( NUMBER_OF_TESTS++ ))
echo -e "\n\n[+] ${NUMBER_OF_TESTS}. Test FORMAT=json container vulnerability found\n"
docker run \
    --rm \
    -u root \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    -e AWS_ACCESS_KEY_ID \
    -e AWS_SECRET_ACCESS_KEY \
    -e AWS_SESSION_TOKEN \
    -e AWS_DEFAULT_REGION \
    -e CONTAINER=${CONTAINER_BAD} \
    -e SCANNER_STATUS=nostatus \
    -e FORMAT=json \
    ${SCANNER_IMAGE}
echo -e "\033[36m\n[+] Result : $?\n\033[0m"

echo -e "\n\n"
echo -e "[+] ####################################"
echo -e "[+] #          github status           #"
echo -e "[+] ####################################"
echo -e "\n"

(( NUMBER_OF_TESTS++ ))
echo -e "\n\n[+] ${NUMBER_OF_TESTS}. Test Happy Path\n"
docker run \
    --rm \
    -u root \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    -e AWS_ACCESS_KEY_ID \
    -e AWS_SECRET_ACCESS_KEY \
    -e AWS_SESSION_TOKEN \
    -e AWS_DEFAULT_REGION \
    -e CONTAINER=${CONTAINER_GOOD} \
    -e TARGET_URL=${TARGET_URL} \
    -e GITHUB_URL=${GITHUB_URL} \
    -e GITHUB_REPO=${GITHUB_REPO} \
    -e COMMIT_SHA=${COMMIT_SHA} \
    -e PAT=${PAT} \
    ${SCANNER_IMAGE}
echo -e "\033[36m\n[+] Result : $?\n\033[0m"

(( NUMBER_OF_TESTS++ ))
echo -e "\n\n[+] ${NUMBER_OF_TESTS}. Test with AWS_DEFAULT_REGION to unsupported region\n"
docker run \
    --rm \
    -u root \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    -e AWS_ACCESS_KEY_ID \
    -e AWS_SECRET_ACCESS_KEY \
    -e AWS_SESSION_TOKEN \
    -e AWS_DEFAULT_REGION=ap-southeast-1 \
    -e CONTAINER=${CONTAINER_GOOD} \
    -e TARGET_URL=${TARGET_URL} \
    -e GITHUB_URL=${GITHUB_URL} \
    -e GITHUB_REPO=${GITHUB_REPO} \
    -e COMMIT_SHA=${COMMIT_SHA} \
    -e PAT=${PAT} \
    ${SCANNER_IMAGE}
echo -e "\033[36m\n[+] Result : $?\n\033[0m"


(( NUMBER_OF_TESTS++ ))
echo -e "\n\n[+] ${NUMBER_OF_TESTS}. Test environment variable AWS_ACCESS_KEY_ID & AWS_SESSION_TOKEN are missing\n"
docker run \
    --rm \
    -u root \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    -e AWS_SECRET_ACCESS_KEY \
    -e AWS_DEFAULT_REGION \
    -e CONTAINER=${CONTAINER_GOOD} \
    -e TARGET_URL=${TARGET_URL} \
    -e GITHUB_URL=${GITHUB_URL} \
    -e GITHUB_REPO=${GITHUB_REPO} \
    -e COMMIT_SHA=${COMMIT_SHA} \
    -e PAT=${PAT} \
    ${SCANNER_IMAGE}
echo -e "\033[36m\n[+] Result : $?\n\033[0m"


(( NUMBER_OF_TESTS++ ))
echo -e "\n\n[+] ${NUMBER_OF_TESTS}. Test environment variable CONTAINER is missing\n"
docker run \
    --rm \
    -u root \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    -e AWS_ACCESS_KEY_ID \
    -e AWS_SECRET_ACCESS_KEY \
    -e AWS_SESSION_TOKEN \
    -e AWS_DEFAULT_REGION \
    -e TARGET_URL=${TARGET_URL} \
    -e GITHUB_URL=${GITHUB_URL} \
    -e GITHUB_REPO=${GITHUB_REPO} \
    -e COMMIT_SHA=${COMMIT_SHA} \
    -e PAT=${PAT} \
    ${SCANNER_IMAGE}
echo -e "\033[36m\n[+] Result : $?\n\033[0m"


(( NUMBER_OF_TESTS++ ))
echo -e "\n\n[+] ${NUMBER_OF_TESTS}. Test environment variable GITHUB_REPO & COMMIT_SHA are missing\n"
docker run \
    --rm \
    -u root \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    -e AWS_ACCESS_KEY_ID \
    -e AWS_SECRET_ACCESS_KEY \
    -e AWS_SESSION_TOKEN \
    -e AWS_DEFAULT_REGION \
    -e TARGET_URL=${TARGET_URL} \
    -e GITHUB_URL=${GITHUB_URL} \
    -e PAT=${PAT} \
    ${SCANNER_IMAGE}
echo -e "\033[36m\n[+] Result : $?\n\033[0m"


(( NUMBER_OF_TESTS++ ))
echo -e "\n\n[+] ${NUMBER_OF_TESTS}. Test Invalid env value passed in to environment variable AWS_SECRET_ACCESS_KEY\n"
docker run \
    --rm \
    -u root \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    -e AWS_ACCESS_KEY_ID \
    -e AWS_SECRET_ACCESS_KEY=abcdefg \
    -e AWS_SESSION_TOKEN \
    -e AWS_DEFAULT_REGION \
    -e CONTAINER=${CONTAINER_GOOD} \
    -e TARGET_URL=${TARGET_URL} \
    -e GITHUB_URL=${GITHUB_URL} \
    -e GITHUB_REPO=${GITHUB_REPO} \
    -e COMMIT_SHA=${COMMIT_SHA} \
    -e PAT=${PAT} \
    ${SCANNER_IMAGE}
echo -e "\033[36m\n[+] Result : $?\n\033[0m"


(( NUMBER_OF_TESTS++ ))
echo -e "\n\n[+] ${NUMBER_OF_TESTS}. Test container vulnerability found\n"
docker run \
    --rm \
    -u root \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    -e AWS_ACCESS_KEY_ID \
    -e AWS_SECRET_ACCESS_KEY \
    -e AWS_SESSION_TOKEN \
    -e AWS_DEFAULT_REGION \
    -e CONTAINER=${CONTAINER_BAD} \
    -e TARGET_URL=${TARGET_URL} \
    -e GITHUB_URL=${GITHUB_URL} \
    -e GITHUB_REPO=${GITHUB_REPO} \
    -e COMMIT_SHA=${COMMIT_SHA} \
    -e PAT=${PAT} \
    ${SCANNER_IMAGE}
echo -e "\033[36m\n[+] Result : $?\n\033[0m"


(( NUMBER_OF_TESTS++ ))
echo -e "\n\n[+] ${NUMBER_OF_TESTS}. Test FORMAT=json Happy Path\n"
docker run \
    --rm \
    -u root \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    -e AWS_ACCESS_KEY_ID \
    -e AWS_SECRET_ACCESS_KEY \
    -e AWS_SESSION_TOKEN \
    -e AWS_DEFAULT_REGION \
    -e CONTAINER=${CONTAINER_GOOD} \
    -e TARGET_URL=${TARGET_URL} \
    -e GITHUB_URL=${GITHUB_URL} \
    -e GITHUB_REPO=${GITHUB_REPO} \
    -e COMMIT_SHA=${COMMIT_SHA} \
    -e PAT=${PAT} \
    -e FORMAT=json \
    ${SCANNER_IMAGE}
echo -e "\033[36m\n[+] Result : $?\n\033[0m"

(( NUMBER_OF_TESTS++ ))
echo -e "\n\n[+] ${NUMBER_OF_TESTS}. Test FORMAT=json with AWS_DEFAULT_REGION to unsupported region\n"
docker run \
    --rm \
    -u root \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    -e AWS_ACCESS_KEY_ID \
    -e AWS_SECRET_ACCESS_KEY \
    -e AWS_SESSION_TOKEN \
    -e AWS_DEFAULT_REGION=ap-southeast-1 \
    -e CONTAINER=${CONTAINER_GOOD} \
    -e TARGET_URL=${TARGET_URL} \
    -e GITHUB_URL=${GITHUB_URL} \
    -e GITHUB_REPO=${GITHUB_REPO} \
    -e COMMIT_SHA=${COMMIT_SHA} \
    -e PAT=${PAT} \
    -e FORMAT=json \
    ${SCANNER_IMAGE}
echo -e "\033[36m\n[+] Result : $?\n\033[0m"


(( NUMBER_OF_TESTS++ ))
echo -e "\n\n[+] ${NUMBER_OF_TESTS}. Test FORMAT=json environment variable AWS_ACCESS_KEY_ID & AWS_SESSION_TOKEN are missing\n"
docker run \
    --rm \
    -u root \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    -e AWS_SECRET_ACCESS_KEY \
    -e AWS_DEFAULT_REGION \
    -e CONTAINER=${CONTAINER_GOOD} \
    -e TARGET_URL=${TARGET_URL} \
    -e GITHUB_URL=${GITHUB_URL} \
    -e GITHUB_REPO=${GITHUB_REPO} \
    -e COMMIT_SHA=${COMMIT_SHA} \
    -e PAT=${PAT} \
    -e FORMAT=json \
    ${SCANNER_IMAGE}
echo -e "\033[36m\n[+] Result : $?\n\033[0m"


(( NUMBER_OF_TESTS++ ))
echo -e "\n\n[+] ${NUMBER_OF_TESTS}. Test FORMAT=json Invalid env value passed in to environment variable AWS_SECRET_ACCESS_KEY\n"
docker run \
    --rm \
    -u root \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    -e AWS_ACCESS_KEY_ID \
    -e AWS_SECRET_ACCESS_KEY=abcdefg \
    -e AWS_SESSION_TOKEN \
    -e AWS_DEFAULT_REGION \
    -e CONTAINER=${CONTAINER_GOOD} \
    -e TARGET_URL=${TARGET_URL} \
    -e GITHUB_URL=${GITHUB_URL} \
    -e GITHUB_REPO=${GITHUB_REPO} \
    -e COMMIT_SHA=${COMMIT_SHA} \
    -e PAT=${PAT} \
    -e FORMAT=json \
    ${SCANNER_IMAGE}
echo -e "\033[36m\n[+] Result : $?\n\033[0m"


(( NUMBER_OF_TESTS++ ))
echo -e "\n\n[+] ${NUMBER_OF_TESTS}. Test FORMAT=json container vulnerability found\n"
docker run \
    --rm \
    -u root \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    -e AWS_ACCESS_KEY_ID \
    -e AWS_SECRET_ACCESS_KEY \
    -e AWS_SESSION_TOKEN \
    -e AWS_DEFAULT_REGION \
    -e CONTAINER=${CONTAINER_BAD} \
    -e TARGET_URL=${TARGET_URL} \
    -e GITHUB_URL=${GITHUB_URL} \
    -e GITHUB_REPO=${GITHUB_REPO} \
    -e COMMIT_SHA=${COMMIT_SHA} \
    -e PAT=${PAT} \
    -e FORMAT=json \
    ${SCANNER_IMAGE}
echo -e "\033[36m\n[+] Result : $?\n\033[0m"


echo -e "\n\n"
echo -e "[+] ####################################"
echo -e "[+] #              result              #"
echo -e "[+] ####################################"
echo -e "\n"

echo -e "\n[+] Finished running ${NUMBER_OF_TESTS} tests."
