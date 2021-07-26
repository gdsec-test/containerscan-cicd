echo "#### MAKE SURE TO SET FOLLOWING VALUES ####"
echo
echo " AWS_ACCESS_KEY_ID"
echo " AWS_SECRET_ACCESS_KEY"
echo " AWS_SESSION_TOKEN"
echo
echo " Plesase replace <...> with necessary fields to run test scripts"
echo

CONTAINER=containerscan-cicd-test:latest

docker build -t ${CONTAINER} . -f good.Dockerfile

aws ecr get-login-password --region us-west-2 | docker login --username AWS --password-stdin 764525110978.dkr.ecr.us-west-2.amazonaws.com

export AWS_DEFAULT_REGION=us-west-2

docker build -t twisttest ../docker/.

docker run \
    --rm \
    -u root \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    -e AWS_ACCESS_KEY_ID \
    -e AWS_SECRET_ACCESS_KEY \
    -e AWS_SESSION_TOKEN \
    -e AWS_DEFAULT_REGION \
    -e CONTAINER=${CONTAINER} \
    -e SCANNER_STATUS=nostatus \
    -e FORMAT=json \
    twisttest:latest
