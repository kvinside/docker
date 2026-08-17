pipeline{
    agent {
        node {
            label "linux"
        }
    }
    environment{
        IMAGE_NAME = "app-golang"
        CONTAINER_NAME = "app1"
        APP_PORT = '9000'
    }
    stages {
        stage('checkout'){
            steps{
                checkout scm
            }
        }
        stage('go test'){
            steps{
                sh 'go test ./...'
            }
        }
        stage('build docker image'){
            steps{
                sh 'docker build -t ${IMAGE_NAME}:latest .'
            }
        }
        stage('stop old container'){
            steps{
                sh '''
                    docker stop ${CONTAINER_NAME} || true
                    docker rm ${CONTAINER_NAME} || true
                '''
            }
        }
        stage('deploy'){
            steps{
                sh '''
                    docker run -d \
                    --name ${CONTAINER_NAME} \
                    -p ${APP_PORT}:${APP_PORT}\
                    ${IMAGE_NAME}:latest
                '''
            }
        }
        stage('verify'){
            steps{
                sh 'docker ps --filter name=${CONTAINER_NAME}'
            }
        }
    }
    post {
        success {
            echo 'CI/CD SUCCESS - app1 berhasil di deploy'
        }
        failure {
            echo 'CI/CD FAILED !'
        }
    }
}