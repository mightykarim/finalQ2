pipeline {
    agent any

    environment {
        VENV_DIR = "venv"
        DEPLOY_DIR = "/tmp/flask_app_deploy"
    }

    stages {

        stage('Clone Repository') {
            steps {
                echo "Cloning latest code..."
                git branch: 'main',
                    url: 'https://github.com/mightykarim/finalQ2.git'
            }
        }

        stage('Install Dependencies') {
            steps {
                echo "Installing Python dependencies..."
                sh '''
                    python3 -m venv ${VENV_DIR}
                    . ${VENV_DIR}/bin/activate
                    pip install --upgrade pip
                    pip install -r requirements.txt
                '''
            }
        }

        stage('Run Unit Tests') {
            steps {
                echo "Running unit tests with pytest..."
                sh '''
                    . ${VENV_DIR}/bin/activate
                    pytest tests/
                '''
            }
        }

        stage('Build Application') {
            steps {
                echo "Building application..."
                sh '''
                    . ${VENV_DIR}/bin/activate
                    python -m py_compile app.py
                '''
            }
        }

        stage('Deploy Application (Simulated)') {
            steps {
                echo "Deploying application (simulation)..."
                sh '''
                    mkdir -p ${DEPLOY_DIR}
                    cp -r * ${DEPLOY_DIR}/
                    echo "Application deployed to ${DEPLOY_DIR}"
                '''
            }
        }
    }

    post {
        success {
            echo "Pipeline completed successfully 🎉"
        }
        failure {
            echo "Pipeline failed ❌"
        }
        always {
            echo "CI/CD pipeline execution finished"
        }
    }
}
