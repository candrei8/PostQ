// Jenkins pipeline for quant-scan PQC assessment
// Add to your Jenkinsfile

pipeline {
    agent any

    stages {
        stage('PQC Assessment') {
            steps {
                sh 'pip install quant-scan'
                sh '''
                    quant-scan scan . \
                        --format json \
                        --output quant-scan-report.json \
                        --severity info || true
                '''
                sh '''
                    quant-scan scan . \
                        --format html \
                        --output quant-scan-report.html || true
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'quant-scan-report.*', fingerprint: true
                    publishHTML(target: [
                        allowMissing: true,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportDir: '.',
                        reportFiles: 'quant-scan-report.html',
                        reportName: 'PQC Assessment Report'
                    ])
                }
            }
        }
    }
}
