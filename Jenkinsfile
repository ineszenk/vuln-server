pipeline {
    agent any
    environment {
        SEMGREP_CONFIG = "p/default"  // Configuration Semgrep (peut être modifiée selon les besoins)
    }
    stages {
        stage('Cloner le dépôt') {
            steps {
                git branch: 'main', url: 'https://github.com/korgrunt/vuln-server' // Remplace par l'URL du dépôt
            }
        }

        stage('Install and launch Semgrep') {
            steps {
                sh '''
                python3 -m venv venv
                . venv/bin/activate
                pip install semgrep
                semgrep --help # pour vérifier l’installation
                semgrep scan . > semgrep-report.txt
                '''
            }
        }
        
        stage('print Semgrep') {
            steps {
                sh '''
                echo "-------*****-------*****-------*****-------*****"
                cat ./semgrep-report.txt
                echo "-------*****-------*****-------*****-------*****"
                '''
            }
        }
        
        stage('Check for Code Findings') {
            steps {
                script {
                    def findingsFile = './semgrep-report.txt' // Remplace avec le chemin vers le fichier à vérifier
                    def findingsCheck = sh(script: "grep -q 'Code Findings' ${findingsFile}", returnStatus: true)
                    
                    if (findingsCheck == 0) {
                        error("security issue")
                    }
                }
            }
        }
        
    }
    post {
        always {
            cleanWs()  // Nettoyer le workspace après l'exécution
        }
    }
}
          