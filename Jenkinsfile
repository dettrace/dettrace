pipeline {
  // This is designed to run on Cutter @ IU
  agent {
    label 'linux-ubuntu-1404'
  }

  triggers {
      // Try to create a webhook:
      pollSCM('')
  }

  stages {
    stage('Build') {
      steps {
        echo "PATH is: $PATH"
        sh "lsb_release -a"
        // Warning: this has global side effects.  Cannot run twice on one machine:
        sh "make docker"
        sh "make test-docker"
      }
    }
  }
  post {
    failure {
      slackSend (color: '#FF0000', message: "FAILED: Job '${env.JOB_NAME} [${env.BUILD_NUMBER}]' (${env.BUILD_URL})")
    }
  }
}
