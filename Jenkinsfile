pipeline {
  agent {
    label 'linux-sice-RHEL'
  }

  stages {
    stage('Build') {
      steps {
        echo "PATH is: $PATH"
        sh "bash runTests.sh"
      }
    }
  }
}
