pipeline {
  agent {
    label 'linux-ubuntu-1404'
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
