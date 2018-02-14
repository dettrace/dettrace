pipeline {
  agent any

  environment {
    PATH = "$PATH"
  }

  stages {
    stage('Build') {
      steps {
        echo "PATH is: $PATH"
		sh './runTests.sh'
      }
    }
  }
}
