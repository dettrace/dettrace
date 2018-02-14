pipeline {
  agent any

  stages {
    stage('Build') {
      steps {
        echo "PATH is: $PATH"
		sh "bash runTests.sh"
      }
    }
  }
}
