pipeline {
  agent {
    label 'linux-ubuntu-1404'
  }

  stages {
    stage('Build') {
      steps {
        echo "PATH is: $PATH"
        sh "lsb_release -a"
        sh "module add gcc || echo ok"
        sh "which -a gcc"        
        sh "gcc -v"
        sh "bash runTests.sh"
      }
    }
  }
}
