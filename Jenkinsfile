pipeline {
  // This is designed to run on Cutter @ IU
  agent {
    label 'linux-ubuntu-1404'
  }

  stages {
    stage('Build') {
      steps {
        echo "PATH is: $PATH"
        sh "lsb_release -a"
        // Warning: this has global side effects.  Cannot run twice on one machine:
        sh "make docker"
      }
    }
  }
}
