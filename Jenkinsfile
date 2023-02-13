node {
      stage("Git Clone"){

        git branch: 'main', url: 'https://github.com/Development456/UserLogin.git'
      }
   
      stage("Docker build"){
        sh 'docker build -t userlogin .'
        sh 'docker image ls'
      }
       withCredentials([[$class: 'UsernamePasswordMultiBinding', credentialsId: 'test', usernameVariable: 'apurva', passwordVariable: 'password']]) {
        sh 'docker login -u apurva@09 -p $password'
      }
      stage("Pushing Image to Docker Hub"){
	sh 'docker tag userlogin apurva/userlogin:latest'
	sh 'docker push apurva/userlogin:latest'
      }
      stage("SSH Into Server") {
       def remote = [:]
       remote.name = 'DEV-VM'
       remote.host = '20.62.171.46'
       remote.user = 'dev_azureuser'
       remote.password = 'AHTgxKmRGb05'
       remote.allowAnyHosts = true
     }
     stage("Deploy"){
	     sh 'docker stop userlogin|| true && docker rm -f userlogin || true'
	     sh 'docker run -d -p 9003:9003 --name userlogin userlogin:latest'
     }
    }
