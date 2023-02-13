node {
      stage("Git Clone"){

        git branch: 'main', url: 'https://github.com/Development456/UserLogin.git'
      }
   
      stage("Docker build"){
        sh 'docker build -t userlogin .'
        sh 'docker image ls'
      }
       withCredentials([[$class: 'UsernamePasswordMultiBinding', credentialsId: 'test', usernameVariable: 'jsilaparasetti', passwordVariable: 'password']]) {
        sh 'docker login -u jsilaparasetti -p $password'
      }
      stage("Pushing Image to Docker Hub"){
	sh 'docker tag userlogin jsilaparasetti/userlogin:latest'
	sh 'docker push jsilaparasetti/userlogin:latest'
      }
      stage("SSH Into Server") {
       def remote = [:]
       remote.name = 'CLAIMS-VM'
       remote.host = '20.163.133.102'
       remote.user = 'azureuser'
       remote.password = 'Miracle@1234'
       remote.allowAnyHosts = true
     }
     stage("Deploy"){
	     sh 'docker stop userlogin|| true && docker rm -f userlogin || true'
	     sh 'docker run -d -p 9003:9003 --name userlogin userlogin:latest'
     }
    }
