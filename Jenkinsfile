//GLOBAL Variables Definition
def pvc_name="mvn-home"
def serviceaccount = "jenkins-admin"
def pvclabel = "pvc-creation-pod"
def cartridge_name = "java"
def cleanuplabel = "postbuild-cleanup-pod"
def librarylabel = "built-in"
//Added for starting podname with the name of te pod and build number
def PODNAME="${JOB_NAME.replace("_","").split('/')[1]}"
def label = PODNAME+"-${BUILD_ID}"
def GIT_URL=env.GIT_URL 
def GIT_CREDENTIAL_ID ='gitlab'
//If New Container-registry reference is required , we need to change both the below variable 'GCR_HUB_ACCOUNT_IMAGEBUILD' & 'GCR_HUB_ACCOUNT' with the same reference.
def GCR_HUB_ACCOUNT_IMAGEBUILD = 'gitlab:8223'
def GCR_HUB_ACCOUNT = 'localhost:32121'
def GCR_HUB_ACCOUNT_NAME = 'root'
def GCR_HUB_REPO_NAME="docker_registry"
def DOCKER_IMAGE_NAME = 'employeereferral'
def IMAGE_TAG = "employeereferral_${BUILD_ID}"
def IMAGE_TAG_INPUT = "employeereferral_${BUILD_ID}"
env.JOBNAME = "${JOB_NAME.split('/')[1]}"
def K8S_DEPLOYMENT_NAME = 'java'
def APP_NAME='todo'
def NAMESPACE="ethan"
def qualityGateName='employeereferral_QG'
def sonarProjectname='employeereferral'
env.nameSpace="${params.NAMESPACE_INPUT}"
def sonarHostUrl="http://sonar.${NAMESPACE}.svc.cluster.local:9001/sonar"
def buildTool = "maven"
def kubectl_image = GCR_HUB_ACCOUNT+"/"+GCR_HUB_ACCOUNT_NAME+"/"+GCR_HUB_REPO_NAME+"/docker-kubectl:19.03-alpine"
def GIT_BRANCH=scm.branches[0].name.split("/")[1]
def deploy_env = 'dev'
def BUILDUSER='builduser'
//Set to true to enable influx. Set to false to disable
env.INFLUXDB=true
env.TRIVY_DB_UPDATE=false
println(GIT_BRANCH)

//Import Shared Library from SCM
library identifier: "jenkins_shared_library@${GIT_BRANCH}", retriever: modernSCM(
  [$class: 'GitSCMSource',
   remote: 'http://gitlab:8084/gitlab/root/jenkins_shared_library.git',
   credentialsId: 'gitlab'])

podTemplate(label: pvclabel, serviceAccount: serviceaccount, containers: [
  containerTemplate(name: 'kubectl', image: kubectl_image, ttyEnabled: true, command: 'cat')], imagePullSecrets: ['gcrcred']) {

  node(pvclabel) {
    stage('Pre-requisite validation') 
    {         
      container('kubectl') 
      { 
        //namespaceValidation(nameSpace)
        pvccreation(pvc_name,cartridge_name)
        gitCheckout(GIT_CREDENTIAL_ID)
        list = ['trivy','maven', 'curl', 'jmeter', 'kubectl', 'zap', 'nodejs', 'kaniko']
       	generatePodTemplate(list,pvc_name,buildTool,GCR_HUB_ACCOUNT,GCR_HUB_ACCOUNT_NAME,GCR_HUB_REPO_NAME,cartridge_name) 
        influxJenkinsTargetCreation()
      }    
    }
  }
}

podTemplate(label: label, serviceAccount: serviceaccount, yaml: finalTemplate) {
    node(label) 
    { 
      timestamps 
      {
        try 
        {
            stage('Git Checkout') 
            { 
                
                gitCheckout(GIT_CREDENTIAL_ID)
            }
            stage('Extract Stage Details') 
        { 
            script{
            def containerStages = readYaml text: finalTemplate
            env.containerList = containerStages.spec.containers.name
            }
            println(env.containerList)
        }

            stage('Build project')
			{
				container("${buildTool}") 
           { 
              withCredentials([usernamePassword(credentialsId: 'nexus-creds', usernameVariable: 'USERNAME', passwordVariable: 'PASSWORD')]) 
              {
              env.NEXUS_USERNAME=USERNAME 
              env.NEXUS_PASSWORD=PASSWORD
             
              def function = load "${WORKSPACE}/JenkinsFunctions_Java.groovy"
          		function.buildMethod()

              }
           }

            }

            /*stage('unit tests')
			{
				container("${buildTool}") 
          {
              def function = load "${WORKSPACE}/JenkinsFunctions_Java.groovy"

          		function.testMethod()
          }

			}*/
         if(env.containerList.contains('curl') == true && env.containerList.contains('maven') == true )
        {
        stage('SonarQube Analysis')
        { 
          
          withCredentials([usernamePassword(credentialsId: 'sonar-creds', passwordVariable: 'PASSWORD', usernameVariable: 'USERNAME')]){
                container('curl') 
              {

                //Create Quality gate
                qualityGate(qualityGateName,sonarProjectname,sonarHostUrl)
              }
                container('maven') 
                {
      
                  withSonarQubeEnv('SonarQube') {
                    sonarScan(sonarProjectname,sonarHostUrl) 

                    }
                    timeout(time: 1, unit: 'HOURS') 
                    {
                       sonarStatus()
                    }
                }
              }	
          }
        }
    if(env.containerList.contains('kaniko') == true)
        {        
          stage('Create Image')
          { 	
            container(name: 'kaniko') 
            {
              imageBuild(GCR_HUB_ACCOUNT_IMAGEBUILD,GCR_HUB_ACCOUNT_NAME,GCR_HUB_REPO_NAME,DOCKER_IMAGE_NAME,IMAGE_TAG)
            }  
          }
        }
        if(env.containerList.contains('trivy') == true)
        {         
          stage('Trivy Scan')
          {
            container('trivy')
            {
            try{
		        sh '''
            trivy --cache-dir /tmp/trivy/ image --security-checks vuln --skip-update --format json --ignorefile trivyignore --severity HIGH,CRITICAL -o image_scan_results.json --ignore-unfixed --input image.tar && trivy --cache-dir /tmp/trivy/ image --security-checks vuln --skip-update --format table --ignorefile trivyignore --severity HIGH,CRITICAL --exit-code 0 --ignore-unfixed --input image.tar
            echo ".....Trivy scan completed and No Vulnerabilities found......" >> log.txt
            '''
	          }
            catch (Exception e){
              sh('echo ".....Trivy scan completed and  Vulnerabilities found. Aborting the build...." >> log.txt')
              sh ('exit 1')
	          }
		finally{
			 if (INFLUXDB == "true")
    	  	  {   

	    		image = sh ( script: 'grep -irw "SEVERITY" image_scan_results.json | wc -l', returnStdout: true).trim()
				println(image)
				
            	def image_vuln = [:]
            	image_vuln['image_vuln'] = image.toInteger()        
            	influxDbPublisher(selectedTarget: 'Influx', customData: image_vuln, measurementName: JOBNAME,customProjectName: JOBNAME)
              }  
		}
            }
          }
        }

        if(env.containerList.contains('kaniko') == true)
        {      
          stage('Publish Image')
          { 
            container(name: 'kaniko') 
            {
              imagePush(GCR_HUB_ACCOUNT_IMAGEBUILD,GCR_HUB_ACCOUNT_NAME,GCR_HUB_REPO_NAME,DOCKER_IMAGE_NAME,IMAGE_TAG)
            }   
          }
        }
      if(env.containerList.contains('kubectl') == true)
      {     
        stage('Deploy Build to Environment') 
         {
          container('kubectl'){
            wrap([$class: 'BuildUser']){
              def deploy_namespace = BUILD_USER.split(" ")[0]
              println(deploy_namespace)


              sh """
                sed -i 's/builduser/${deploy_namespace}/g' namespace.yaml
                sed -i 's/builduser/${deploy_namespace}/g' tomcat.yaml
                sed -i 's/builduser/${deploy_namespace}/g' tomcat-svc.yaml
                sed -i 's/builduser/${deploy_namespace}/g' mysql.yaml
                sed -i 's/builduser/${deploy_namespace}/g' mysql-pvc.yaml
                sed -i 's/tomcat-deployenv/employeereferral${deploy_env}/g' tomcat.yaml
				        sed -i 's/tomcat-deployenv/employeereferral${deploy_env}/g' tomcat-svc.yaml
                sed -i "s/deployenvnum/${IMAGE_TAG}/g" tomcat.yaml
                sed -i 's/buildenv/emprefdb/g' mysql-pvc.yaml
                sed -i 's/buildenv/emprefdb/g' mysql.yaml
                sed -i 's/builddb/emprefdb/g' mysql.yaml
              """
              
              sh 'kubectl apply -f namespace.yaml'
              try{
                withCredentials([[$class: 'UsernamePasswordMultiBinding',
                credentialsId: 'gitlab',
                usernameVariable: 'DOCKER_HUB_USER',
                passwordVariable: 'DOCKER_HUB_PASSWORD']]) {
                sh("kubectl create secret docker-registry nodecred --docker-server=${GCR_HUB_ACCOUNT} --docker-username=${DOCKER_HUB_USER} --docker-password=${DOCKER_HUB_PASSWORD} -n ${deploy_namespace}")
                }
              }
              catch (Exception e){
                echo "nodecred already exist"
              }
                  try{
                    sh("kubectl get deployment/mysqldb -n ${deploy_namespace}")
                    if(true)
                    {
                      echo "mysql exits"
                    }
                  }
                  catch(e)
                  {
                    sh '''
                    kubectl apply -f mysql-pvc.yaml
                    kubectl apply -f mysql.yaml
                    '''
				            POD=sh (returnStdout: true, script: """kubectl get pod -l app=emprefdb -n ${deploy_namespace} -o jsonpath="{.items[0].metadata.name}" """)
					          echo "${POD}"
                    sleep 100
					          sh ("kubectl exec -i ${POD} -n ${deploy_namespace} -- mysql -u root -ppassword < empreferal.sql")
                  }
                try{
	                sh("kubectl get deployment/employeereferral${deploy_env} -n ${deploy_namespace}")
				          if(true)
	                {
		                sh """
                      kubectl delete deployment employeereferral${deploy_env} -n ${deploy_namespace}
			                kubectl apply -f tomcat.yaml
		                """
                	}
                }
                catch(e)
				        {
                  sh"""
                  kubectl apply -f tomcat.yaml
				          kubectl apply -f tomcat-svc.yaml
                  sleep 250
				          kubectl get svc employeereferral${deploy_env} -n ${deploy_namespace}
				          """
				        }
				LB = sh (returnStdout: true,script: """ kubectl get svc employeereferral${deploy_env} -n ${deploy_namespace} -o jsonpath="{ .status.loadBalancer.ingress[*]['ip', 'hostname']}" """)
				echo "LB: ${LB}"
				def loadbalancer = "http://"+LB
				echo "application_url: ${loadbalancer}:/1003_CS_EmployeeReferral-0.0.1-SNAPSHOT"
              }
            } 
          } 
          stage('function testing')
	      	{
			      echo "functional testing"	
	      	}
        }
      }
      catch (Exception err) 
        {
          currentBuild.result = 'FAILURE'
          echo 'Exception occurred: ' + err.toString()
          echo "RESULT: ${currentBuild.result}"
          echo "Finished: ${currentBuild.result}"
        } 
      }
  }
}    

podTemplate(label: cleanuplabel, serviceAccount: serviceaccount, containers: [
  containerTemplate(name: 'kubectl', image: kubectl_image, ttyEnabled: true, command: 'cat')], imagePullSecrets: ['gcrcred']) {

  node(cleanuplabel) {
    stage('Post-build-CleanUp') 
    {         
      container('kubectl') 
      { 
        cleanup(label)
      }    
    }
  }
}
