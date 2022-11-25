pipeline {
    
    agent {
       label "tempesta-test"
    }

    environment {
        RUN_BUILD = "true"
    }

    stages {   

        stage('Set buildName'){
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                    script {
                        currentBuild.displayName = "${GIT_COMMIT[0..7]} $PARAMS"
                    }
                }
            }
        }

        stage('Pre build'){
            steps {
                script {
                    try {
                        dir("/root/tempesta"){
                            OLD_HASH=sh(script: "git rev-parse --short HEAD", returnStdout: true).trim()
                        }
                        echo "OLD HASH: $OLD_HASH"
                        dir("tempesta"){
                            git url: 'https://github.com/tempesta-tech/tempesta.git', branch: 'master'
                            NEW_HASH=sh(script: "git rev-parse --short HEAD", returnStdout: true).trim()
                        }
                        echo "NEW HASH: $NEW_HASH"
                        if (OLD_HASH == NEW_HASH){
                            echo "HASH EQUALS - no build required"
                            env.RUN_BUILD = "false"
                            echo "Check tempesta start/stop"
                            def TEMPESTA_STATUS = sh(returnStatus: true, script: "/root/tempesta/scripts/tempesta.sh --start")
                            sh "/root/tempesta/scripts/tempesta.sh --stop"
                            echo "$TEMPESTA_STATUS"
                            if (TEMPESTA_STATUS != 0){
                                echo "TEMPESTA CANT RUN - new build required"
                                sh 'rm -rf /root/tempesta; cp -r tempesta/ /root/tempesta'
                                env.RUN_BUILD = "true"
                            } else {
                                echo "TEMPESTA RUN SUCCESSFULLY - no new build required"
                                env.RUN_BUILD = "false"
                            }
                        } else {
                            sh 'rm -rf /root/tempesta; cp -r tempesta/ /root/tempesta'
                            env.RUN_BUILD = "true"
                        }
                    } catch (Exception e) {
                        echo "ERROR $e"
                        sh 'rm -rf /root/tempesta; cp -r tempesta/ /root/tempesta'
                        env.RUN_BUILD = "true"
                    } finally {
                        echo "RUN_BUILD: ${RUN_BUILD}"
                    }
                }
            }
        }

        stage('Build') {
            when {
                expression { env.RUN_BUILD == 'true' }
            }
            steps {
                dir("/root/tempesta"){
                    git url: 'https://github.com/tempesta-tech/tempesta.git', branch: 'master'
                    }
                dir("/root/tempesta"){
                    sh 'make'
                }
            }
        }

        stage('Run tests') {
            options {
                timeout(time: 180, unit: 'MINUTES')   // timeout on this stage
            }
            steps {
                sh "./run_tests.py $PARAMS"
            }
        }

        stage('Clean WS'){
            steps {
                    cleanWs()
                }
            }

    }
    
    post {
            always {
                sh 'sleep 1; reboot &'
            }
        }
}
