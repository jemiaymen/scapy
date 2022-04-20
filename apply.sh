eval $(minikube -p minikube docker-env)

minikube kubectl -- apply -f pod1-deployment.yaml
minikube kubectl -- apply -f pod2-deployment.yaml
minikube kubectl -- apply -f pod3-deployment.yaml
minikube kubectl -- apply -f pod4-deployment.yaml
minikube kubectl -- apply -f pod5-deployment.yaml
minikube kubectl -- apply -f pod8-deployment.yaml
minikube kubectl -- apply -f pod9-deployment.yaml