#!/bin/bash

###################################
#           Variables
###################################

GREEN='\033[0;32m'  
NC='\033[0m'
YELLOW='\033[0;33m'

NAMESPACE="vault"  #namespace where vault will be installed
PORT_FORWARD="8200" #port in host for forwarding by COMMAND: kubectl port-forward vault-0 $PORT_FORWARD:8200

#function for create new namespace
function add_namespace {
    
    echo -e "\n${YELLOW}* Add new namespace and choose it by default${NC}"
    kubectl create ns $NAMESPACE
    kubectl config set-context --current --namespace=$NAMESPACE

}

#add registry hashicorp
function add_repos {
    echo -e "\n${YELLOW}* Add repo hashicorp${NC}"
    helm repo add hashicorp https://helm.releases.hashicorp.com
    
    echo -e "- Update repo list"
    helm repo update
}

#install consul via helm
function install_consul {
    echo -e "\n${YELLOW}* Install consul with values from helm-consul-values.yml${NC}"
    helm install -n $NAMESPACE consul hashicorp/consul --values helm-consul-values.yml
    
    echo -e "- Verify installation"
    kubectl -n $NAMESPACE wait --timeout=180s --for=condition=Ready $(kubectl -n $NAMESPACE get pod --selector=app=consul -o name)
}

#install vault via helm
function install_vault {
    echo -e "\n${YELLOW}* Install vault with values from helm-vault-values.yml${NC}"
    helm -n $NAMESPACE install vault hashicorp/vault --values helm-vault-values.yml
    
    echo -e "- Verify installation"
    kubectl -n $NAMESPACE wait --timeout=180s --for=condition=Ready $(kubectl get pod --selector=app.kubernetes.io/name=vault-agent-injector -o name)
}

#initialization vault
function init_vault {
    
    kubectl -n $NAMESPACE exec --stdin=true  --tty=true vault-0 -- vault operator  init -status 1> /dev/null

    if [ "$?" -ne "0" ]; then
      echo -e "\n${YELLOW}* Init vault${NC}"
      kubectl -n $NAMESPACE exec vault-0 -- vault operator init -key-shares=1 -key-threshold=1 -format=json > cluster-keys.json
      echo -e "- Vault keys have writen in cluster-keys.json."
      echo -e "${YELLOW}- Save this keys into SECRET STORAGE and delete file.{NC}"
    else 
      echo -e "\nVault was already initialized"
    fi
}

usage=$(cat <<EOF
Usage: ./k8s_vault <arg1> <arg2> <arg3> <arg4> ... <argN>

Arguments:
add_repos                       add helm repo hashicorp
install_consul                  install consul for vault via helm
install_vault                   install vault via helm
init_vault                      initialization vault
port-forward                    enable port forwarding for vault
all_steps                       add repositories, install consul and vault, initialize vault and get vault keys 
EOF
)


# store arguments in a special array 
args=("$@")
# get number of elements 
ELEMENTS=${#args[@]}
#if number of argumets = 0 then print USAGE
[ $ELEMENTS -eq "0" ] && printf "$usage\n" 

for (( i=0;i<$ELEMENTS;i++));
do                           

    case ${args[${i}]} in
        add_repos)                        add_repos;;
        install_consul)                   install_consul;;
        install_vault)                    install_vault;;    
        init_vault)                       init_vault;;
        port-forward)                     kubectl -n $NAMESPACE port-forward vault-0 $PORT_FORWARD:8200;;


        all_steps)                        add_namespace && \
                                          add_repos && \
                                          install_consul && \
                                          install_vault && \
                                          init_vault;;

        --help)                           printf "$usage\n" && exit 1;;

        *)                                printf "$usage\n" && exit 1;
        
    esac

    
done
