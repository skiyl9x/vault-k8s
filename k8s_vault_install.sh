#!/bin/bash

###################################
#           Variables
###################################
ROOT_DIR="secret"
PATH_TO_SECRET="wp/db/config"
USERNAME="user"
PASSWORD="pass"
POLICY_NAME="wp"
NAMESPACE="vault"
SERVICE_ACCOUNT="vault"


function add_repos {
    echo "* add repo hashicorp"
    helm repo add hashicorp https://helm.releases.hashicorp.com
    
    echo -e "\n* update repo list"
    helm repo update
}

function install_consul {
    echo -e "\n* install consul with values from helm-consul-values.yml"
    helm install consul hashicorp/consul --values helm-consul-values.yml
    
    echo -e "\n* verify installation"
    kubectl wait --timeout=180s --for=condition=Ready $(kubectl get pod --selector=app=consul -o name)
}

function install_vault {
    echo -e "\n* install vault with values from helm-vault-values.yml"
    helm install vault hashicorp/vault --values helm-vault-values.yml
    
    echo -e "\n* verify installation"
    kubectl wait --timeout=180s --for=condition=Ready $(kubectl get pod --selector=app.kubernetes.io/name=vault-agent-injector -o name)
}

function init_vault {
    
    kubectl exec --stdin=true  --tty=true vault-0 -- vault operator  init -status 1> /dev/null
  
    if [ "$?" -ne "0" ]; then
      echo -e "\n* init vault"
      kubectl exec vault-0 -- vault operator init -key-shares=1 -key-threshold=1 -format=json > cluster-keys.json
      echo -e "\n* vault keys have saved in cluster-keys.json."
    else 
      echo "Vault was already initialized"
    fi
}

function unseal_vaults  {
    kubectl exec --stdin=true  --tty=true vault-0 -- vault operator key-status
    echo -e "\n* get vault unseal key"
    VAULT_UNSEAL_KEY=$(cat cluster-keys.json | jq -r ".unseal_keys_b64[]")
    
    echo -e "\n* unseal all vaults"
    for i in {0..2}; do
        kubectl exec --stdin=true --tty=true vault-$i -- vault operator unseal $VAULT_UNSEAL_KEY
    done
}



function vault_login {
    echo -e "\n* get root token"
    ROOT_TOKEN=`cat cluster-keys.json | jq -r ".root_token"`
    
    echo -e "\n* vault login"
    echo $ROOT_TOKEN
    kubectl exec --stdin=true --tty=true vault-0 -- vault login
}

function add_new_key {
    
    kubectl exec --stdin=true  --tty=true vault-0 --  vault secrets list -format table  | awk '{print $1}' | grep "^$ROOT_DIR/" 1>/dev/null
    if [ "$?" -ne "0" ]; then
      echo -e "\n* create <root directory> for secrets"
      kubectl exec --stdin=true  --tty=true vault-0 -- \
      vault secrets enable -path=$ROOT_DIR kv-v2 
    else
      echo "PATH: $ROOT_DIR/ exist in the vault"
    fi

    echo -e "\n* add new secrret with <path to secret> and keys <username>, <password>"
    kubectl exec --stdin=true  --tty=true vault-0 -- \
    vault kv put $ROOT_DIR/$PATH_TO_SECRET username=$USERNAME password=$PASSWORD

    echo -e "\n* show created key"
    kubectl exec --stdin=true  --tty=true vault-0 -- \
    vault kv get $ROOT_DIR/$PATH_TO_SECRET
}

function allow_access_from_kubernetes  {

    echo -e "\n* enable kubectl proxy"  
    kubectl proxy &
    echo -e "\n* get URL for ISSUER"  
    ISSUER=`curl --silent http://127.0.0.1:8001/.well-known/openid-configuration | jq -r .issuer`
    echo "issuer=$ISSUER"
    kill %%

    echo -e "\n* enable for vault authentification to kubernetes"  
    kubectl exec --stdin=true  --tty=true vault-0 -- vault auth enable kubernetes

    echo -e "\n* vault add credentials with kubernetes cluster"  
    kubectl exec --stdin=true  --tty=true vault-0 -- sh -c '
    vault write auth/kubernetes/config \
    kubernetes_host="https://$KUBERNETES_PORT_443_TCP_ADDR:443" \
    token_reviewer_jwt="$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
    kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt disable_iss_validation=true \
    issuer="$ISSUER"'
}

function add_vault_policy  {
    
    echo -e "\n* add sa <name>"
    kubectl create sa $SERVICE_ACCOUNT


    echo -e "\n* create new policy for created secret"  
    kubectl exec --stdin=true  --tty=true vault-0 -- \
    vault policy write $POLICY_NAME - <<EOF
path "$ROOT_DIR/$PATH_TO_SECRET" {
  capabilities = ["read"]
}
EOF
    
    echo -e "\n* apply policy for kubernetes"  
    kubectl exec --stdin=true  --tty=true vault-0 -- vault write auth/kubernetes/role/$POLICY_NAME \
    bound_service_account_names=$SERVICE_ACCOUNT \
    bound_service_account_namespaces=$NAMESPACE \
    policies=$POLICY_NAME \
    ttl=24h
    
}

usage=$(cat <<EOF
Usage: ./k8s_vault_install.sh <arg1> <arg2> <arg3> <arg4> ... <arg10>

Arguments:
--add_repos                       add helm repo hashicorp
--install_consul                  install consul for vault via helm
--install_vault                   install vault via helm
--init_vault                      initialization vault
--unseal_vaults                   unseal all vaults
--vault_login                     get password and login into vault
--add_new_key                     add secret new key in vault
--allow_access_from_kubernetes    allow access from kubernetes
--add_vault_policy                add vault policy
--all_steps                       perform all steps
--port-forward                    enable port forwarding for vault
EOF
)

for arg in "$@"
do
    case $arg in
        --vault_login) vault_login;;
        --add_repos) add_repos;;
        --install_consul) install_consul;;
        --install_vault) install_vault;;
        --init_vault) init_vault;;
        --unseal_vaults) unseal_vaults;;
        --vault_login) vault_login;;
        --add_new_key) add_new_key;;
        --allow_access_from_kubernetes) allow_access_from_kubernetes;;
        --add_vault_policy) add_vault_policy;;
	--port-forward) kubectl port-forward vault-0 8200:8200;;
        --all_steps) add_repos && \
                     install_consul && \
                     install_vault && \
                     init_vault && \
                     unseal_vaults && \
                     vault_login && \
                     add_new_key && \
                     allow_access_from_kubernetes && \
                     add_vault_policy;;
        *) printf "$usage\n" ;;
    esac
done
