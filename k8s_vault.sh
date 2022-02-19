#!/bin/bash

###################################
#           Variables
###################################
ROOT_DIR="secret" #name of root directory in kv-v2 vault
PATH_TO_SECRET="wp/db" #path to secret in kv-v2 vault
SECRET="config" #name of secret in kv-v2 vault
CRED_JSON_STRING='' #credentials in json format. It will be generate via function gen_db_cred
VAULT_KEYS=`cat cluster-keys.json` #credentials in json format. It will be generate via function init_vault


GREEN='\033[0;32m'  
NC='\033[0m'
YELLOW='\033[0;33m'

NAMESPACE="vault"  #namespace where vault will be installed
NAMESPACE_app="database" #namespace with application that will be use credentials
SERVICE_ACCOUNT="vault-mysql-sa" #service account name where are application that need access to password
ACCESS_ROLE="vault-mysql-ar" #access role for application
POLICY_NAME="vault-mysql-policy" #policy name for application
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

#unsealling vaults
function unseal_vaults  {
    echo -e "\n${YELLOW}* Unseal all vaults${NC}"
    echo -e "- Get vault unseal key"
    VAULT_UNSEAL_KEY=$(echo $VAULT_KEYS | jq -r ".unseal_keys_b64[]")

    for i in {0..2}; do
        echo -e "\n===============vault-$i==============="
        kubectl -n $NAMESPACE exec --stdin=true  --tty=true vault-$i -- vault operator key-status > /dev/null 2>&1
        if [ "$?" -ne "0" ]; then
            kubectl -n $NAMESPACE exec --stdin=true --tty=true vault-$i -- vault operator unseal $VAULT_UNSEAL_KEY
        else
            echo -e "\n* vault-$i has already unsealed${NC}"
        fi
    done
}

#sealling vaults
function seal_vaults  {
    echo -e "\n${YELLOW}* Seal all vaults${NC}"
    for i in {0..2}; do
        echo -e "\n===============vault-$i==============="
        kubectl -n $NAMESPACE exec --stdin=true  --tty=true vault-$i -- vault operator key-status > /dev/null 2>&1
        if [ "$?" -eq "0" ]; then
            vault_login $i
            sleep 6
            kubectl -n $NAMESPACE exec --stdin=true --tty=true vault-$i -- vault operator seal
        else
            echo -e "- vault-$i has already sealed"
        fi
    done
}

#login into vault
function vault_login {

    index=$1
    echo -e "\n${YELLOW}* Get root token${NC}"
    VAULT_TOKEN=`echo $VAULT_KEYS | jq -r ".root_token"`
    
    echo -e "- Vault login"
    kubectl -n $NAMESPACE exec --stdin=true --tty=true vault-$index -- vault login $VAULT_TOKEN 1>/dev/null



}

#add new data in vault DB
function add_new_key {

    echo -e "\n${YELLOW}* Add new secret by PATH: $ROOT_DIR/$PATH_TO_SECRET/$SECRET${NC}"
    kubectl -n $NAMESPACE exec --stdin=true  --tty=true vault-0 --  vault secrets list -format table  | awk '{print $1}' | grep "^$ROOT_DIR/" 1>/dev/null
    if [ "$?" -ne "0" ]; then
      echo -e "- create <root directory> for secrets\n"
      kubectl -n $NAMESPACE exec --stdin=true  --tty=true vault-0 -- \
      vault secrets enable -path=$ROOT_DIR kv-v2 
    else
      echo -e "- PATH: $ROOT_DIR/ exist in the vault"
    fi

    echo $CRED_JSON_STRING | kubectl exec --stdin=true  --tty=true vault-0 vault-0 -- \
                           sh -c 'vault kv put  /secret/wp/db/config -'

    # echo -e "- Show created key"
    # kubectl exec --stdin=true  --tty=true vault-0 -- \
    # vault kv get $ROOT_DIR/$PATH_TO_SECRET/$SECRET
    echo -e "${GREEN}- The secret has added succesfully!${NC}\n"

}

function get_key_value {
    echo -e "- Show created key"
    kubectl -n $NAMESPACE exec --stdin=true  --tty=true vault-0 -- \
    vault kv get $ROOT_DIR/$PATH_TO_SECRET/$SECRET
}

#allow access from k8s to vault
function allow_access_from_kubernetes  {

    echo -e "\n${YELLOW}* Enable kubectl proxy${NC}"
    kubectl proxy &
    sleep 3
    echo -e "- Get URL for ISSUER"
    ISSUER=`curl --silent http://127.0.0.1:8001/.well-known/openid-configuration | jq -r .issuer`
    echo "issuer=$ISSUER"
    kill %%

    kubectl -n $NAMESPACE exec --stdin=true  --tty=true vault-0 -- vault  auth list | awk '{print $1}' | grep "^kubernetes/" 1>/dev/null
    if [ "$?" -ne "0" ]; then
        echo -e "- Enable vault authentification to kubernetes"
        kubectl -n $NAMESPACE exec --stdin=true  --tty=true vault-0 -- vault auth enable kubernetes
    fi

    echo -e "- Vault add credentials with kubernetes cluster"  
    kubectl -n $NAMESPACE exec --stdin=true  --tty=true vault-0 -- sh -c '
    vault write auth/kubernetes/config \
    kubernetes_host="https://$KUBERNETES_PORT_443_TCP_ADDR:443" \
    token_reviewer_jwt="$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
    kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt disable_iss_validation=true \
    issuer="$ISSUER"'
}

#new policy with requirements
function add_vault_policy  {
    
    echo -e "\n${YELLOW}* Add service account key${NC}"
    kubectl -n $NAMESPACE create sa $SERVICE_ACCOUNT --namespace=$NAMESPACE_app


    echo -e "- Create new policy for created secret"  
    kubectl -n $NAMESPACE exec --stdin=true  --tty=true vault-0 -- \
    vault policy write $POLICY_NAME - <<EOF
path "$ROOT_DIR/*" {
  capabilities = ["read"]
}
EOF
    
    echo -e "\n* Apply policy for kubernetes"  
    kubectl -n $NAMESPACE exec --stdin=true  --tty=true vault-0 -- vault write auth/kubernetes/role/$ACCESS_ROLE \
    bound_service_account_names=$SERVICE_ACCOUNT \
    bound_service_account_namespaces=$NAMESPACE_app \
    policies=$POLICY_NAME \
    ttl=24h
    
}

#generation patch file
function gen_mysql_config_file {

    echo -e "\n${YELLOW}* mysql-config.yml file generation${NC}"
    mysql_config_text=$(cat <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: mysql-configuration
  namespace: $NAMESPACE_app
  annotations:
    vault.hashicorp.com/agent-inject: 'true'
    vault.hashicorp.com/role: '$ACCESS_ROLE'
    vault.hashicorp.com/agent-inject-secret-init.sh: '$ROOT_DIR/$PATH_TO_SECRET/$SECRET'
    vault.hashicorp.com/agent-inject-template-init.sh: | 
        {{- with secret "$ROOT_DIR/$PATH_TO_SECRET/$SECRET" -}}
        HOST="mysql-set-0.mysql.$NAMESPACE_app.svc.cluster.local"
EOF
)
    printf "$mysql_config_text\n" > mysql-config.yml
    cat <<"TAGTEXTFILE" >> mysql-config.yml
        MYSQL_ROOT_PASSWORD={{ .Data.data.MYSQL_ROOT_PASSWORD }}
        MYSQL_DATABASE={{ .Data.data.MYSQL_DATABASE }}
        MYSQL_USER={{ .Data.data.MYSQL_USER}}
        MYSQL_PASSWORD={{ .Data.data.MYSQL_PASSWORD }}

        mysql -uroot -p$MYSQL_ROOT_PASSWORD_old -h$HOST  -e "show databases;" 1>/dev/null 2>&1

        if [ "$?" -eq "0" ];
        then
            echo "MYSQL_ROOT_PASSWORD has changed. "
            mysql -uroot -p$MYSQL_ROOT_PASSWORD_old -h$HOST << EOF 
        ALTER USER 'root'@'%' IDENTIFIED BY '$MYSQL_ROOT_PASSWORD';
        ALTER USER 'root'@'localhost' IDENTIFIED BY '$MYSQL_ROOT_PASSWORD';
        FLUSH PRIVILEGES;
        EOF
        fi

        mysql -uroot -p$MYSQL_ROOT_PASSWORD -h$HOST << EOF
        CREATE DATABASE IF NOT EXISTS $MYSQL_DATABASE;
        CREATE USER IF NOT EXISTS '$MYSQL_USER' @'%';
        ALTER USER '$MYSQL_USER' @'%' IDENTIFIED BY '$MYSQL_PASSWORD';
        GRANT ALL PRIVILEGES ON $MYSQL_DATABASE . * TO '$MYSQL_USER' @'%';
        FLUSH PRIVILEGES;
        \! echo 'Information in MySQL DB has changed. Congrats!';
        EOF
        {{- end -}}
TAGTEXTFILE

    mysql_config_text=$(cat <<EOF
spec:
  serviceAccountName: $SERVICE_ACCOUNT
  containers:
  - name: mysql-container
    image: imega/mysql-client
    args:
      ['sh', '-c', 'sh /vault/secrets/init.sh && tail -f /dev/null']
    imagePullPolicy: IfNotPresent
    env:
    - name: MYSQL_ROOT_PASSWORD_old
      valueFrom:
       secretKeyRef:
        name: mysql-password
        key: MYSQL_ROOT_PASSWORD
EOF
)

    printf "$mysql_config_text\n" >> mysql-config.yml

    echo -e "- File mysql-config.yml with injection has generated\n. For update password this COMMAND: \n\n \
bash init-db.sh\n"

}

function gen_db_cred {

    prefix=`tr -dc A-Za-z0-9 </dev/urandom | head -c 6 ; echo ''`
    MYSQL_DATABASE=wp_db_name_$prefix
    MYSQL_PASSWORD=`tr -dc A-Za-z0-9 </dev/urandom | head -c 16 ; echo ''`
    MYSQL_ROOT_PASSWORD=`tr -dc A-Za-z0-9 </dev/urandom | head -c 16 ; echo ''`
    MYSQL_USER=wp_db_user_$prefix

    CRED_JSON_STRING=$( jq -n \
                    --arg mysql_db "$MYSQL_DATABASE" \
                    --arg mysql_pass "$MYSQL_PASSWORD" \
                    --arg mysql_root "$MYSQL_ROOT_PASSWORD" \
                    --arg mysql_user "$MYSQL_USER" \
                    '{MYSQL_DATABASE: $mysql_db, MYSQL_PASSWORD: $mysql_pass, MYSQL_ROOT_PASSWORD: $mysql_root, MYSQL_USER: $mysql_user}' )

}



usage=$(cat <<EOF
Usage: ./k8s_vault <arg1> <arg2> <arg3> <arg4> ... <arg10>

Arguments:
add_repos                       add helm repo hashicorp
install_consul                  install consul for vault via helm
install_vault                   install vault via helm
init_vault                      initialization vault
unseal_vaults                   unseal all vaults
seal_vaults                     seal vaults
vault_login                     get password and login into vault
add_new_key [option]            add secret new key in vault 
allow_access_from_kubernetes    allow access from kubernetes
add_vault_policy                add vault policy
port-forward                    enable port forwarding for vault
gen_mysql_config_file           generate file with injection for mysql
steps-1                         add repositories, install consul and vault, initialize vault and get vault keys 
steps-2                         unseal all vaults, login into vault, add secret new key in vault, allow access from k8s, add vault policy, generate file with injection for mysql 
EOF
)

add_new_key_usage=$(cat <<EOF
Create new key and write it into vault database

Usage: ./k8s_vault add_new_key [option]

Options:
    add_new_key --gen_db_cred              add DATABASE credentials in vault
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
        unseal_vaults)                    unseal_vaults ;;
        seal_vaults)                      seal_vaults ;;
        vault_login)                      vault_login "0" && echo -e "- Succesfully have logined\n";;
        allow_access_from_kubernetes)     allow_access_from_kubernetes;;
        add_vault_policy)                 add_vault_policy;;
        port-forward)                     kubectl port-forward vault-0 $PORT_FORWARD:8200;;
        gen_mysql_config_file)            gen_mysql_config_file;;
        get_key_value)                    get_key_value;;

        steps-1)                          add_namespace && \
                                          add_repos && \
                                          install_consul && \
                                          install_vault && \
                                          init_vault && \

        steps-2)                          unseal_vaults && \
                                          vault_login  "0" && echo -e "- Succesfully have logined\n" && \
                                          gen_db_cred && add_new_key && \
                                          allow_access_from_kubernetes && \
                                          add_vault_policy && \
                                          gen_mysql_config_file;;

        *)                                [[  ${args[0]}  != "add_new_key" ]] && printf "$usage\n" && exit 1;
        
    esac


    if [ ${args[0]} = "--help" ] ;
    then
        printf "$usage\n"
    fi;
    if [ "${args[${i}]}" = "add_new_key" ]; then
        case ${args[${i}+1]} in
            --help)         printf "$add_new_key_usage\n";;
            --gen_db_cred)    gen_db_cred && add_new_key;;
            *)              printf "$add_new_key_usage\n";;
        esac
    fi
    
done
