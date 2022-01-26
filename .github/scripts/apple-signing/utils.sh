## terminal goodies
PURPLE='\033[0;35m'
GREEN='\033[0;32m'
RED='\033[0;31m'
BOLD=$(tput bold)
RESET='\033[0m'

function success() {
  echo -e "\n${GREEN}${BOLD}$@${RESET}"
}

function title() {
  success "Task: $@"
}

function commentary() {
  echo -e "\n${PURPLE}# $@${RESET}"
}

function error() {
  echo -e "${RED}${BOLD}error: $@${RESET}"
}

function exit_with_error() {
  error $@
  exit 1
}

function exit_with_message() {
  success $@
  exit 0
}

function realpath {
  echo "$(cd $(dirname $1); pwd)/$(basename $1)";
}


# this function adds all of the existing keychains plus the new one which is the same as going to Keychain Access
# and selecting "Add Keychain" to make the keychain visible under "Custom Keychains". This is done with
# "security list-keychains -s" for some reason. The downside is that this sets the search path, not appends
# to it, so you will loose existing keychains in the search path... which is truly terrible.
function add_keychain() {
  keychains=$(security list-keychains -d user)
  keychainNames=();
  for keychain in $keychains
  do
    basename=$(basename "$keychain")
    keychainName=${basename::${#basename}-4}
    keychainNames+=("$keychainName")
  done

  echo "existing user keychains: ${keychainNames[@]}"

  security -v list-keychains -s "${keychainNames[@]}" "$1"
}
