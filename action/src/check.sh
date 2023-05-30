#!/usr/bin/env bash

source /utils.sh
source /git_checkout.sh
source /user_keys.sh

usernames=$1
SIGNER=""

if [[ $GITHUB_REF_TYPE != "tag" ]]; then
  err "Signature check is only supported for git tags"
fi

REPO_NAME=$(echo $GITHUB_REPOSITORY | cut -d'/' -f2)
readonly REPO_NAME

git_checkout
if [[ $? != 0 ]]; then
  err "FAILED"
fi

for username in `echo $usernames | tr "," "\n"`; do
  print_blue "trying to verify tag $GITHUB_REF_NAME with $username's keys"
  create_allowed_signers_file $username
  if [[ $? != 0 ]]; then
    continue
  fi

  verify_tag $username
  if [[ $? == 0 ]]; then
    print_green "$GITHUB_REF_NAME was signed by $SIGNER"
    echo "signed_by=$SIGNER" >> "$GITHUB_OUTPUT"
    break
  fi
done
