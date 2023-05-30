#!/usr/bin/env bash

ALLOWED_SIGNERS_FILE="/allowed_signers"
readonly ALLOWED_SIGNERS_FILE

create_allowed_signers_file() {
  local username=$1

  local user_email
  user_email=$(gh api \
    -H "${GH_HEADER_ACCEPT}" \
    -H "${GH_HEADER_API}" \
    /users/$username | jq -r ".email")
  if [[ $user_email == "" ]]; then
    print_red "$username doesn't have an email"
    return 1
  fi

  local keys
  keys=$(gh api \
    -H "$GH_HEADER_ACCEPT" \
    -H "$GH_HEADER_API" \
    /users/$username/ssh_signing_keys | jq -r ".[].key")
  if [[ $keys == "" ]]; then
    print_yellow "no SSH keys found for $username ($user_email)"
    return 1
  fi

  if [[ -f "${ALLOWED_SIGNERS_FILE}" ]]; then
    rm "${ALLOWED_SIGNERS_FILE}"
  fi

  while IFS= read -r key
  do
    echo "${user_email} ${key}" >> $ALLOWED_SIGNERS_FILE
  done <<< "$keys"
}

verify_tag() {
  local username=$1

  pushd $REPO_NAME > /dev/null
  git tag -v $GITHUB_REF_NAME > /dev/null
  if [[ $? == 0 ]]; then
    SIGNER=$username
    return 0
  fi
  popd > /dev/null
  return 1
}