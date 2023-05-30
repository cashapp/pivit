#!/usr/bin/env bash

git_checkout() {
  gh repo clone $GITHUB_REPOSITORY
  if [[ $? != 0 ]]; then
    print_red "failed to clone $GITHUB_REPOSITORY"
    return 1
  fi

  pushd $REPO_NAME > /dev/null
  git config gpg.format ssh
  git config gpg.ssh.allowedSignersFile $ALLOWED_SIGNERS_FILE
  popd > /dev/null
}