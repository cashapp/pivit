#!/usr/bin/env bash

set -uo pipefail

# Foreground color coding
_RST="\033[0m" # resets color and format
readonly _RST
_RED="\033[0;31m"
readonly _RED
_GREEN="\033[0;32m"
readonly _GREEN
_BLUE="\033[0;34m"
readonly _BLUE
_YELLOW="\033[0;33m"
readonly _YELLO


GH_HEADER_ACCEPT="Accept: application/vnd.github+json"
readonly GH_HEADER_ACCEPT

GH_HEADER_API="X-GitHub-Api-Version: 2022-11-28"
readonly GH_HEADER_API


#######################################################
# Helper functions
#######################################################

err() {
  echo -e "${_RED}$*${_RST}" >&2
  exit 1
}

warn() {
  echo -e "${_YELLOW}$*${_RST}" >&2
}

print_red() {
  echo -e "${_RED}$*${_RST}"
}

print_green() {
  echo -e "${_GREEN}$*${_RST}"
}

print_blue() {
  echo -e "${_BLUE}$*${_RST}"
}

print_yellow() {
  echo -e "${_YELLOW}$*${_RST}"
}