#!/usr/bin/env bash
# Update the README.md file
pod2markdown lib/Mail/SpamAssassin/Plugin/ASCII.pm >README.md
# Run the tests
prove -l t/*.t
