#!/bin/bash

if [ $# -eq 1 ]; then
    if [ $1 == '--clean' ]; then
        rm valid_header-{bugnum,bug_reason}.patch
        rm bad_header-{no_mail,no_name,no_bug}.patch
        exit 0
    fi
    exit 1
fi

echo '# User HG Pusher <hg.pusher@mozilla.org>' > valid_header-bugnum.patch
echo 'bug 12345: test commit' >> valid_header-bugnum.patch
echo '' >> valid_header-bugnum.patch

echo '# User HG Pusher <hg.pusher@mozilla.org>' > valid_header-bug_reason.patch
echo 'bug REASON: test commit' >> valid_header-bug_reason.patch
echo '' >> valid_header-bug_reason.patch

echo '# User HG Pusher' > bad_header-no_mail.patch
echo 'bug 12345: test commit' >> bad_header-no_mail.patch
echo '' >> bad_header-no_mail.patch

echo '# User <hg.pusher@mozilla.org>' > bad_header-no_name.patch
echo 'bug 12345: test commit' >> bad_header-no_name.patch
echo '' >> bad_header-no_name.patch

echo '# User HG Pusher <hg.pusher@mozilla.org>' > bad_header-no_bug.patch
echo 'test commit' >> bad_header-no_bug.patch
echo '' >> bad_header-no_bug.patch

