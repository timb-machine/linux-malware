#!/bin/sh

# Usage: `bash test.sh` (only supported shell for this script is bash)

status=0

sc="4831ff5766ffc748b86f20776f726c640a50b848656c6c48c1e02050488"\
"9e64883c6044889f84889c2b20c0f054831c04889c7b03c0f05"
sc_bin=$(echo -n $sc | sed 's/\([0-9A-F]\{2\}\)/\\x\1/gI')

time r="$(base64 -w0 `which echo` |\
     bash ddexec.sh echo -n asd qwerty "" zxcvb " fdsa gf")"
if [ "$r" = "$(echo -n asd qwerty "" zxcvb " fdsa gf")" ]
then
    echo "bash + ddexec, test 1: OK"
else
    echo "bash + ddexec, test 1: Error :("
    status=1
fi
time r="$(base64 -w0 `which echo` |\
     bash ddexec.sh echo -n asd qwerty "" zxcvb " fdsa gf" .)"
if [ "$r" = "$(echo -n asd qwerty "" zxcvb " fdsa gf" .)" ]
then
    echo "bash + ddexec, test 2: OK"
else
    echo "bash + ddexec, test 2: Error :("
    status=1
fi
time r=$(echo $sc | bash ddsc.sh -x)
if [ "$r" = "Hello world" ]
then
    echo "bash + ddsc, test 1: OK"
else
    echo "bash + ddsc, test 1: Error :("
    status=1
fi
time r=$(printf "$sc_bin" | bash ddsc.sh)
if [ "$r" = "Hello world" ]
then
    echo "bash + ddsc, test 2: OK"
else
    echo "bash + ddsc, test 2: Error :("
    status=1
fi
echo

time r="$(base64 -w0 `which echo` |\
     zsh ddexec.sh echo -n asd qwerty "" zxcvb " fdsa gf")"
if [ "$r" = "$(echo -n asd qwerty "" zxcvb " fdsa gf")" ]
then
    echo "zsh + ddexec, test 1: OK"
else
    echo "zsh + ddexec, test 1: Error :("
    status=1
fi
time r="$(base64 -w0 `which echo` |\
     zsh ddexec.sh echo -n asd qwerty "" zxcvb " fdsa gf" .)"
if [ "$r" = "$(echo -n asd qwerty "" zxcvb " fdsa gf" .)" ]
then
    echo "zsh + ddexec, test 2: OK"
else
    echo "zsh + ddexec, test 2: Error :("
    status=1
fi
time r=$(echo $sc | zsh ddsc.sh -x)
if [ "$r" = "Hello world" ]
then
    echo "zsh + ddsc, test 1: OK"
else
    echo "zsh + ddsc, test 1: Error :("
    status=1
fi
time r=$(printf "$sc_bin" | zsh ddsc.sh)
if [ "$r" = "Hello world" ]
then
    echo "zsh + ddsc, test 2: OK"
else
    echo "zsh + ddsc, test 2: Error :("
    status=1
fi
echo

time r="$(base64 -w0 `which echo` |\
     ash ddexec.sh echo -n asd qwerty "" zxcvb " fdsa gf")"
if [ "$r" = "$(echo -n asd qwerty "" zxcvb " fdsa gf")" ]
then
    echo "ash + ddexec, test 1: OK"
else
    echo "ash + ddexec, test 1: Error :("
    status=1
fi
time r="$(base64 -w0 `which echo` |\
     ash ddexec.sh echo -n asd qwerty "" zxcvb " fdsa gf" .)"
if [ "$r" = "$(echo -n asd qwerty "" zxcvb " fdsa gf" .)" ]
then
    echo "ash + ddexec, test 2: OK"
else
    echo "ash + ddexec, test 2: Error :("
    status=1
fi
time r=$(echo $sc | ash ddsc.sh -x)
if [ "$r" = "Hello world" ]
then
    echo "ash + ddsc, test 1: OK"
else
    echo "ash + ddsc, test 1: Error :("
    status=1
fi
time r=$(printf "$sc_bin" | ash ddsc.sh)
if [ "$r" = "Hello world" ]
then
    echo "ash + ddsc, test 2: OK"
else
    echo "ash + ddsc, test 2: Error :("
    status=1
fi

exit $status
