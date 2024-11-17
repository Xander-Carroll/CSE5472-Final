#!/bin/bash
bash create_ip_lists.sh 
cd scripts
for script in *.sh
do
    ret=$(bash $script)
    echo $ret
    if [ $ret!=0 ];then
        RED='\033[0;31m'
        message="${RED}failed"
    else
        message="success"
    fi
    echo -e "$script.......$message"
done
