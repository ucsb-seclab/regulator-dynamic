#!/bin/bash

echo '[*] Booting Docker';
sudo docker run \
    -e "POSTGRES_HOST=172.17.0.2" \
    -e "POSTGRES_PORT=5432" \
    -e "POSTGRES_DB=postgresdb" \
    -e "POSTGRES_USER=postgresadmin" \
    -e "POSTGRES_PASSWORD=aa2fbaff-98da-471c-9a67-19029781eddf" \
    -e "INPUT_DIR=/media/regulator/tarballs" \
    -e "OUTPUT_DIR=/media/regulator/codeql_dbs" \
    -v /media/regulator/gather/tarballs:/media/regulator/tarballs \
    -v /media/regulator/codeql_dbs:/media/regulator/codeql_dbs \
    regulator_codeql
echo '[*] Done';
