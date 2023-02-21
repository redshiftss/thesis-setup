#!/bin/bash
container_names=$(sudo docker search --format "table {{.Name}}" nginx-conf | sed 's/NAME//')
echo -e "printing container names: \n$container_names"

for container in $container_names
do
    cat ./password.txt | docker login --username lpircalaboiu --password-stdin
    sudo docker image pull container_name
done