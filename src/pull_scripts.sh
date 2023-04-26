#!/bin/bash
container_names=$(sudo docker search --format "table {{.Name}}" nginx-conf | sed 's/NAME//')
echo -e "printing container names: \n$container_names"
cat ./password.txt | docker login --username lpircalaboiu --password-stdin

for container in $container_names
do
    sudo docker image pull $container
done