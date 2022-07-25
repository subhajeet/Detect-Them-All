# Script to get merlin started 


git clone https://github.com/its-a-feature/Mythic
cd Mythic
sudo ./install_docker_kali.sh
ls 
docker compose
docker -h
docker build
docker start
docker ls
docker run ls
docker list
ls
sudo ./mythic-cli mythic start
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
./mythic-cli install github https://github.com/MythicAgents/merlin
sudo cat .env | grep MYTHIC_ADMIN_PASSWORD

# Now log into the portal with the creds.
