# Build this image
# docker build -t custom-jenkins-node-python .     

# Run this image
# docker run -p 8080:8080 -p 50000:50000 --restart=on-failure custom-jenkins-node-python


# Utilise l'image Jenkins LTS avec JDK 17 comme base
FROM jenkins/jenkins:lts-jdk17

# Passer en mode root pour installer les paquets
USER root

# Installer Node.js, npm, Python3 avec venv
RUN apt-get update && \
    apt-get install -y nodejs npm python3 python3-pip python3-venv curl && \
    rm -rf /var/lib/apt/lists/*


# Vérification pour que python3 soit disponible dans la commande CLI `python3`
RUN ln -sf /usr/bin/python3 /usr/bin/python

# Revenir à l'utilisateur Jenkins pour la sécurité
USER jenkins
