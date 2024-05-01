FROM python:3.11.2

LABEL maintainer="Kirill Lygin"
LABEL description="Gitsearch docker image"
LABEL version="1.0"
LABEL name="gitsearch"

ENV PATH="$PATH:/usr/local/go/bin"

WORKDIR /app

# COPY ./uploads ./

# needed things form apt
# RUN apt update -y && apt upgrade -y && \
RUN apt install -y wget

# configure maria db repo
RUN wget https://r.mariadb.com/downloads/mariadb_repo_setup && \
    chmod +x mariadb_repo_setup && \
    ./mariadb_repo_setup --mariadb-server-version="mariadb-10.6" && \
    apt install -y libmariadb3 libmariadb-dev

# install pip dependencies 
COPY requirements.txt requirements.txt
RUN pip3 install --upgrade pip && pip install -r requirements.txt

# get go
RUN rm -rf /usr/local/go && \
    wget https://go.dev/dl/go1.21.3.linux-amd64.tar.gz && \
    tar -C /usr/local/ -xzf go1.21.3.linux-amd64.tar.gz && \
    rm ./go1.21.3.linux-amd64.tar.gz
    
# get trufflehog
RUN wget https://github.com/trufflesecurity/trufflehog/releases/download/v3.74.0/trufflehog_3.74.0_linux_amd64.tar.gz && \
    tar -xzf trufflehog_3.74.0_linux_amd64.tar.gz && \
    rm ./trufflehog_3.74.0_linux_amd64.tar.gz

# get gitleaks
RUN wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.2/gitleaks_8.18.2_linux_x64.tar.gz && \
    tar -xzf gitleaks_8.18.2_linux_x64.tar.gz && \
    rm ./gitleaks_8.18.2_linux_x64.tar.gz

# get git-secrets
RUN wget https://github.com/awslabs/git-secrets/blob/master/git-secrets

# move everyting to binaries 
RUN chmod +x trufflehog git-secrets gitleaks && \
    mv trufflehog /usr/local/go/bin && \
    mv git-secrets /usr/local/bin && \
    mv gitleaks /usr/local/bin


# install pip requirements

# and let's roll
CMD ["python3", "gitsearcher.py"]
