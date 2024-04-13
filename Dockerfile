FROM python:3.11.2

ENV PATH="$PATH:/usr/local/go/bin"

WORKDIR /app

COPY ./uploads ./

RUN rm -rf /usr/local/go && tar -C /usr/local -xzf go1.21.3.linux-amd64.tar.gz && rm ./go1.21.3.linux-amd64.tar.gz && chmod +x gitrob trufflehog git-secrets gitleaks && mv gitrob /usr/local/go/bin && mv trufflehog /usr/local/go/bin && mv git-secrets /usr/local/bin && mv gitleaks /usr/local/bin

#COPY requirements.txt requirements.txt

RUN pip install --upgrade pip && pip install -r requirements.txt

CMD ["python3","./gitsearcher.py"]
