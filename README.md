# CMS EMBEDDER PyTHON SERVICE

Esse serviço serve, exclusivamente, para preparar um documento PDF para assinatura e inserir um CMS na estrutura desse PDF preparado.

## Como iniciar o projeto?

#### Primeiro, deve-se iniciar o env virtual. Para isso, execute os camandos abaixo:

``` 
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

#### Após isso, execute o comando abaixo para inciiar o server:

```
flask --app pdf_sigining_server:app run
```
