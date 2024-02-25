# UE SEC-105

Mise en œuvre d’un outil ou d’un concept de sécurité

- Auteur: Arthur Deloffre
- Classe: Cyber1 (Année 2023-2024)

### Implémentation d’un système de 2FA sur le modèle "défi/réponse”

## Description de l’objectif de sécurité visé

Le projet consiste à reproduire un  schéma d'authentification avec une double authentiication "défi/réponse”  en Python. Il vise donc à comprendre le fonctionnement du chiffrement RSA et de reproduire son fonctionnement dans un cadre réaliste dans un lab composé de 3 machines.

Afin de simuler les échanges d’authentifications, deux machines seront déployées via Docker et communiqueront via des sockets TCP.

Une troisième machine contenant un serveur web sera aussi déployé à des fins de journalisation.

Le fichier `TP_SEC105_SCHEMA.drawio` détail le fonctionnement des communications des 3 machines.

L'objectif principal de ce schéma est de garantir l'identité légitime d'une entité (utilisateur, appareil, service) en vérifiant sa capacité à répondre correctement à un défi spécifique.

Voici la liste des objectifs de sécurité visé par le schéma d'épreuve/réponse :

- Résistance aux attaques par force brute
- Protection contre les attaques replay
- Protection aux attaques de type Man-In-The-Middle (MITM)
- Authentification sécurisée & Facilité d'utilisation

## Schéma de principe

Le schéma ci-dessous reprend les flux de notre projet :

- Le client initialise une connexion au serveur et s’identifie avec ses identifiants.
- Si les identifiants sont corrects, alors le schéma de double authentification continue.
- Le serveur génère un challenge que le client doit savoir signer.
- Le client renvoie le challenge signé
- Le serveur vérifie la signature et agit en fonction de la validité du challenge.

Le schéma se décompose donc en deux phases, l'une appelée `appairage`, qui sert à partager la clé publique du client, et une seconde appelée `authentification`, qui vise à vérifier que l'identité qui demande une connexion est bien le propriétaire de la clé.

Un serveur web développé en *Flask* sur une 3ème machine permet de visualiser proprement les différents échanges entre client/serveur et d'avoir une vue d'ensemble du processus.

Le client implémente aussi un serveur WEB en Flask qui sert pour le déclenchement de l’authentification.

Voici un schéma des communications entre les machines: 

![infra.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/0b2a246f-c92b-48ff-8784-7b75b74fa9c7/22ad3aec-a3ce-4363-b1fe-a7154196856a/infra.png)

## Implémentation

*(Note: L’entièreté des codes présents dans ce projet sont le fruit de mon travail et non la recopie du travail d’autrui)*

### Mise en œuvre et déploiement de machines dockerisés.

Afin de travailler efficacement et d’avoir une facilité de déploiement du lab, je décide d’utiliser Docker plutôt que des machines virtuelles. 

J’utilise donc 3 *Dockerfile* que je relis avec un fichier *docker-compose.yml.* 

C’est ce dernier fichier qui va se charger de la configuration des communications entre les 3 machines, notamment avec le partage d’un même réseau virtualisé. 

Voici un exemple de Dockerfile pour une des trois applications python:

```bash
FROM python:3.8

WORKDIR /app
COPY source/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY source/ /app

EXPOSE 8080

CMD ["python3", "server.py"]
```

et voici le *docker-compose.yml :* 

```yaml
version: '3'

services:
  client:
    build:
      context: ./client
    ports:
      - "6000:6000"
    environment:
      - PORT=6000
    networks:
      - shared

  server:
    build:
      context: ./server
    ports:
      - "1337:1337"
    environment:
      - PORT=1337
      - USERNAME=Vozec
      - PASSWORD=I5ThisASup4rPas5w0rd@?
    networks:
      - shared

  logger:
    build:
      context: ./logger
    ports:
      - "1111:5000"
    environment:
      - PORT=5000
    networks:
      - shared

networks:
  shared:
```

Je fournit directement un compte valide au serveur qui me servira pour tester la première partie du schéma d’authentification: 

- Nom d’utilisateur:  `Vozec`
- Mot de passe: `I5ThisASup4rPas5w0rd@?`

Il suffit de lancer la commande suivante à la racine du projet pour démarrer les 3 machines: 

```bash
docker-compose up --build
```

![docker_up.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/0b2a246f-c92b-48ff-8784-7b75b74fa9c7/23c813be-b573-4ff4-95f7-da8a6fd74d9a/docker_up.png)

### Serveur Web de journalisation.

Un serveur Web en Flask a était développé avec une API afin d’avoir un schéma clair des communications ainsi qu’une vue d’ensemble sur les actions prisent par le client et le serveur.

Voici l’arborescence de fichiers :

```bash
[main][/mnt/c/Users/vozec/Desktop/TP_sec105/logger]$ tree .
.
├── Dockerfile
└── source
    ├── logger.py
    ├── requirements.txt
    ├── static
    │   ├── css
    │   │   └── style.css
    │   ├── img
    │   │   ├── favicon.ico
    │   │   └── lightning.png
    │   └── js
    │       └── index.js
    ├── templates
    │   ├── base.html
    │   ├── footer.html
    │   ├── header.html
    │   └── index.html
    └── utils
        └── message.py

8 directories, 12 files
```

L’api comporte 3 endpoints: 

- /api/reset (GET)
- /api/add/<sender> (POST)
- /

Le premier sert à réinitialiser les logs en supprimant les anciennes communications enregistrées.

Le second endpoint sert à ajouter un message en spécifiant l’envoyeur dans l’url et le contenu dans un paramètre *message* en POST.

Le dernier endpoint, à la racine du serveur, permet d’avoir une vision global des échanges, de la même manière qu’une messagerie instantanés avec d’un coté le serveur et de l’autre le client.

(Du code *html/css/javascript* a était ajouté pour améliorer le rendu visuel final)

Voici le code principal du serveur: 

```python
from flask import Flask, render_template, request, jsonify
from os import getenv

from utils.message import message

app = Flask(__name__)
app._static_folder = 'static'
messages = []

@app.route('/api/reset', methods=['GET'])
def reset_messages():
    global messages
    messages = []
    return jsonify({'status': 'ok'})

@app.route('/api/add/<sender>', methods=['POST'])
def add_message(sender):
    if sender not in ['server', 'client']:
        return jsonify({'error': 'Invalid sender'})

    content = request.form.get('message')
    if not content:
        return jsonify({'error': 'Invalid/Missing message'})

    messages.append(message(f'{sender}:  {content}', sender))

    return jsonify({'status': 'ok'})

@app.route('/')
def get_logs():
    return render_template('index.html', messages=messages)

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=int(getenv('PORT')))
```

## Création du client et du server

Une class pour la journalisation peut être créer et sera ajouté dans les deux applications: 

```python
from requests import post, get

class logger:
    def __init__(self, identity, server):
        self.identity = identity
        self.server = server

    def reset(self):
        get(f'{self.server}/api/reset')

    def log(self, message):
        try:
            post(f'{self.server}/api/add/{self.identity}', data={
                'message': message
            })
        except Exception as ex:
            print(ex)

# Example
logger = logger(identity='server', server='http://logger:5000')
logger.log("Hello World !")
```

Le serveur implémente un *serveur TCP* avec la librairie socket en python, il écoute ici sur le port 5000 et attend une connexion d’un client:

```python
def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', int(getenv('PORT'))))
    server_socket.listen()
    print(f"Server listening on '0.0.0.0':{getenv('PORT')}")

    while True:
        client_socket, client_address = server_socket.accept()
				...

main()
```

Coté client, on retrouve un endpoint “/login” qui déclenche la procédure de login vers le serveur avec les informations de connections fournis en paramètre. Cela permet de tester avec des identifiants valides et invalides rapidement.

La connexion au serveur TCP se fait via la bibliothèque *pwntools* qui permet une gestion des sockets efficace.

```python
from pwn import *

class client:
    def __init__(self, url, port):
        self.l = logger('client', 'http://logger:5000')
				self.l.log(f'Establishing TCP connection on port {self.port}')
        self.io = remote(self.url, self.port)
				self.rsa = RSA()
		
		def send_public(self):
        self.l.log(f'[Pairing part] Public key sended (e, n)')
        self.io.sendline(str(self.rsa.get_publickey()).encode())
        response = self.io.recv(1024)

		....
	
	
@app.route('/login', methods=['POST'])
def login():
    if 'username' not in request.form:
        return jsonify({'error': 'Field missing: username'})
    if 'password' not in request.form:
        return jsonify({'error': 'Field missing: password'})

    c = client('server', 1337)  # Create connection
    c.send_public()             # Initialize public key exchange

    username = request.form['username']
    password = request.form['password']
    logged = c.login(username, password)

    if logged:
        c.get_challenge()
        c.send_signed()
        m = c.get_message()
        return jsonify({'msg': m})

    return jsonify({'error': 'Invalid credentials'})
```

Pour des raisons pratiques et de démonstration, la partie d’appairage et  d’authentification sont exécutées successivement dans le code proposé. Évidemment, dans le monde réel, l'appairage aurait lieu en présence d'un administrateur/à la configuration de compte, et l'authentification aurait lieu à chaque connexion.

Voici la routine exécutée par le serveur après une nouvelle connexion. Le nom des méthodes sont assez explicites à la compréhension.

```python
while True:
	client_socket, client_address = server_socket.accept()
	
	c = connection(client_socket, client_address)
	c.get_public() # appairage
	
	# authentification
	valid_credentials = c.login()

	if valid_credentials:
		c.gen_challenge()
		c.send_challenge()
		c.get_signature()
		c.verify()
		c.send_message()

	c.close()
```

Enfin, voici le code pour la partie cryptographique, celui ci est exécuté sur la partie client puisque c’est lui qui doit signer le challenge du serveur: 

```python
from Crypto.Util.number import getPrime, long_to_bytes, bytes_to_long
from hashlib import sha256

class RSA:
    def __init__(self):
        self.e = 65537
        self.p = getPrime(1024)
        self.q = getPrime(1024)
        self.n = self.p * self.q
        self.phi = (self.p - 1) * (self.q - 1)
        self.d = pow(self.e, -1, self.phi)

    def get_publickey(self):
        return self.e, self.n

    def get_privatekey(self):
        return self.d

    def encrypt(self, message):
        return pow(bytes_to_long(message), self.e, self.n)

    def decrypt(self, message):
        return long_to_bytes(pow(message, self.d, self.n))

# Example
rsa = RSA()

## Envoie de la clé publique: 
pub = rsa.get_publickey()
socket.send(pub.encode())

## Récupération du challenge et signature:
m = socket.recv(1024)

### Hash + Formatage avec les préfix/suffix d'une signature RSA selon la norme PKCS#1
hashed = sha256(m).digest()
asn1_sha256 = b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20'
suffix = b'\x00' + asn1_sha256 + hashed
msg = b'\x00\x01' + b'\xff' * (256 - 2 - len(suffix)) + suffix

s = rsa.decrypt(bytes_to_long(msg)) # s = m^e % n

```

Coté serveur, la vérification est effectuée de cette manière: 

```python

# Récupération de la signature puis du hash
def get_signature(self):
    data = self.socket.recv(4096).strip()
    self.l.log(f'[Authentification part] Data received')

    # Sign: m = s^d % n
    data = long_to_bytes(pow(bytes_to_long(data), self.e, self.n))
    if asn1_sha256 not in data:
        return
    self.hash = data.split(asn1_sha256)[1]
	  self.l.log(f'[Authentification part] Hash extracted (hex): {hexlify(self.hash).decode()}')

# Vérification de la signature par comparaison des hash
def verify(self):
    valid_hash = sha256(self.m.encode()).digest()
    if valid_hash == self.hash:
        self.verified = True
    else:
        self.verified = False
    self.l.log(f'[Authentification part] Verification result: {str(self.verified)}')
```

Le reste du code ne sera pas détaillé ici car cela serai moins pertinent. 

Il ne concerne que la communication entre client/serveur comme par exemple le code d’envoie de mot de passe, celui d’envoie et de réception de signature ou encore toute les requêtes de journalisation faites avec la troisième machine.

L’entièreté du projet avec le code est disponible dans le fichier `source.zip`

## Résultat:

Voici le résultat renvoyé par le client quand je lui demande de se connecter au serveur avec 2 mots de passe différents :

![start.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/0b2a246f-c92b-48ff-8784-7b75b74fa9c7/8e7f74c2-926b-4d9f-aa03-988513aa7e0a/start.png)

Voici le résultat d’un schéma d’authentification qui échoue à cause d’un mauvais mot de passe: 

![win1.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/0b2a246f-c92b-48ff-8784-7b75b74fa9c7/3a8a8bd7-aa8f-4338-89c4-1c85c2aee1f6/win1.png)

Voici le résultat d’un schéma d’authentification qui est valide avec un bon mot de passe et un bon échange de signature:

![win1.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/0b2a246f-c92b-48ff-8784-7b75b74fa9c7/59a6b437-0847-44ab-afa8-d5c5f0a5c796/win1.png)

![win2.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/0b2a246f-c92b-48ff-8784-7b75b74fa9c7/f0d957b1-aa22-4af4-a5cc-99075081c2c1/win2.png)

 

## Conclusion

Le schéma d'épreuve/réponse offre une méthode robuste et fiable pour l'authentification et permet d'assurer une couche de protection supplémentaire aux mots-de-passes courant lors de l'identification d'un individu.

Ce projet m’a permis de mettre en place ce système d’authentification et de mieux comprendre les aspects cryptographique sur lequel il se base. En plus d’améliorer mes compétences en développement, j’ai pu appréhender ce système de double authentification et réimplémentant l’entièreté de son fonctionnement en python. 

Une amélioration possible serai de mettre en place un canal plus sécurisé que de “simple” échanges TCP non chiffrés. Un attaquant pourrait se placer entre les communications du serveur et du client et ainsi faire signer ce qu’il veut au client, y compris un challenge destiné à une seconde authentification pour l’attaquant.

Le système d’échange de clés de diffie-hellman semble être une bonne solution à ce problème et permettrai une communication plus opaque d’un point de vu extérieur.

# Sources:

## Documentations:

- https://docs.docker.com/compose/
- https://flask-fr.readthedocs.io/index.html
- https://docs.python.org/3/library/socket.html
- https://github.com/Gallopsled/pwntools

## Articles:

- https://www.di.ens.fr/~nitulesc/files/crypto6.pdf
- https://cedricvanrompay.gitlab.io/tp-rsa/instructions.html
- https://vozec.fr/rsa/rsa-9-breaking-signature-shema/
- https://fr.wikipedia.org/wiki/Chiffrement_RSA
