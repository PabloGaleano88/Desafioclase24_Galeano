# Refactor a nuestro Login - Clase 21 - Galeano Pablo
## Comisión: 47295

### Alumno: Pablo Galeano

### Profesor: Gonzalo Fernández

### Tutor: Martín Castagno

[![HTML 5](https://img.shields.io/badge/HTML_5-e34c26?style=for-the-badge&logo=html5&logoColor=white&labelColor=101010)]() [![CSS 3](https://img.shields.io/badge/CSS_3-264de4?style=for-the-badge&logo=css3&logoColor=white&labelColor=101010)]()[![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=white&labelColor=101010)]()[![MongoDB](https://img.shields.io/badge/MongoDB-47A248?style=for-the-badge&logo=mongodb&logoColor=white&labelColor=101010)]()[![MongoDB](https://img.shields.io/badge/handlebars-F26726?style=for-the-badge&logo=handlebars.js&logoColor=white&labelColor=101010)]()[![Passport](https://img.shields.io/badge/passport-34E27A?style=for-the-badge&logo=passport&logoColor=white&labelColor=101010)]()

##
* El usuario adminCoder@coder.com se encuentra como administrador

* Se agregó el logeo a través de github

* Se hicieron los test propuestos.

* El cart donde se agregan los productos está hardcodeado según lo indicado por el profe. 

* Se debe realizar las siguientes instalaciones en caso de no disponer de las mismas en el equipo

#### Nodemon
```
npm install -g nodemon
```
### Express
```
npm install express
```
### Handlebars
```
npm install express-handlebars
```
### Socket io
```
npm install socket.io
```
### Multer
```
npm install multer
```
### Mongoose
```
npm install mongoose
```

### Mongoose Paginate
```
npm install mongoose-paginate-v2
```
### Connect-mongo
```
npm install connect-mongo 
```
### Session
```
npm install express-session 
```
### passport
```
npm install passport
```
### passport GitHub
```
npm install passport-github2
```
### passport-local
```
npm install passport-local
```
### Bcrypt
```
npm install bcrypt
```


##
* Para correr  la aplicación en modo desarrollador se debe escribir en la terminal:
```
npm run dev 
```
* Para correr  la aplicación en modo produccion se debe escribir en la terminal:
```
npm start
```

Se esuchará por el puerto 8080, con lo cual se puede interactuar con la app a traves de los siguientes endpoints:

[http://localhost:8080/products/](http://localhost:8080/products) -> Si ingresa a acá pedirá Login

[http://localhost:8080/login/](http://localhost:8080/login)

[http://localhost:8080/signup/](http://localhost:8080/signup)

[http://localhost:8080/api/products/](http://localhost:8080/api/products/)

[http://localhost:8080/api/carts/](http://localhost:8080/api/carts/)

[http://localhost:8080](http://localhost:8080) -> Se ven los productos en formato Json

[http://localhost:8080/realtimeproducts/](http://localhost:8080/realtimeproducts)  -> con websockets

[http://localhost:8080/chat/](http://localhost:8080/chat)


Tener en cuenta que para probar con el formulario en realtimeproducts se deben llenar todos los campos

Los puts,update y delete tambien se pueden hacer con ThunderClient. Los POST no debido a que no deja enviar files desde el modo form-encoded, por lo tanto, multer no recibe la imagen y nos arroja error.