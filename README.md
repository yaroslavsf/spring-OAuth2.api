## 📝Table of Contents
- [Getting started](#getting_started)
- [Swagger](#swagger)
- [Credentials](#credentials)
- [Migration](#migration)

## 🧐About
### Flow
```
+--------+                               +---------------+
|        |--(A)- Authorization Request ->|   Resource    |
|        |                               |     Owner     |
|        |<-(B)-- Authorization Grant ---|               |
|        |                               +---------------+
|        |
|        |                               +---------------+
|        |--(C)-- Authorization Grant -->| Authorization |
| Client |                               |     Server    |
|        |<-(D)----- Access Token -------|               |
|        |                               +---------------+
|        |
|        |                               +---------------+
|        |--(E)----- Access Token ------>|    Resource   |
|        |                               |     Server    |
|        |<-(F)--- Protected Resource ---|               |
+--------+                               +---------------+
```
## 🏁Getting started <a name = "getting_started"></a>
### Database:
- Create ``.env`` file from ``.env.sample`` and configure db 
- Run database
    ```
    docker-compose up
    ```
### Backend application
- [Configure JDK](./HELP.md)

### Frontend application
- Get into frontend folder:```cd ./frontend```
- ```npm install```
- ```npm run start```
- http://localhost:3000

## Swagger <a name = "swagger"></a>
http://localhost:8080/swagger-ui/index.html

## 🔒Credentials <a name = "credentials"></a>
Admin<br>
login: admin@example.com<br>
pass: 1234

User<br>
login: user@example.com<br>
pass: 1234

## 🔧Migration <a name = "migration"></a>
### Database:
Change
1) .env credentials
2) application.properties database configuration 