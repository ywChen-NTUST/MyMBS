# My Message Board System
## build

0. clone project
```bash
git clone https://github.com/ywChen-NTUST/MyMBS.git
cd MyMBS/
```

1. prepare an image for administrator account and save it in `www/profile_photo` with prefix 01_
```
www
 |- profile_photo
          |- 01_<administrator_profile_photo>
```

2. copy `.env.template` to `.env` and modify it
```bash
cp .env.template .env
# modify .env
## for ADMIN_PROFILE, place the image name which you store in www/profile_photo (i.e. 01_administrator.jpg)
```

3. change owner of the `www/attachments/` and `www/profile_photo` directory to `www-data`
```bash
chown www-data:www-data www/profile_photo/
chown www-data:www-data www/attachments/
```

4. run container
```bash
docker-compose up -d --build
```

5. (Optional) Setup domain name

    1. modify `config/mymbs_nginx.conf`

        Basicly, only needs to modify `server_name` to your domain name

    2. copy file
        ```bash
        cp config/mymbs_nginx.conf /etc/nginx/sites-enabled/
        ```
    3. restart nginx
        ```bash
        service nginx restart
        ```

6. (Optional) Setup SSL
```bash
certbot --nginx
```

## preserve user data and clone to another server

user data is stored under these directory: 

- `db/persist`
- `www/profile_photo`
- `www/attachments`

if you want to preserve to another server, fellowing these steps:

0. login into your new server and goto the project dir

1. cleaning the old data (if you haven't build the system before, no needs to do this step)
```bash
rm -rf db/persist/
rm -rf www/attachments
rm -rf www/profile_photo
```

2. copy files
```bash
scp -r <old_server_username>@<old_server_ip>:<project_dir>/db/persist ./db/
scp -r <old_server_username>@<old_server_ip>:<project_dir>/www/profile_photo ./www/
scp -r <old_server_username>@<old_server_ip>:<project_dir>/www/attachments ./www/
```

3. rebuild containers
```bash
docker-compose up -d --build
```