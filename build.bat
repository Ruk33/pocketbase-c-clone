@echo off
wsl gcc -std=c99 -Wall -Wextra -Werror main.c asocket.c http_request.c json_read.c -lsqlite3 -o build/pocketbasec
