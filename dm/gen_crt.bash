#!/bin/bash -e

openssl req -x509 -nodes -days 730 -newkey rsa:2048 -keyout .ssl/tls.key:d1 -out .ssl/tls.crt:d1 -config san.cnf
