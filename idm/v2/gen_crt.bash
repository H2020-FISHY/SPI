#!/bin/bash -e

openssl req -x509 -nodes -days 730 -newkey rsa:2048 -keyout .ssl/tls.key:fcs -out .ssl/tls.crt:fcs -config san.cnf
