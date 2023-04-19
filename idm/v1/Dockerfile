FROM jboss/keycloak:16.1.1
USER root 

RUN microdnf install iproute

COPY --chown=jboss:root .ssl/tls.crt /etc/x509/https/tls.crt
COPY --chown=jboss:root .ssl/tls.key /etc/x509/https/tls.key

COPY keycloak-logo-text.png /opt/jboss/keycloak/themes/keycloak/login/resources/img/keycloak-logo-text.png
COPY login.css /opt/jboss/keycloak/themes/keycloak/login/resources/css/login.css

COPY entrypoint.bash /opt/entrypoint.bash
ENTRYPOINT [ "/opt/entrypoint.bash"]
CMD [""]
