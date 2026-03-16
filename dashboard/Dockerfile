FROM grafana/grafana:latest

WORKDIR /etc/grafana/provisioning/dashboards

# Copy dashboard configs
COPY dashboards.yml /etc/grafana/provisioning/dashboards/
COPY *.json /var/lib/grafana/dashboards/

ENV GF_SECURITY_ADMIN_PASSWORD=admin
ENV GF_USERS_ALLOW_SIGN_UP=false

EXPOSE 3000

CMD ["grafana-server"]
